"""playbooks/tasks/fetch-backup.yml: decrypt and validate a backup (local source seam)."""
import json
import os
import shutil
import subprocess

import pytest

from test_render import FIXTURE_VAULT_PASS, ROOT

pytestmark = pytest.mark.skipif(shutil.which("age") is None, reason="age not installed")

PLAYBOOK = """---
- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - ansible.builtin.include_tasks: {task}
    - ansible.builtin.copy:
        content: "{{{{ entry_restore_archive }}}}"
        dest: {out}/archive-path
        mode: "0600"
    - ansible.builtin.copy:
        content: "{{{{ entry_restore_tmpdir }}}}"
        dest: {out}/tmpdir-path
        mode: "0600"
"""


def _setup(tmp_path, members, vault_priv="K\n"):
    ident = tmp_path / "id.txt"
    subprocess.run(["age-keygen", "-o", str(ident)], check=True, capture_output=True)
    pub = subprocess.run(["age-keygen", "-y", str(ident)], check=True,
                         capture_output=True, text=True).stdout.strip()
    src = tmp_path / "src"
    for name, data in members.items():
        (src / name).parent.mkdir(parents=True, exist_ok=True)
        (src / name).write_text(data)
    tar = tmp_path / "state.tar"
    subprocess.run(["tar", "-C", str(src), "-cf", str(tar), "."], check=True)
    store = tmp_path / "store"
    store.mkdir()
    name = "entry-20260101T000000Z-abcdef123456.tar.age"
    subprocess.run(["age", "-r", pub, "-o", str(store / name), str(tar)], check=True)
    (store / "latest").write_text(f"bk/{name}")
    varsfile = tmp_path / "vars.json"
    varsfile.write_text(json.dumps({
        "vault_backup_age_identity": ident.read_text(),
        "vault_entry_awg": {"private_key": vault_priv},
        "backup_s3_prefix": "bk",
        "backup_fetch_source": f"local:{store}",
    }))
    return varsfile, name


def _run(tmp_path, varsfile, extra=()):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    playbook = tmp_path / "play.yml"
    playbook.write_text(PLAYBOOK.format(task=ROOT / "playbooks/tasks/fetch-backup.yml", out=out))
    env = dict(os.environ)
    if not (ROOT / ".vault-pass").exists():
        env.setdefault("ANSIBLE_VAULT_PASSWORD_FILE", str(FIXTURE_VAULT_PASS))
    env["ANSIBLE_CONFIG"] = str(ROOT / "ansible.cfg")
    proc = subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "-e", "ansible_connection=local",
         "-e", f"@{varsfile}", *extra, str(playbook)],
        cwd=ROOT, env=env, capture_output=True, text=True)
    return proc, out


GOOD = {"awg0.conf": "[Interface]\n", "wireguard_server_private_key.key": "K\n",
        "clientsTable": "[]\n"}


def test_fetch_latest_decrypts_and_validates(tmp_path):
    varsfile, _ = _setup(tmp_path, GOOD)
    proc, out = _run(tmp_path, varsfile)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    archive = (out / "archive-path").read_text()
    tmpdir = (out / "tmpdir-path").read_text()
    names = subprocess.run(["tar", "-tf", archive], check=True, capture_output=True,
                           text=True).stdout.split()
    assert "./awg0.conf" in names
    assert oct(os.stat(tmpdir).st_mode & 0o777) == "0o700"
    assert "WARNING" not in proc.stdout
    # only the decrypted tar remains; identity temp file is gone
    assert sorted(os.listdir(tmpdir)) == ["backup.tar"]
    shutil.rmtree(tmpdir)


def test_named_object_and_key_mismatch_warns(tmp_path):
    varsfile, name = _setup(tmp_path, GOOD, vault_priv="OTHER\n")
    proc, out = _run(tmp_path, varsfile, ["-e", f"backup_object={name}"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "differs from" in proc.stdout
    shutil.rmtree((out / "tmpdir-path").read_text())


def test_archive_without_awg0_conf_fails_and_cleans_up(tmp_path):
    varsfile, _ = _setup(tmp_path, {"wireguard_server_private_key.key": "K\n"})
    before = {p for p in os.listdir(os.environ.get("TMPDIR", "/tmp")) if p.startswith("multihop-restore-")}
    proc, _ = _run(tmp_path, varsfile)
    assert proc.returncode != 0
    assert "not a valid entry backup" in proc.stdout + proc.stderr
    after = {p for p in os.listdir(os.environ.get("TMPDIR", "/tmp")) if p.startswith("multihop-restore-")}
    assert after <= before
