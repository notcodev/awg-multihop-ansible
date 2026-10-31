"""Playbooks: syntax-check every entry point and exercise the uplink key rotation."""
import json
import os
import subprocess
import sys

import pytest
import yaml

from test_awg_filter import awg
from test_render import FIXTURE_VAULT_PASS, ROOT

PLAYBOOKS = [
    "site.yml", "exit.yml", "entry.yml", "backup.yml", "restore.yml",
    "swap-exit.yml", "swap-entry.yml", "verify.yml",
]
EXAMPLE_INVENTORY = ROOT / "inventories" / "example"
# Dummy plaintext vault, generated per test session (gitignored).
VAULT_INVENTORY = ROOT / "tests" / "fixtures" / "inventory-vault"


def _env(**extra):
    env = dict(os.environ)
    if not (ROOT / ".vault-pass").exists():
        env.setdefault("ANSIBLE_VAULT_PASSWORD_FILE", str(FIXTURE_VAULT_PASS))
    env["ANSIBLE_CONFIG"] = str(ROOT / "ansible.cfg")
    env.update(extra)
    return env


@pytest.fixture(scope="session")
def dummy_vault():
    """Example inventory + an unencrypted vault from gen-secrets.py."""
    vault_dir = VAULT_INVENTORY / "group_vars" / "all"
    vault_dir.mkdir(parents=True, exist_ok=True)
    # A host-less inventory source whose group_vars/all overlays the example.
    (VAULT_INVENTORY / "hosts.yml").write_text("---\nall: {}\n")
    for name, mode in (("vault.yml", "all"), ("vault_uplink.yml", "uplink-key")):
        out = subprocess.run([sys.executable, str(ROOT / "scripts" / "gen-secrets.py"), mode],
                             check=True, capture_output=True, text=True).stdout
        (vault_dir / name).write_text(out)
    return ["-i", str(EXAMPLE_INVENTORY), "-i", str(VAULT_INVENTORY)]


def test_dummy_vault_reaches_hosts(dummy_vault):
    proc = subprocess.run(["ansible-inventory", *dummy_vault, "--host", "entry1"],
                          cwd=ROOT, env=_env(), capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    hostvars = json.loads(proc.stdout)
    assert {"entry_domain", "vault_entry_awg", "vault_link_awg",
            "vault_uplink_entry"} <= hostvars.keys()


@pytest.mark.parametrize("playbook", sorted(
    set(PLAYBOOKS) | {p.name for p in (ROOT / "playbooks").glob("*.yml")}))
def test_syntax_all(dummy_vault, playbook):
    path = ROOT / "playbooks" / playbook
    assert path.exists(), f"missing playbook {playbook}"
    proc = subprocess.run(["ansible-playbook", *dummy_vault, "--syntax-check", str(path)],
                          cwd=ROOT, env=_env(), capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "WARNING" not in proc.stderr, proc.stderr


def test_verify_entry_task_file_exists():
    assert (ROOT / "playbooks" / "tasks" / "verify-entry.yml").exists()


ROTATE_PLAYBOOK = """---
- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - ansible.builtin.include_tasks: {task}
      vars:
        uplink_vault_file: {target}
    - ansible.builtin.copy:
        content: "{{{{ vault_uplink_entry | to_json }}}}"
        dest: {out}
        mode: "0600"
"""


def _rotate(tmp_path, target, env):
    # gen-secrets.py is found relative to the playbook dir, as in playbooks/.
    (tmp_path / "playbooks").mkdir(exist_ok=True)
    if not (tmp_path / "scripts").exists():
        (tmp_path / "scripts").symlink_to(ROOT / "scripts")
    playbook = tmp_path / "playbooks" / "play.yml"
    out = tmp_path / "loaded.json"
    playbook.write_text(ROTATE_PLAYBOOK.format(
        task=ROOT / "playbooks" / "tasks" / "rotate-uplink-key.yml", target=target, out=out))
    # PWD as a shell would set it: the rotation runs ansible-vault from there.
    proc = subprocess.run(["ansible-playbook", "-i", "localhost,", str(playbook)],
                          cwd=ROOT, env={**env, "PWD": str(ROOT)},
                          capture_output=True, text=True)
    return proc, out


def test_rotate_uplink_key_writes_encrypted_vault_and_loads_it(tmp_path):
    vault_dir = tmp_path / "inv" / "group_vars" / "all"
    vault_dir.mkdir(parents=True)
    target = vault_dir / "vault_uplink.yml"
    target.write_text("old\n")

    proc, out = _rotate(tmp_path, target, _env())
    assert proc.returncode == 0, proc.stdout + proc.stderr

    raw = target.read_text()
    assert raw.startswith("$ANSIBLE_VAULT;"), "vault_uplink.yml must be encrypted"
    assert oct(target.stat().st_mode & 0o777) == "0o600"
    assert [p.name for p in vault_dir.iterdir()] == ["vault_uplink.yml"]
    view = subprocess.run(["ansible-vault", "view", str(target)], cwd=ROOT, env=_env(),
                          capture_output=True, text=True, check=True).stdout
    key = yaml.safe_load(view)["vault_uplink_entry"]
    assert awg.pubkey(key["private_key"]) == key["public_key"]
    # include_vars made the new key visible to the rest of the play.
    assert json.loads(out.read_text()) == key


def test_rotate_uplink_key_keeps_old_file_when_encryption_fails(tmp_path):
    vault_dir = tmp_path / "inv" / "group_vars" / "all"
    vault_dir.mkdir(parents=True)
    target = vault_dir / "vault_uplink.yml"
    target.write_text("old\n")

    # Executable password file: works for ansible-playbook (first call), then
    # fails, so ansible-vault inside the task cannot encrypt.
    passfile = tmp_path / "pass.sh"
    passfile.write_text(f'#!/bin/sh\n[ -e "{tmp_path}/used" ] && exit 1\n'
                        f': > "{tmp_path}/used"\necho dummy\n')
    passfile.chmod(0o700)
    proc, _ = _rotate(tmp_path, target, _env(ANSIBLE_VAULT_PASSWORD_FILE=str(passfile)))
    assert proc.returncode != 0
    assert "fatal: [localhost]" in proc.stdout and "ansible-vault encrypt" in proc.stdout
    assert target.read_text() == "old\n"
    assert [p.name for p in vault_dir.iterdir()] == ["vault_uplink.yml"]
