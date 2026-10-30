"""The entry_app seed tasks must never overwrite state the app has changed."""
import os
import subprocess

from test_render import FIXTURE_VAULT_PASS, RENDER_DIR, ROOT

PLAYBOOK = """---
- hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - {fixture}
  roles:
    - entry_app
"""


def _run(playbook, state_dir):
    env = dict(os.environ)
    if not (ROOT / ".vault-pass").exists():
        env.setdefault("ANSIBLE_VAULT_PASSWORD_FILE", str(FIXTURE_VAULT_PASS))
    env["ANSIBLE_CONFIG"] = str(ROOT / "ansible.cfg")
    proc = subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "-e", "ansible_connection=local",
         "-e", f"entry_state_dir={state_dir}", "--tags", "entry_app_seed",
         str(playbook)],
        cwd=ROOT, env=env, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout


def test_seed_tasks_keep_app_state(tmp_path):
    playbook = tmp_path / "play.yml"
    playbook.write_text(PLAYBOOK.format(fixture=RENDER_DIR / "fixture_vars.yml"))
    state = tmp_path / "state"

    _run(playbook, state)
    conf = (state / "awg0.conf").read_text()
    assert "[Peer]" not in conf
    assert (state / "wireguard_psk.key").read_text().endswith("\n")
    assert oct((state / "awg0.conf").stat().st_mode & 0o777) == "0o600"
    assert not (state / "clientsTable").exists()

    # The app adds a user: peer in awg0.conf and a clientsTable.
    with (state / "awg0.conf").open("a") as fh:
        fh.write("\n[Peer]\nPublicKey = FAKEPEERKEY=\nAllowedIPs = 10.8.1.2/32\n")
    (state / "clientsTable").write_text('[{"clientId":"FAKEPEERKEY="}]\n')
    snapshot = {p.name: p.read_bytes() for p in state.iterdir()}

    out = _run(playbook, state)
    assert {p.name: p.read_bytes() for p in state.iterdir()} == snapshot
    assert "changed=0" in out
