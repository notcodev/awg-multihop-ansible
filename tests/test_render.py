"""Template render harness: renders role templates with fixture vars."""
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RENDER_DIR = ROOT / "tests" / "render"
FIXTURE_VAULT_PASS = ROOT / "tests" / "fixtures" / "vault-pass"


def render(src: str, dest: str, extra_vars: dict | None = None) -> str:
    """Render `src` (repo-root relative or absolute) and return the text."""
    src_path = Path(src)
    if not src_path.is_absolute():
        src_path = ROOT / src_path
    env = dict(os.environ)
    if not (ROOT / ".vault-pass").exists():
        env.setdefault("ANSIBLE_VAULT_PASSWORD_FILE", str(FIXTURE_VAULT_PASS))
    env["ANSIBLE_CONFIG"] = str(ROOT / "ansible.cfg")
    # ansible.cfg uses repo-relative paths, so run from the repo root.
    payload = {"render_list": [{"src": str(src_path), "dest": dest}]}
    payload.update(extra_vars or {})
    out = RENDER_DIR / "out" / dest
    out.unlink(missing_ok=True)
    proc = subprocess.run(
        ["ansible-playbook", str(RENDER_DIR / "render.yml"), "-e", json.dumps(payload)],
        cwd=ROOT, env=env, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return out.read_text()


def test_env_template_renders_public_iface():
    text = render("roles/common/templates/multihop.env.j2", "multihop.env")
    assert "PUBLIC_IFACE=eth0" in text
    assert "SSH_PORT=22" in text
