import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("awg", ROOT / "plugins" / "filter" / "awg.py")
awg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(awg)


def run(arg):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen-secrets.py"), arg],
        capture_output=True, text=True, check=True,
    ).stdout


def test_all_outputs_valid_vault_doc():
    out = run("all")
    assert out.startswith("# Suggested ports")
    doc = yaml.safe_load(out)
    for k in ("vault_entry_awg", "vault_link_awg", "vault_backup_writer",
              "vault_backup_reader", "vault_backup_age_identity"):
        assert k in doc
    e, link = doc["vault_entry_awg"], doc["vault_link_awg"]
    assert e["params"]["header_protection_key"] != link["params"]["header_protection_key"]
    assert e["public_key"] == awg.pubkey(e["private_key"])
    assert link["exit_public_key"] == awg.pubkey(link["exit_private_key"])
    assert all(isinstance(v, str) for v in e["params"].values())
    assert doc["vault_backup_writer"] == {"access_key": "CHANGE_ME", "secret_key": "CHANGE_ME"}
    assert doc["vault_backup_age_identity"] == "CHANGE_ME"
    ports = [int(p) for p in out.splitlines()[0].replace(",", " ").split() if p.isdigit()]
    assert len(ports) == 2 and ports[0] != ports[1]
    assert all(20000 <= p <= 60000 for p in ports)


def test_uplink_key_doc():
    doc = yaml.safe_load(run("uplink-key"))
    u = doc["vault_uplink_entry"]
    assert u["public_key"] == awg.pubkey(u["private_key"])
