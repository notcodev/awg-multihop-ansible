#!/usr/bin/env python3
"""Generate vault material for the multihop AWG deployment.

  gen-secrets.py all         full vault.yml document on stdout
  gen-secrets.py uplink-key  vault_uplink.yml document on stdout
"""
import secrets
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "plugins" / "filter"))
import awg  # noqa: E402


def _dump(doc: dict) -> str:
    return yaml.safe_dump(doc, default_flow_style=False, sort_keys=False, width=1000)


def gen_all() -> str:
    rng = secrets.SystemRandom()
    entry_port, exit_port = rng.sample(range(20000, 60001), 2)
    entry_priv = awg.genkey()
    exit_priv = awg.genkey()
    doc = {
        "vault_entry_awg": {
            "private_key": entry_priv,
            "public_key": awg.pubkey(entry_priv),
            "psk": awg.genpsk(),
            "params": awg.gen_awg_params(rng),
        },
        "vault_link_awg": {
            "exit_private_key": exit_priv,
            "exit_public_key": awg.pubkey(exit_priv),
            "psk": awg.genpsk(),
            "params": awg.gen_awg_params(rng),
        },
        "vault_backup_writer": {"access_key": "CHANGE_ME", "secret_key": "CHANGE_ME"},
        "vault_backup_reader": {"access_key": "CHANGE_ME", "secret_key": "CHANGE_ME"},
        "vault_backup_age_identity": "CHANGE_ME",
    }
    header = (
        f"# Suggested ports for vars.yml: entry_awg_port: {entry_port}, "
        f"exit_awg_port: {exit_port}\n"
        "# Encrypt with: ansible-vault encrypt vault.yml\n"
    )
    return header + _dump(doc)


def gen_uplink_key() -> str:
    priv = awg.genkey()
    return _dump({"vault_uplink_entry": {"private_key": priv, "public_key": awg.pubkey(priv)}})


def main(argv: list) -> int:
    if len(argv) != 2 or argv[1] not in ("all", "uplink-key"):
        print(__doc__, file=sys.stderr)
        return 2
    sys.stdout.write(gen_all() if argv[1] == "all" else gen_uplink_key())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
