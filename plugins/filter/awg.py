"""AmneziaWG key/param helpers and Ansible filters.

Defaults mirror AwgInstaller::generateAwgParameters of amnezia-client
(commit 7f9b7db, protocolConstants.h namespace awg).
"""
import base64
import random

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

DEFAULT_SPECIAL_JUNK1 = (
    "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c"
    "000100010000105a00044d583737>"
)

_LINE_ORDER = [
    ("Jc", "jc"), ("Jmin", "jmin"), ("Jmax", "jmax"),
    ("S1", "s1"), ("S2", "s2"), ("S3", "s3"), ("S4", "s4"),
    ("H1", "h1"), ("H2", "h2"), ("H3", "h3"), ("H4", "h4"),
    ("HeaderProtectionKey", "header_protection_key"),
    ("ContentPaddingAddition", "content_padding_addition"),
    ("RekeyAfterTime", "rekey_after_time"),
    ("RekeyTimeout", "rekey_timeout"),
    ("RejectAfterTime", "reject_after_time"),
    ("KeepaliveTimeout", "keepalive_timeout"),
    ("MaxHandshakeAttempts", "max_handshake_attempts"),
    ("RandomTrailers", "random_trailers"),
    ("DisableCookies", "disable_cookies"),
    ("I1", "i1"), ("I2", "i2"), ("I3", "i3"), ("I4", "i4"), ("I5", "i5"),
]


def genkey() -> str:
    raw = X25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode()


def pubkey(priv: str) -> str:
    key = X25519PrivateKey.from_private_bytes(base64.b64decode(priv))
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode()


def genpsk() -> str:
    return genkey()


def gen_awg_params(rng: random.Random) -> dict:
    return {
        "jc": str(rng.randint(4, 6)),
        "jmin": "10",
        "jmax": "50",
        "s1": "12", "s2": "12", "s3": "12", "s4": "12",
        "h1": "1", "h2": "2", "h3": "3", "h4": "4",
        "i1": DEFAULT_SPECIAL_JUNK1,
        "i2": "", "i3": "", "i4": "", "i5": "",
        "header_protection_key": genkey(),
        "content_padding_addition": "",
        "rekey_after_time": "100-120",
        "rekey_timeout": "3-7",
        "reject_after_time": "150-180",
        "keepalive_timeout": "5-15",
        "max_handshake_attempts": "15-20",
        "random_trailers": "on",
        "disable_cookies": "on",
    }


def awg_params_lines(params: dict, comment_i: bool = False) -> list:
    lines = []
    for name, key in _LINE_ORDER:
        value = str(params.get(key, "") or "")
        if value == "":
            continue
        prefix = "# " if comment_i and key.startswith("i") and len(key) == 2 else ""
        lines.append(f"{prefix}{name} = {value}")
    return lines


class FilterModule:
    def filters(self):
        return {"awg_pubkey": pubkey, "awg_params_lines": awg_params_lines}
