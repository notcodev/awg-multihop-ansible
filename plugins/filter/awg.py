"""AmneziaWG key/param helpers and Ansible filters.

Obfuscation values (Jc/Jmin/Jmax, S1-S4, H1-H4, I1) are randomized per call so
deployments and links don't share the Amnezia app's fixed defaults. Timings and
toggles mirror AwgInstaller::generateAwgParameters of amnezia-client
(commit 7f9b7db, protocolConstants.h namespace awg).

Constraints: amneziawg-go rejects overlapping H ranges and, with a
HeaderProtectionKey, any S below 12; the Amnezia app rejects equal H values and
equal padded message sizes (148+S1, 92+S2, 64+S3, 32+S4).
"""
import base64
import random

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# WireGuard message sizes the app compares padded sizes against.
_MESSAGE_SIZES = (148, 92, 64, 32)

# Common names for the I1 DNS-query signature packet.
I1_DOMAINS = (
    "google.com", "youtube.com", "apple.com", "microsoft.com", "cloudflare.com",
    "amazon.com", "yandex.ru", "vk.com", "wikipedia.org", "github.com",
    "icloud.com", "office.com", "whatsapp.net", "telegram.org", "mail.ru",
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


def _gen_paddings(rng: random.Random) -> list:
    # S4 pads every data packet, so it stays small; S1-S3 only pad handshakes.
    while True:
        s = [rng.randint(15, 150), rng.randint(15, 150), rng.randint(15, 150),
             rng.randint(12, 32)]
        if len({m + x for m, x in zip(_MESSAGE_SIZES, s)}) == 4:
            return s


def _gen_headers(rng: random.Random) -> list:
    # Four disjoint "lo-hi" ranges in [5, 2^31): sorted distinct bounds paired up.
    bounds = sorted(rng.sample(range(5, 2**31), 8))
    ranges = [f"{bounds[i]}-{bounds[i + 1]}" for i in range(0, 8, 2)]
    rng.shuffle(ranges)
    return ranges


def _gen_dns_query(rng: random.Random) -> str:
    qname = b"".join(
        bytes([len(label)]) + label.encode() for label in rng.choice(I1_DOMAINS).split(".")
    )
    packet = (rng.randbytes(2) + bytes.fromhex("01000001000000000000") + qname
              + b"\x00" + bytes.fromhex("00010001"))
    return f"<b 0x{packet.hex()}>"


def gen_awg_params(rng: random.Random) -> dict:
    jmin = rng.randint(10, 100)
    s = _gen_paddings(rng)
    h = _gen_headers(rng)
    return {
        "jc": str(rng.randint(4, 8)),
        "jmin": str(jmin),
        "jmax": str(min(jmin + rng.randint(50, 600), 1000)),
        "s1": str(s[0]), "s2": str(s[1]), "s3": str(s[2]), "s4": str(s[3]),
        "h1": h[0], "h2": h[1], "h3": h[2], "h4": h[3],
        "i1": _gen_dns_query(rng),
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
