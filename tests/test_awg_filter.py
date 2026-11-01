import base64
import importlib.util
import random
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

_spec = importlib.util.spec_from_file_location(
    "awg", Path(__file__).resolve().parent.parent / "plugins" / "filter" / "awg.py"
)
awg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(awg)

def test_pubkey_roundtrip():
    priv = awg.genkey()
    pub = awg.pubkey(priv)
    assert len(pub) == 44 and len(base64.b64decode(pub)) == 32
    assert pub == awg.pubkey(priv)
    known_priv = base64.b64encode(b"\x01" * 32).decode()
    expected = base64.b64encode(
        X25519PrivateKey.from_private_bytes(b"\x01" * 32).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    assert awg.pubkey(known_priv) == expected


def _h_range(value):
    lo, _, hi = value.partition("-")
    return int(lo), int(hi or lo)


def test_params_keep_app_timings_and_toggles():
    p = awg.gen_awg_params(random.Random(1))
    assert len(p["header_protection_key"]) == 44
    assert p["rekey_after_time"] == "100-120"
    assert p["rekey_timeout"] == "3-7"
    assert p["reject_after_time"] == "150-180"
    assert p["keepalive_timeout"] == "5-15"
    assert p["max_handshake_attempts"] == "15-20"
    assert p["random_trailers"] == "on" and p["disable_cookies"] == "on"
    assert all(p[k] == "" for k in ("i2", "i3", "i4", "i5", "content_padding_addition"))
    assert all(isinstance(v, str) for v in p.values())


def test_random_params_respect_constraints():
    # amneziawg-go: H ranges must not overlap, S >= 12 with header protection;
    # Amnezia app: H unique, padded sizes 148+S1, 92+S2, 64+S3, 32+S4 distinct.
    for seed in range(3000):
        p = awg.gen_awg_params(random.Random(seed))
        assert 4 <= int(p["jc"]) <= 8
        jmin, jmax = int(p["jmin"]), int(p["jmax"])
        assert 10 <= jmin <= 100 and jmin + 50 <= jmax <= min(jmin + 600, 1000)
        s = [int(p[f"s{i}"]) for i in range(1, 5)]
        assert all(15 <= x <= 150 for x in s[:3]) and 12 <= s[3] <= 32
        sizes = [148 + s[0], 92 + s[1], 64 + s[2], 32 + s[3]]
        assert len(set(sizes)) == 4
        ranges = sorted(_h_range(p[f"h{i}"]) for i in range(1, 5))
        assert all(5 <= lo <= hi < 2**31 for lo, hi in ranges)
        assert all(a[1] < b[0] for a, b in zip(ranges, ranges[1:]))


def test_i1_is_a_dns_query_packet():
    p = awg.gen_awg_params(random.Random(7))
    assert p["i1"].startswith("<b 0x") and p["i1"].endswith(">")
    raw = bytes.fromhex(p["i1"][5:-1])
    assert raw[2:12] == bytes.fromhex("01000001000000000000")
    assert raw[-4:] == bytes.fromhex("00010001") and raw[-5] == 0
    labels, i = [], 12
    while raw[i]:
        labels.append(raw[i + 1:i + 1 + raw[i]].decode())
        i += 1 + raw[i]
    assert ".".join(labels) in awg.I1_DOMAINS and i == len(raw) - 5


def test_two_param_sets_differ():
    a = awg.gen_awg_params(random.Random())
    b = awg.gen_awg_params(random.Random())
    assert a["header_protection_key"] != b["header_protection_key"]
    keys = ["jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1"]
    assert [a[k] for k in keys] != [b[k] for k in keys]


def test_lines_order_and_omission():
    p = awg.gen_awg_params(random.Random(1))
    lines = awg.awg_params_lines(p, False)
    keys = [ln.split(" = ")[0] for ln in lines]
    assert keys == [
        "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
        "HeaderProtectionKey", "RekeyAfterTime", "RekeyTimeout",
        "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts",
        "RandomTrailers", "DisableCookies", "I1",
    ]
    assert f"Jmin = {p['jmin']}" in lines
    p["content_padding_addition"] = "10-100"
    keys = [ln.split(" = ")[0] for ln in awg.awg_params_lines(p, False)]
    assert keys.index("ContentPaddingAddition") == keys.index("HeaderProtectionKey") + 1


def test_lines_comment_i():
    p = awg.gen_awg_params(random.Random(1))
    p["i2"] = "<r 5>"
    lines = awg.awg_params_lines(p, True)
    assert f"# I1 = {p['i1']}" in lines
    assert "# I2 = <r 5>" in lines
    assert not any(ln.startswith("I") for ln in lines)
    assert "Jc = " + p["jc"] in lines
