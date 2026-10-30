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

APP_I1 = (
    "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c"
    "000100010000105a00044d583737>"
)


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


def test_params_follow_app_generator():
    p = awg.gen_awg_params(random.Random(1))
    assert 4 <= int(p["jc"]) <= 6
    assert (p["jmin"], p["jmax"]) == ("10", "50")
    assert [p[f"s{i}"] for i in range(1, 5)] == ["12"] * 4
    assert [p[f"h{i}"] for i in range(1, 5)] == ["1", "2", "3", "4"]
    assert len(p["header_protection_key"]) == 44
    assert p["rekey_after_time"] == "100-120"
    assert p["rekey_timeout"] == "3-7"
    assert p["reject_after_time"] == "150-180"
    assert p["keepalive_timeout"] == "5-15"
    assert p["max_handshake_attempts"] == "15-20"
    assert p["random_trailers"] == "on" and p["disable_cookies"] == "on"
    assert p["i1"] == APP_I1
    assert all(p[k] == "" for k in ("i2", "i3", "i4", "i5", "content_padding_addition"))
    assert all(isinstance(v, str) for v in p.values())


def test_two_param_sets_differ():
    a = awg.gen_awg_params(random.Random())
    b = awg.gen_awg_params(random.Random())
    assert a["header_protection_key"] != b["header_protection_key"]


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
    assert "Jmin = 10" in lines
    p["content_padding_addition"] = "10-100"
    keys = [ln.split(" = ")[0] for ln in awg.awg_params_lines(p, False)]
    assert keys.index("ContentPaddingAddition") == keys.index("HeaderProtectionKey") + 1


def test_lines_comment_i():
    p = awg.gen_awg_params(random.Random(1))
    p["i2"] = "<r 5>"
    lines = awg.awg_params_lines(p, True)
    assert f"# I1 = {APP_I1}" in lines
    assert "# I2 = <r 5>" in lines
    assert not any(ln.startswith("I") for ln in lines)
    assert "Jc = " + p["jc"] in lines
