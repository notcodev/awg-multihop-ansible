"""Restore validation for entry backups (controller side).

awg-quick runs PreUp/PostUp/PreDown/PostDown from awg0.conf as root, age
gives no authenticity and the recipient key is public, so a holder of the S3
writer key could plant a backup that runs code on the next restored entry.
A backup is accepted only if every member is a regular file directly at the
archive root and awg0.conf uses allow-listed keys, with the inventory's port
and subnet.
"""
import ipaddress
import tarfile

INTERFACE_KEYS = {
    "privatekey", "address", "listenport", "mtu",
    "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
    "i1", "i2", "i3", "i4", "i5",
    "headerprotectionkey", "contentpaddingaddition", "rekeyaftertime", "rekeytimeout",
    "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts", "randomtrailers",
    "disablecookies",
}
PEER_KEYS = {"publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"}
SECTIONS = {"[Interface]": INTERFACE_KEYS, "[Peer]": PEER_KEYS}
REQUIRED = ("awg0.conf", "wireguard_server_private_key.key")


def _root_name(name):
    """Member name relative to the archive root, '' for the root itself, None if not at the root."""
    rel = name[2:] if name.startswith("./") else name
    rel = rel.rstrip("/") if rel not in ("", ".") else ""
    if rel in ("", "."):
        return ""
    if name.startswith("/") or "/" in rel or rel in ("..",):
        return None
    return rel


def _conf_problems(text, port, subnet):
    problems, section, seen = [], None, {"listenport": [], "address": []}
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.split("#", 1)[0].strip()  # as awg-quick: '#' starts a comment
        if not stripped:
            continue
        if stripped.startswith("["):
            if stripped not in SECTIONS:
                problems.append(f"awg0.conf line {n}: unknown section {stripped!r}")
                section = None
                continue
            section = stripped
            continue
        if "=" not in stripped:
            problems.append(f"awg0.conf line {n}: not a 'Key = value' line")
            continue
        key, value = (part.strip() for part in stripped.split("=", 1))
        if section is None:
            problems.append(f"awg0.conf line {n}: '{key}' outside a section")
            continue
        if key.lower() not in SECTIONS[section]:
            problems.append(f"awg0.conf line {n}: key '{key}' is not allowed in {section}")
            continue
        if section == "[Interface]" and key.lower() in seen:
            seen[key.lower()].append(value)
    ports = seen["listenport"]
    if ports != [str(port)]:
        problems.append(f"awg0.conf ListenPort {', '.join(ports) or '(missing)'} != entry_awg_port {port}")
    net = ipaddress.ip_network(subnet, strict=False)
    addrs = [a.strip() for v in seen["address"] for a in v.split(",") if a.strip()]
    if not addrs:
        problems.append(f"awg0.conf Address (missing) is not in entry_awg_subnet {subnet}")
    for addr in addrs:
        try:
            ok = ipaddress.ip_interface(addr).network == net
        except ValueError:
            ok = False
        if not ok:
            problems.append(f"awg0.conf Address {addr} is not in entry_awg_subnet {subnet}")
    return problems


def backup_archive_problems(path, port, subnet):
    """Return a list of reasons to refuse the decrypted backup tar at `path` (empty = ok)."""
    problems, names, conf = [], set(), None
    try:
        tar = tarfile.open(path, "r:")
    except (tarfile.TarError, OSError) as exc:
        return [f"not a readable tar archive ({exc})"]
    with tar:
        for m in tar.getmembers():
            rel = _root_name(m.name)
            if rel is None:
                problems.append(f"member {m.name!r} is not directly at the archive root")
                continue
            if rel == "":
                if not m.isdir():
                    problems.append(f"member {m.name!r} must be the root directory")
                elif "" in names:
                    problems.append(f"duplicate member {m.name!r}")
                names.add("")
                continue
            if not m.isreg():
                problems.append(f"member {m.name!r} is not a regular file")
                continue
            if rel in names:
                problems.append(f"duplicate member {m.name!r}")
                continue
            names.add(rel)
            if rel == "awg0.conf":
                conf = tar.extractfile(m).read()
    for req in REQUIRED:
        if req not in names:
            problems.append(f"{req} is missing at the archive root")
    if conf is not None:
        try:
            problems += _conf_problems(conf.decode("utf-8"), port, subnet)
        except UnicodeDecodeError:
            problems.append("awg0.conf is not UTF-8 text")
    return problems


class FilterModule:
    def filters(self):
        return {"backup_archive_problems": backup_archive_problems}
