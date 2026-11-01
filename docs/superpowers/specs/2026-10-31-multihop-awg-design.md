# Multihop AmneziaWG VPN with Ansible — Design

Date: 2026-10-31
Status: draft v2 (reviewer questions folded in), awaiting approval

## 1. Intent

Users in country A connect with the **Amnezia VPN app** to an **entry server**
that is also in country A. The entry server forwards all of their traffic
through an AmneziaWG tunnel to an **exit server** in country B. Websites see
the exit server's IP.

Why: the user→entry link looks like ordinary domestic traffic, and the
entry→exit link is the one that has to survive cross-border filtering. Both
links therefore use AmneziaWG (the obfuscated WireGuard), not plain WireGuard.

The owner wants:

- to **manage users from the Amnezia VPN app**: add/revoke users and share the
  `vpn://` keys the app generates;
- to be able to **swap the entry server** at any time without re-issuing keys
  to users;
- to be able to **swap the exit server** at any time **without reconfiguring
  the entry server**;
- **reusable Ansible playbooks** that do all of this.

## 2. Goals

1. One command deploys a working entry + exit pair on fresh Ubuntu 24.04
   servers.
2. The entry server's AmneziaWG server is a container the Amnezia app
   recognises as its own, so users are managed entirely from the app.
3. Both links use the AmneziaWG protocol the app labels **"version 3.1"**.
4. **Entry swap:** one command deploys a new entry server from the latest
   backup. It keeps the same server key, the same obfuscation parameters and
   the same users. The owner repoints the entry DNS record, and users
   reconnect with their existing keys.
5. **Exit swap:** one command deploys a new exit server as an exact clone
   (same keys, same parameters). The owner repoints the exit DNS record. The
   entry server notices by itself, with no Ansible run against the entry.
6. Automatic, encrypted, versioned backups of the entry's user state to an
   S3-compatible bucket.
7. Re-running any playbook is safe: it never destroys users added through the
   app.
8. **Server-side split routing on the entry:** traffic to domestic
   destinations (country A IP ranges plus owner-listed networks/domains)
   leaves directly from the entry. Everything else goes through the exit.
   Transparent to the app and to users; the lists live in Ansible variables.

## 3. Non-goals

- Running more than one entry or more than one exit at once (no load
  balancing or failover pools). The design should not *prevent* adding this
  later, but it is not built now.
- IPv6 inside the tunnel. Client configs carry `::/0` (app default); IPv6 is
  simply not routed. See §8.6.
- Other Amnezia protocols (OpenVPN, XRay, etc.) and AmneziaDNS on the entry.
- Monitoring/alerting stacks.
- Automatic DNS record changes through a provider API (only a pluggable hook
  with a "manual" default; see §8.8).
- General server hardening beyond what the VPN needs (SSH hardening etc. is
  the owner's existing practice).
- **Importing an existing Amnezia server.** This is a fresh start; there are
  no existing users whose keys must survive (designer's assumption, stated to
  the owner and not contradicted).
- **Changing AmneziaWG protocol settings from the app.** Forbidden by the
  owner (see §7.5). Pushing split-tunnel lists into client keys is also out
  of scope: the app always writes `AllowedIPs = 0.0.0.0/0, ::/0` for users it
  creates, so split routing is done on the server (§7.6).

## 4. Anti-goals (failure even if it "works")

- **Leaking through the entry's IP.** If the exit or the tunnel is down,
  user traffic must be dropped, never NATed out of the entry server's own
  public interface (fail-closed). The **only** exception is traffic to
  destinations on the split-routing direct list (§7.6), which leaves from the
  entry by design.
- **Losing users.** An Ansible run, a container recreate or an entry swap
  must not silently drop users the app added.
- **Breaking the app's management.** Anything Ansible creates on the entry
  must not confuse the app (for example, no extra containers whose names
  start with `amnezia-`) or overwrite the app's files on a re-run.
- **Readable secrets at rest outside the owner's control.** Backups in S3 must
  be encrypted with a key that never lives on any server.
- **Pinning to "whatever is latest today".** Container images must be pinned
  so a rebuild months later produces the same thing.

## 5. Constraints

- OS: **Ubuntu 24.04** on both servers.
- Entry server and exit server are reachable by **domain names** under a
  DNS zone the owner controls in a cloud provider's control panel (trusted,
  provider-hosted domain). The owner can set low TTLs. There is no API
  integration assumed.
- Backups go to an **S3-compatible** bucket. The provider is not fixed; the
  endpoint URL is configurable.
- The Amnezia app manages a server over **SSH with sudo**, using
  `sudo docker ...` commands.

## 6. How the Amnezia app sees a server (verified in source)

Verified against `amnezia-vpn/amnezia-client` at commit `7f9b7db`
(2026-10-29):

- Protocol "AmneziaWG" in the app is the container **`amnezia-awg2`**
  (`ContainerUtils::containerToString`). Its install scripts are in
  `client/server_scripts/awg/` (`Dockerfile`, `configure_container.sh`,
  `run_container.sh`, `start.sh`, `template.conf`). The older
  `amnezia-awg` / `awg_legacy` container is out of scope.
- **Version 3.1** is the app's label for configs carrying any of
  `HeaderProtectionKey`, `ContentPaddingAddition`, `RekeyAfterTime`,
  `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`,
  `MaxHandshakeAttempts`, or `RandomTrailers`/`DisableCookies = on`
  (`awgProtocolConfig.cpp`, `hasAwg3Markers`). Fresh installs from the app
  default to 3.1, using the defaults from `AwgInstaller::generateAwgParameters`
  and `protocolConstants.h`.
- **Detecting an existing server:** the app runs
  `sudo docker ps --format '{{.Names}} {{.Ports}}'` and matches
  `(amnezia[-a-z0-9]*).*?:([0-9]*)->[0-9]*/(udp|tcp)`. It then reads
  `/opt/amnezia/awg/awg0.conf` from inside the container (`docker exec ... xxd`)
  and parses `key = value` lines. I1–I5 are read from **commented**
  `# I1 = ...` lines in the server config.
- **Users list:** `/opt/amnezia/awg/clientsTable` inside the container. Peers
  are written into `awg0.conf` inside the container.
- **Domain names:** for AWG containers the app keeps the host name **as
  entered** (`genBaseVars`: AWG skips IP resolution) and writes it as the
  `Endpoint` of every client config. The client app resolves the name at each
  connect (`vpnConnection.cpp`, `getIPAddress`). This is what makes the entry
  swappable via DNS.
- The app's run script uses no volume for `/opt/amnezia/awg`. Everything lives
  in the container's writable layer.
- **Editing protocol settings in the app reinstalls the container.**
  `InstallController::updateServerConfig` → `isReinstallContainerRequired`
  (true when `AwgServerConfig::hasEqualServerSettings` is false: port,
  subnet, any J/S/H/I or 3.1 parameter) → `docker rm -fv`, `docker rmi`,
  `docker build --no-cache --pull` from `amneziawg-go:latest`, run without
  our bind mount, new server keys, empty user list. All issued keys die. This
  is plain Amnezia behaviour, independent of this project.
- **Split tunneling in the app** is client-side: site-based lists are app
  settings per device. If a client config's `AllowedIPs` is not exactly
  `0.0.0.0/0` + `::/0`, the app routes only those networks and disables site
  split tunneling (`vpnConnection.cpp`, `appendSplitTunnelingConfig`). For
  users the app creates on a self-hosted server, `AllowedIPs` is always
  `0.0.0.0/0, ::/0` (`wireguardConfigurator.cpp`), so it can't be pushed
  from the server through the app.
- Docker networking the app creates: bridge **`amnezia-dns-net`**, subnet
  `172.29.172.0/24`, bridge interface **`amn0`**. The AWG container also sits
  on the default bridge (`docker0`). Inside the container, `start.sh` NATs the
  VPN subnet out of `eth0`/`eth1`.

## 7. Architecture

```
 user (Amnezia app) ──AWG 3.1──▶ ENTRY (country A)                  EXIT (country B)
   endpoint: entry.<domain>      ┌──────────────────────────┐       ┌──────────────────────┐
                                 │ container amnezia-awg2   │       │ container            │
                                 │  (app-managed users)     │       │ multihop-exit        │
                                 │  NAT → docker0 / amn0    │       │  AWG 3.1 server,     │
                                 └────────────┬─────────────┘       │  one peer: entry     │
                                              │ policy routing      │  NAT → internet      │
                                 ┌────────────▼─────────────┐       └──────────▲───────────┘
                                 │ container multihop-uplink│──AWG 3.1───────┘
                                 │  (host network) iface    │   endpoint: exit.<domain>
                                 │  awg-uplink              │
                                 └──────────────────────────┘
```

### 7.1 Exit server

- Docker, plus one container **`multihop-exit`** running the AmneziaWG
  userspace implementation (`amneziavpn/amneziawg-go`, pinned by digest), the
  same build family the app uses.
- One `[Interface]` (exit private key, listen port, all AWG 3.1 parameters)
  and **one `[Peer]`**: the entry server (entry-uplink public key, PSK,
  `AllowedIPs` = the uplink tunnel address of the entry).
- The exit has no `Endpoint` for the entry; the entry always dials out. This
  is why the exit does not care what the entry's IP is.
- NAT (masquerade) from the tunnel to the exit's public interface. IP
  forwarding enabled.
- Host firewall: allow SSH and the AWG UDP port; drop everything else
  inbound.
- **Identity is fully defined by vault variables** (private key, PSK, all AWG
  parameters, listen port, tunnel addressing). Deploying the exit role onto
  any fresh server produces an identical exit.

### 7.2 Entry server: the app-managed part

- Ansible reproduces what the app does on install:
  - installs Docker;
  - creates the `amnezia-dns-net` network (172.29.172.0/24, bridge `amn0`);
  - builds the `amnezia-awg2` image from a **vendored copy** of the app's
    `server_scripts/awg/Dockerfile`, with the base image pinned by digest;
  - writes `start.sh` with the variables the app would substitute;
  - writes `awg0.conf` from vault-held parameters;
  - runs the container with the app's flags and port mapping (`-p
    PORT:PORT/udp`, privileged, `NET_ADMIN`, `SYS_MODULE`,
    `src_valid_mark=1`, connected to `amnezia-dns-net`).
- **Deliberate difference from the app:** `/opt/amnezia/awg` is a
  **bind mount** from the host (`/opt/amnezia-state/awg2/` or similar). The
  app keeps working, because it only uses `docker exec`, but now:
  - the state survives a container recreate;
  - backups read files from the host instead of `docker exec`.
- **Ownership rule:** Ansible writes `awg0.conf`, the key files and
  `clientsTable` **only when they don't exist yet** (first deploy) or when a
  restore is explicitly requested. On every other run it leaves them alone.
  The app owns them from then on.
- The entry's AWG server identity (private key, PSK file, every obfuscation
  parameter, port, client subnet) lives in vault, but **only to seed the very
  first deploy**. After that, the **backup is the source of truth**. On a
  restore, the backup wins over the vault whenever they differ. The playbook
  warns about the difference but doesn't fail.
- After the first deploy the owner adds the server in the app by **domain**
  (`entry.<domain>`) with SSH credentials. The app detects `amnezia-awg2` as
  already installed.

### 7.3 Entry server: the uplink and routing (Ansible-owned)

- A second container, **`multihop-uplink`**, using the same pinned
  amneziawg-go image with `--network host`, `NET_ADMIN`, and `/dev/net/tun`.
  It creates the interface **`awg-uplink`** in the host network namespace.
  - Its name must **not** start with `amnezia-`, so the app ignores it.
  - Config: entry-uplink private key, exit public key, PSK,
    `Endpoint = exit.<domain>:<port>`, AWG 3.1 parameters matching the exit,
    `PersistentKeepalive`.
  - It must **not** install a default route in the host's main table (no
    `wg-quick`-style `AllowedIPs = 0.0.0.0/0` auto-routing in the main table).
    Use `Table = off` or the equivalent and let §7.3 routing handle it.
- **Policy routing on the host** (systemd unit or networkd config, persistent
  across reboots):
  - a routing table `multihop`: `default dev awg-uplink`, plus a
    `blackhole default` (or `unreachable`) at a higher metric, so traffic is
    dropped, not leaked, when the uplink is down (fail-closed);
  - rules sending **forwarded traffic arriving from the Docker bridges
    (`iif docker0`, `iif amn0`)** to table `multihop`;
  - a higher-priority exception so the **AWG server's own packets** to
    users (UDP, source port = entry listen port, coming from the
    `amnezia-awg2` container; replies and server-initiated packets alike) use
    the main table and leave via the entry's public interface. Without this,
    they would go into the uplink and break the user→entry link. These
    packets get a dedicated fwmark (`0x5b00/0xff00`) and an `ip rule` for
    that mark (priority 10110) uses the main table. The source port alone
    identifies the AWG socket because the container's start.sh masquerades
    user UDP into a port range that excludes the listen port, so a user flow
    can never carry that source port;
  - local/bridge destinations (Docker subnets) stay in the main table
    (`suppress_prefixlength 0` pattern or explicit routes).
  - Host-originated traffic (apt, SSH, the uplink's own UDP to the exit, S3
    backups) is **not** routed into the tunnel.
- **NAT on the uplink:** packets leaving `awg-uplink` are masqueraded to the
  entry's uplink tunnel address, so the exit only needs one `AllowedIPs`
  entry for the entry.
- **Firewall fail-closed backstop:** a `DOCKER-USER` (or equivalent) rule
  that drops traffic from the Docker bridges going out of the entry's public
  interface, except the AWG server's packets described above. This is
  the guarantee against leaks if routing is ever wrong.
- **MTU:** two stacked AWG headers. Set the uplink MTU so the inner tunnel
  fits (start with 1420 on the uplink, and clamp TCP MSS on forwarded traffic
  into `awg-uplink`). The exact values are left to the builder (see §10).
- **Split routing exception:** traffic whose destination is on the direct
  list (§7.6) is routed via the main table and NATed out of the entry's public
  interface. The fail-closed firewall backstop allows exactly that set and
  nothing else.
- **Exit re-resolve:** a systemd timer (every ~1 min) resolves
  `exit.<domain>`. When it differs from the uplink peer's current endpoint, it
  runs `awg set awg-uplink peer <pub> endpoint <new-ip>:<port>` inside the
  uplink container. This is how an exit swap needs no Ansible run on the
  entry.

### 7.4 Backups (entry user state)

- A systemd timer on the entry, every 15 minutes by default:
  1. Archive the bind-mounted `/opt/amnezia/awg` state (awg0.conf, key files,
     clientsTable) into a tarball.
  2. If its hash equals the last uploaded hash, stop.
  3. Otherwise encrypt with **`age`** to the owner's age **public** key, and
     upload with the **AWS CLI** (custom `--endpoint-url`) to
     `s3://<bucket>/<prefix>/entry-<timestamp>.tar.age`, plus update a
     `latest` pointer object.
- Backups use a **dedicated bucket** (nothing else stored in it) with
  **versioning** on. The owner enables versioning; the playbook documents it
  and, where the provider supports the API call, checks for it and warns.
- The entry server gets the narrowest S3 credentials the provider supports:
  write-only to the prefix if possible, otherwise scoped to the dedicated
  bucket. The vault has two credential sets: `backup_writer` (on the entry)
  and `backup_reader` (owner's machine only, used for restore). They may be
  the same key if the provider can't separate them. Because backups are
  age-encrypted, a leaked entry credential still exposes no secrets; at worst
  someone can delete or overwrite objects, which versioning covers.
- The age **private** key never touches any server: it lives in the Ansible
  vault on the owner's machine.
- **Drift detection:** every backup run, and every `entry.yml` run, checks
  that the `amnezia-awg2` container still has the bind mount. If not (the
  app reinstalled it, §7.5), the backup timer exits non-zero, logs loudly
  and writes a marker file, and `entry.yml` fails with recovery instructions.
- Restoring is done by Ansible from the owner's machine:
  1. Download the backup (latest, or a named object) locally.
  2. Decrypt it locally.
  3. Push the decrypted state to the new entry's bind-mount path before the
     `amnezia-awg2` container starts.
- An on-demand backup task runs as the first step of the entry-swap playbook,
  if the old entry is still reachable.
- Exit state is not backed up to S3: it is fully defined by the vault.

### 7.5 Forbidden: editing protocol settings in the app

Owner's decision: changing AmneziaWG settings (port, subnet, obfuscation
parameters) from the app is **forbidden**. Adding/removing/renaming users
and sharing keys stays fully supported.

- The README says so prominently, with the reason (§6: it wipes keys and
  users).
- Detection as in §7.4 (bind mount missing → loud failure in timer and
  playbooks).
- Recovery documented in the README: run `restore.yml` with the last good
  backup. That recreates the container with the bind mount and the previous
  identity; keys issued *after* the reinstall are lost, and that's
  acceptable.
- To change protocol parameters intentionally, the owner edits vault vars
  and runs a dedicated, explicitly confirmed `rekey-entry.yml`. Because that
  invalidates all user keys, it's a rare, deliberate operation. (Optional.
  The builder may defer this playbook, but must not make it easy to trigger
  by accident.)

### 7.6 Server-side split routing (entry)

Goal: traffic to destinations in country A leaves directly from the entry
(local IP, lower latency, local sites that block foreign IPs keep working).
Everything else goes via the exit.

- Variables:
  - `split_routing_enabled` (default `true`);
  - `split_direct_countries` (list of ISO codes, e.g. `[RU]`);
  - `split_country_list_url` (template URL for per-country aggregated CIDR
    lists, default a public source such as ipdeny aggregated zones;
    overridable);
  - `split_direct_cidrs` (extra networks to send direct);
  - `split_direct_domains` (domains resolved periodically on the entry, with
    their A records added to the direct set);
  - `split_force_exit_cidrs` (overrides: domestic networks that must still go
    via the exit; wins over everything above).
- Mechanism: a kernel set (nftables set or ipset; builder's choice) of
  direct prefixes, matched on traffic arriving from the Docker bridges. It
  sets a fwmark, and an `ip rule` for that mark uses the main table. The rest
  follows the `multihop` table from §7.3. Thousands of prefixes are expected
  (a whole country), so use a set, not individual routes.
- A systemd timer refreshes the country lists (daily) and the domain
  resolutions (every ~10 min), and updates the set atomically. If a download
  fails, keep the previous set. Never fall back to an empty set and never
  to "everything direct".
- The firewall backstop (§7.3) allows public-interface egress from the
  Docker bridges only for packets carrying the direct mark (plus AWG
  replies).
- DNS: users' DNS queries go wherever the app config points (default
  public resolvers) and follow the same rules (their IPs are not domestic, so
  normally via the exit).

### 7.7 DNS

- Two records owned by the owner: `entry.<domain>` → entry IP,
  `exit.<domain>` → exit IP, low TTL (60–300 s).
- The playbooks use a pluggable `dns_update` step. The default backend
  `manual` pauses and prints "point `exit.<domain>` to `<new IP>`, then press
  Enter", then waits until public resolution shows the new IP. The
  backend interface is a role/task file that takes `record`, `ip`; adding a
  provider backend later means adding one task file.

## 8. Playbooks and repository layout

### 8.1 Playbooks (entry points)

| Playbook | Does |
|---|---|
| `site.yml` | Full deploy of both: exit first, then entry. Idempotent; safe to re-run. |
| `exit.yml` | Deploy/converge the exit only. Used for first deploy and for exit swap. |
| `entry.yml` | Deploy/converge the entry only (no restore unless asked). |
| `swap-exit.yml` | Deploy exit onto the new host, DNS step, verify the entry's uplink handshakes with the new exit. |
| `swap-entry.yml` | Backup the old entry if reachable, deploy the new entry, restore the latest (or `backup_object=...`) backup, DNS step, verify. |
| `backup.yml` | Trigger an on-demand backup on the entry. |
| `restore.yml` | Restore a named backup onto the current entry (with confirmation). |
| `secrets.yml` (or a helper script) | Generate a fresh set of vault secrets (keys, PSKs, AWG parameters) for a new deployment. |

Swapping means "change which host the `entry` or `exit` group points to in
inventory, then run the swap playbook". The old and new hosts are both listed
during a swap (e.g. `entry_old` group), so the old entry can be backed up
first.

**Entry swap flow (`swap-entry.yml`).** A few minutes of downtime is
acceptable (designer's assumption, stated to the owner and not contradicted).

1. If the old entry is reachable: take a final backup, then **stop and
   disable** its `amnezia-awg2` and `multihop-uplink` containers, so no user
   is added after the last backup and the two entries never compete for the
   exit's single peer slot.
2. If the old entry is **not** reachable: generate a **new entry-uplink
   keypair**, store it in vault, and run the exit role, so the exit only
   accepts the new entry. This is why the entry-uplink key is a per-swap vault
   value, not fixed forever. The playbook says clearly that users added since
   the last backup are lost.
3. Deploy the new entry, restore the latest (or `backup_object=...`) backup.
4. DNS step for `entry.<domain>`.
5. Verify: the uplink handshake is fresh, and traffic from the app container
   exits with the exit's IP.

**Exit swap flow (`swap-exit.yml`):** deploy the exit role on the new host
(same vault identity), DNS step for `exit.<domain>`, wait for the entry's
re-resolve timer to pick it up, verify the handshake. Optionally stop the old
exit after verification.

### 8.2 Roles

- `common`: base packages, sysctl (forwarding, `src_valid_mark`), Docker
  install, host firewall basics.
- `awg_image`: build/pull the pinned amneziawg-go based images.
- `exit`: exit container, config, NAT, firewall.
- `entry_app`: the app-compatible `amnezia-awg2` container, network, bind
  mount, first-deploy state, restore.
- `entry_uplink`: uplink container, policy routing, fail-closed firewall,
  re-resolve timer.
- `split_routing`: direct-destination set, refresh timer, mark rules.
- `backup`: age + AWS CLI install, backup script and timer, credentials.
- `dns_update`: pluggable DNS step (`manual` backend).

### 8.3 Inventory and variables

- `inventories/<name>/hosts.yml` with groups `entry` and `exit`, one host
  each. Multiple inventories allow several independent deployments from the
  same code (reusability).
- `group_vars/all/vars.yml`: domains, ports, subnets, S3 endpoint/bucket/
  prefix, backup interval, image digests.
- `group_vars/all/vault.yml` (ansible-vault encrypted): all private keys,
  PSKs, AWG obfuscation parameters for **both** links, S3 credentials, age
  private key.
- The secrets generator randomizes the obfuscation values (Jc/Jmin/Jmax,
  S1–S4, H1–H4 ranges, a DNS-query I1) within the limits of amneziawg-go and
  the Amnezia app, and keeps the app's 3.1 timings and toggles (§6). The two
  links never share parameter values: each gets its own random set.

### 8.4 Addressing (defaults, overridable)

- User subnet (app default): `10.8.1.0/24`, server `10.8.1.1`.
- Uplink tunnel: `10.9.0.0/30`: exit `10.9.0.1`, entry `10.9.0.2`.
- Ports: entry user port and exit port configurable; defaults are random
  high UDP ports generated by the secrets generator.

### 8.5 Requirements on the owner's machine

Ansible (core 2.17+ or current), `community.docker`, `community.general`,
`ansible.posix`, the `age` CLI, the AWS CLI. These are listed in
`requirements.yml` and the README.

### 8.6 IPv6

Not routed. To keep the fail-closed guarantee, IPv6 forwarding from the
Docker bridges must not leak out of the entry (IPv6 forwarding off, or ip6
rules dropping it).

### 8.7 Verification built into the playbooks

- `exit.yml`: the container is running and listening on the UDP port.
- `entry.yml` does **not** verify itself (accepted deviation): the path
  checks live in `verify.yml` (`playbooks/tasks/verify-entry.yml`), which
  `site.yml`, `swap-exit.yml` and `swap-entry.yml` run at the end. It checks
  the uplink handshake, that a request from inside `amnezia-awg2` raises the
  exit's tunnel counters and shows the **exit's** public IP, the public
  interface's routing group, and that `amnezia-awg2` is the container
  entry_app builds (AWG up, the two UDP `--to-ports` rules, the build label).
- **Fail-closed test:** a separate `verify.yml` (optional) stops the uplink,
  confirms traffic from the app container is dropped (does not show the
  entry's IP), then starts the uplink again.

### 8.8 Documentation

A `README.md` covering: first deploy, adding the server in the app (by
domain), swap-entry procedure, swap-exit procedure, restoring an old backup,
what not to do in the app (don't "remove/reinstall" the AmneziaWG protocol
from the app: that recreates the container without the bind mount; the README
explains how to recover with `entry.yml` + restore).

## 9. Decisions made by the designer (not explicitly by the owner)

1. Ansible installs the entry's `amnezia-awg2` container itself (instead of
   the owner installing it from the app) so that a swap is one command.
2. `/opt/amnezia/awg` on the entry is a host bind mount (differs from the
   app) for durability and simple backups.
3. Both links run the userspace `amneziawg-go` in Docker, pinned by digest,
   rather than a kernel module from a PPA. That's one implementation and one
   upgrade path, matching what the app runs.
4. Fail-closed by default.
5. Backup every 15 minutes, upload only on change, `age` encryption, AWS CLI.
6. DNS updates: `manual` backend default, pluggable.
7. Separate random AWG parameters per link.
8. No AmneziaDNS container; users use whatever DNS the app config sets, which
   is routed via the exit anyway.
9. Fresh start, no import of an existing Amnezia server (assumed, not
   contradicted).
10. A few minutes of downtime during an entry swap is OK; the old entry is
    stopped after its final backup (assumed, not contradicted).
11. Backup wins over vault on restore; vault only seeds the first deploy.
12. Dedicated S3 bucket; narrowest credentials the provider supports;
    separate writer/reader credential sets in vault.
13. Entry-uplink key rotates when swapping away from an unreachable entry.
14. Split routing on by default once country codes are set. Country list
    source is configurable. On a refresh failure, the previous list is kept.

## 10. Left to the builder

- Exact iptables/nftables vs `ip rule` mechanics, as long as §7.3's
  behaviour and the fail-closed guarantee hold. Ubuntu 24.04 uses
  iptables-nft; Docker manages its own chains, so rules must coexist with
  Docker (DOCKER-USER) and survive Docker restarts.
- MTU / MSS clamp values (verify with a real path test).
- The secrets generator's implementation (Ansible task vs. small script).
  It must use `awg genkey` / `genpsk` (or equivalent X25519 generation)
  and the 3.1 parameter rules from the app source.
- How the re-resolve check is implemented (shell + `getent`/`dig` is fine).
- Testing approach: e.g. Molecule or two throwaway VMs. At minimum,
  `ansible-lint` and `--syntax-check` must pass.
