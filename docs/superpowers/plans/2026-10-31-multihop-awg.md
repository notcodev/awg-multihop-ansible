# Multihop AmneziaWG VPN — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reusable Ansible playbooks that deploy a two-hop AmneziaWG 3.1 VPN.
An app-manageable entry server (Amnezia VPN app, container `amnezia-awg2`)
forwards user traffic through an AWG uplink to a swappable exit server. The
playbooks also cover server-side split routing, encrypted S3 backups, and
entry/exit swap playbooks.

**Architecture:** Both hosts run Docker with the pinned `amneziawg-go`
image. The entry runs the app-compatible `amnezia-awg2` container, whose
state is bind-mounted from the host, plus a host-network `multihop-uplink`
container. Host-side shell scripts (`multihop-*`, run by systemd) own policy
routing, the firewall, split-routing sets, exit re-resolve and backups.
Ansible roles install and configure them. All secrets live in ansible-vault
files produced by a Python generator.

**Tech Stack:** ansible-core + community.docker/community.general/ansible.posix,
Python 3 (generator + filter plugin, pytest), POSIX bash scripts
(bats-core + shellcheck), iproute2, iptables-nft + ipset, systemd, `age`,
AWS CLI v2, Docker (`docker.io` on Ubuntu 24.04), Multipass for integration.

**Spec:** `docs/superpowers/specs/2026-10-31-multihop-awg-design.md`

## Global Constraints

- Target OS: Ubuntu 24.04 on both hosts. Controller: macOS/Linux with `uv`.
- App-facing names/paths are exact (from the spec, §6):
  - container and image named `amnezia-awg2`;
  - in-container config `/opt/amnezia/awg/awg0.conf`, plus
    `wireguard_server_private_key.key`, `wireguard_server_public_key.key`,
    `wireguard_psk.key` and `clientsTable` in the same directory;
  - Docker network `amnezia-dns-net`, subnet `172.29.172.0/24`, bridge `amn0`.
- In `awg0.conf` (the entry server side), I1–I5 are written **commented**
  (`# I1 = …`), as the app does; the app reads them from there.
- Nothing Ansible creates may match `grep amnezia` in `docker ps -a`,
  `docker images` output, or live under `/opt/amnezia`, except the
  `amnezia-awg2` container/image and the `amnezia-dns-net` network.
  - Ansible's own containers: `multihop-uplink` (entry) and `multihop-exit`
    (exit).
  - The base image is re-tagged locally as `multihop/awg-base:pinned`.
  - Host state lives under `/var/lib/multihop/`.
- Base image `amneziavpn/amneziawg-go` is pinned **by digest** (`awg_base_image_digest`).
- Fail-closed: traffic from `docker0`/`amn0` may leave the entry's public
  interface only if it carries the direct mark or is UDP from source port
  `entry_awg_port` (the AWG server's own socket). That port identifies only
  the AWG socket because `amnezia-awg2`'s start.sh masquerades user UDP into
  a port range that excludes `entry_awg_port`.
- Ansible writes entry state files (`awg0.conf`, key files) **only if
  `awg0.conf` is absent** or during an explicit restore. It never writes
  `clientsTable` (the app creates it).
- On restore, backup content wins over vault values.
- No IPv6 forwarding on either host.
- Interfaces:
  - `awg-uplink` (entry → exit) and `awg-exit` (exit side);
  - routing table `51820 multihop`;
  - direct fwmark `0x5a/0xff`; AWG-traffic fwmark `0x5b00/0xff00`;
  - ipsets `multihop_direct` and `multihop_force_exit`;
  - `ip rule` priorities 10100 (direct mark → main), 10110 (AWG-traffic
    mark `0x5b00/0xff00` → main), 10120 (bridges → main `suppress_prefixlength 0`) and 10130
    (bridges → multihop).
- Defaults:
  - user subnet `10.8.1.0/24` (server `10.8.1.1`);
  - uplink `10.9.0.0/30` (exit `.1`, entry `.2`);
  - `uplink_mtu: 1280`;
  - `backup_interval: 15min`;
  - re-resolve every `1min`;
  - domain refresh `10min`, country list refresh every 24h.
- Scripts read config from `${MULTIHOP_ENV:-/etc/multihop/multihop.env}` and
  state from `${MULTIHOP_STATE_DIR:-/var/lib/multihop}` (so bats can redirect them).
- Commits: one per task (the repo is initialised in Task 1).

### Variable contract (all tasks use these names)

`inventories/<name>/group_vars/all/vars.yml`:
- domains and ports: `entry_domain`, `exit_domain`, `entry_awg_port`,
  `exit_awg_port`, `ssh_port` (default 22);
- addressing and image: `entry_awg_subnet`, `uplink_subnet`, `uplink_mtu`,
  `awg_base_image_digest`;
- split routing: `split_routing_enabled`, `split_direct_countries`,
  `split_country_list_url` (with a `{cc}` placeholder, default
  `https://www.ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone`),
  `split_direct_cidrs`, `split_direct_domains`, `split_force_exit_cidrs`;
- backups: `backup_s3_endpoint`, `backup_s3_region`, `backup_s3_bucket`,
  `backup_s3_prefix`, `backup_interval`, `backup_age_recipient` (age public
  key);
- DNS: `dns_backend` (default `manual`).

`group_vars/all/vault.yml` (encrypted):
- `vault_entry_awg`: `{private_key, public_key, psk, params}`;
- `vault_link_awg`: `{exit_private_key, exit_public_key, psk, params}`;
- `vault_backup_writer` and `vault_backup_reader`: `{access_key, secret_key}`;
- `vault_backup_age_identity`.

`group_vars/all/vault_uplink.yml` (encrypted, rotatable):
- `vault_uplink_entry`: `{private_key, public_key}`.

`params` (AWG parameter dict) keys:
- junk and padding: `jc jmin jmax s1 s2 s3 s4`;
- headers and special junk: `h1 h2 h3 h4 i1 i2 i3 i4 i5`;
- 3.1 options: `header_protection_key content_padding_addition rekey_after_time
  rekey_timeout reject_after_time keepalive_timeout max_handshake_attempts
  random_trailers disable_cookies`.
- An empty string means "omit the line".

## Review Focus

1. **Re-running `entry.yml` after users were added in the app** must keep
   those peers and `clientsTable` untouched (Task 6 idempotency test,
   Task 13 integration step).
2. **Docker restart or host reboot** must restore routing and firewall
   before any user traffic flows. Fail-closed still holds (Task 7 unit
   ordering test, Task 13 restart/reboot step).
3. **Exit domain temporarily unresolvable** (NXDOMAIN, empty answer,
   resolver down) must leave the current uplink endpoint as it is, never
   clear it (Task 7 bats).
4. **Country list download returns garbage** (HTML error page, empty body,
   HTTP error) must keep the previous `multihop_direct` set, never empty it
   and never widen it (Task 8 bats).
5. **App reinstalled `amnezia-awg2` without the bind mount** must make
   backups refuse to run and `entry.yml` fail with recovery instructions
   (Task 9 bats, Task 6 assert, Task 13 step).

---

### Task 1: Repository scaffold and tooling

**Files:**
- Create:
  - repo root: `.gitignore`, `pyproject.toml` (via uv), `ansible.cfg`,
    `requirements.yml`, `Makefile`, `.ansible-lint`;
  - example inventory: `inventories/example/hosts.yml`,
    `inventories/example/group_vars/all/vars.yml`;
  - tests: `tests/conftest.py`, `tests/bats/helpers.bash`.

**Interfaces:**
- Produces:
  - `make lint` (shellcheck on `roles/*/files/multihop-*`, ansible-lint,
    `ansible-playbook --syntax-check` for every `playbooks/*.yml`);
  - `make test` (pytest + bats);
  - `make collections`;
  - the bats helper `stub <cmd> [stdout] [exit]`, which writes an executable
    to `$BATS_TEST_TMPDIR/bin` that appends `"<cmd> $*"` to `$STUB_LOG` and
    prints stdout;
  - `run_script <name> <args>`, which runs `roles/*/files/<name>` with that
    PATH prefix.

- [ ] **Step 1:** `git init`. Then run `uv init --bare` and
  `uv add --dev ansible-core ansible-lint pytest`. Install bats and
  shellcheck with `brew install bats-core shellcheck` (system tools, not
  manifest deps).
- [ ] **Step 2:** Write `ansible.cfg`:
  - `inventory = inventories/example`;
  - `roles_path = roles`;
  - `filter_plugins = plugins/filter`;
  - `collections_path = ./collections`;
  - `vault_password_file = .vault-pass`;
  - `interpreter_python = auto_silent`.

  Write `requirements.yml`, listing collections `community.docker`,
  `community.general` and `ansible.posix` with no versions. In `.gitignore`,
  ignore `.vault-pass`, `collections/`, `.venv/`, `tests/render/out/` and
  `*.decrypted*`.
- [ ] **Step 3:** Write `inventories/example/hosts.yml` (groups `entry` and
  `exit` with placeholder hosts, plus an empty `entry_old` group) and
  `vars.yml`, with every non-vault variable from the variable contract set
  to its documented default or a `CHANGE_ME` placeholder.
- [ ] **Step 4:** Write `tests/bats/helpers.bash` with `stub` and
  `run_script` as specified. Add a smoke test `tests/bats/helpers.bats`
  that stubs `ip` and asserts `$STUB_LOG` contains `ip rule show`.
- [ ] **Step 5:** Run `make collections && make test`. Expected: pytest
  reports "no tests ran" (exit 5 is acceptable, so make it non-fatal for
  now) and bats passes 1 test.
- [ ] **Step 6:** Commit with `chore: scaffold ansible project and test tooling`.

### Task 2: AWG secrets library, filter plugin, and secrets generator

**Files:**
- Create: `plugins/filter/awg.py`, `scripts/gen-secrets.py`, `tests/test_awg_filter.py`, `tests/test_gen_secrets.py`

**Interfaces:**
- Produces, in `plugins/filter/awg.py`:
  - pure functions: `genkey() -> str`, `pubkey(priv: str) -> str` and
    `genpsk() -> str`, all base64 X25519 via `cryptography`, which comes
    with ansible-core;
  - `gen_awg_params(rng: random.Random) -> dict`;
  - `awg_params_lines(params: dict, comment_i: bool) -> list[str]`;
  - the Ansible filters `awg_pubkey` and `awg_params_lines`.
- Produces, in `scripts/gen-secrets.py`:
  - `gen-secrets.py all`, which prints a full `vault.yml` YAML document
    (the `vault_*` keys from the contract, with S3 and age fields as
    `CHANGE_ME`) plus suggested `entry_awg_port`/`exit_awg_port` in a
    leading comment;
  - `gen-secrets.py uplink-key`, which prints a `vault_uplink.yml`
    document.

- [ ] **Step 1: Write failing tests** in `tests/test_awg_filter.py`:
  - `test_pubkey_roundtrip`: `pubkey(genkey())` is 44 chars of base64 and
    deterministic for the same private key. Check it against a known vector
    computed with `cryptography`'s `X25519PrivateKey.from_private_bytes(b"\x01"*32)`.
  - `test_params_follow_app_generator`, which mirrors the app's
    `AwgInstaller::generateAwgParameters`:
    - `4 <= jc <= 6`;
    - `jmin == "10"`, `jmax == "50"`;
    - `s1..s4 == "12"`;
    - `h1..h4 == "1","2","3","4"`;
    - `header_protection_key` is a 44-char base64 key;
    - `rekey_after_time == "100-120"`, `rekey_timeout == "3-7"`,
      `reject_after_time == "150-180"`, `keepalive_timeout == "5-15"`,
      `max_handshake_attempts == "15-20"`;
    - `random_trailers == "on"`, `disable_cookies == "on"`;
    - `i1 ==` the app's `defaultSpecialJunk1` string;
    - `i2..i5 == ""`, `content_padding_addition == ""`.
  - `test_two_param_sets_differ`: two calls produce different `header_protection_key`.
  - `test_lines_order_and_omission`:
    - output order is Jc, Jmin, Jmax, S1, S2, S3, S4, H1, H2, H3, H4,
      HeaderProtectionKey, ContentPaddingAddition, RekeyAfterTime,
      RekeyTimeout, RejectAfterTime, KeepaliveTimeout,
      MaxHandshakeAttempts, RandomTrailers, DisableCookies, I1..I5;
    - empty values are omitted;
    - the format is `Key = value`.
  - `test_lines_comment_i`: with `comment_i=True`, the I lines are
    `# I1 = …`.
- [ ] **Step 2:** Run `uv run pytest tests/test_awg_filter.py -v`.
  Expected: FAIL (module missing).
- [ ] **Step 3:** Implement `plugins/filter/awg.py` with the functions
  above and a `FilterModule`. Copy the app defaults verbatim from
  `client/core/utils/constants/protocolConstants.h` at commit `7f9b7db`.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5: Write failing tests** in `tests/test_gen_secrets.py`:
  - `test_all_outputs_valid_vault_doc`: run the script via subprocess and
    parse the YAML.
    - Required keys: `vault_entry_awg`, `vault_link_awg`,
      `vault_backup_writer`, `vault_backup_reader` and
      `vault_backup_age_identity`.
    - `vault_entry_awg.params` differs from `vault_link_awg.params` in
      `header_protection_key`.
    - Public keys match `pubkey(private)`.
  - `test_uplink_key_doc` checks the `uplink-key` output the same way.
- [ ] **Step 6:** Implement `scripts/gen-secrets.py`. It imports
  `plugins/filter/awg.py` via `sys.path`, uses `secrets.SystemRandom()`,
  and picks ports from 20000–60000, distinct.
- [ ] **Step 7:** Run `uv run pytest -v`. Expected: PASS.
- [ ] **Step 8:** Commit with `feat: AWG key/param generator and filter plugin`.

### Task 3: `common` role (base host setup and image)

**Files:**
- Create:
  - role: `roles/common/{defaults/main.yml,tasks/main.yml,handlers/main.yml}`;
  - firewall: `roles/common/files/multihop-input-fw`,
    `roles/common/templates/multihop-input-fw.service.j2`;
  - env and test: `roles/common/templates/multihop.env.j2`,
    `tests/bats/input_fw.bats`.

**Interfaces:**
- Produces:
  - On each host:
    - `docker.io`, `python3-docker`, `ipset`, `curl`, `jq` and `dnsutils`
      are installed;
    - sysctls are set: `net.ipv4.ip_forward=1`,
      `net.ipv4.conf.all.src_valid_mark=1`,
      `net.ipv6.conf.all.forwarding=0`;
    - the image `multihop/awg-base:pinned` exists, pulled from
      `amneziavpn/amneziawg-go@{{ awg_base_image_digest }}` and re-tagged.
  - `/etc/multihop/multihop.env` is a shell env file. Common keys:
    `PUBLIC_IFACE`, `SSH_PORT`, `INPUT_UDP_PORTS`, and `INPUT_TCP_PORTS`
    (from var `extra_input_tcp_ports`, default `[]`; the integration test
    uses it for MinIO). Later roles append keys
    through `blockinfile` with distinct markers.
  - `multihop-input-fw up`:
    - manages chain `MULTIHOP-IN`, jumped from `INPUT`;
    - allows `lo`, ESTABLISHED/RELATED, TCP `SSH_PORT` and each UDP port in
      `INPUT_UDP_PORTS`;
    - drops other inbound traffic on `PUBLIC_IFACE`.
  - `multihop-input-fw.service` (oneshot, `RemainAfterExit`,
    `Before=network-online.target`).
- Facts: `public_iface` defaults to `ansible_default_ipv4.interface`.

- [ ] **Step 1: Failing bats tests** in `input_fw.bats`:
  - `up adds jump once`: run `up` twice and assert
    `iptables -C INPUT -j MULTIHOP-IN` is checked before any `-I`;
  - `up allows ssh port from env`;
  - `up allows each INPUT_UDP_PORTS entry`;
  - `final rule drops on PUBLIC_IFACE only`.
- [ ] **Step 2:** Run `bats tests/bats/input_fw.bats`. Expected: FAIL.
- [ ] **Step 3:** Implement `multihop-input-fw`:
  - bash, `set -euo pipefail`;
  - sources `$MULTIHOP_ENV`;
  - `up` flushes or creates `MULTIHOP-IN` and re-adds the rules;
  - `down` removes the jump.
- [ ] **Step 4:** Run bats and shellcheck. Expected: PASS.
- [ ] **Step 5:** Write the role tasks (apt, sysctl via `ansible.posix.sysctl`
  in `/etc/sysctl.d/90-multihop.conf`, docker service enabled, image
  pull+tag via `community.docker.docker_image` / `docker_image_tag`, env
  file, script to `/usr/local/sbin/`, unit, enable+start).
- [ ] **Step 6:** Run `make lint`. Expected: PASS.
- [ ] **Step 7:** Commit with `feat: common role with base packages, sysctl, pinned image, input firewall`.

### Task 4: Render-test harness

**Files:**
- Create: `tests/render/render.yml`, `tests/render/fixture_vars.yml`, `tests/test_render.py`

**Interfaces:**
- Produces:
  - `tests/render/render.yml`, a localhost play that loads
    `fixture_vars.yml` (fixed keys and params) and renders each template
    passed as `-e render_list=[{src: <role>/templates/x.j2, dest: name}]`
    into `tests/render/out/<dest>`;
  - the pytest helper `render(src, dest, extra_vars=None) -> str` in
    `tests/test_render.py`, which runs `ansible-playbook` via subprocess and
    returns the file text.
- [ ] **Step 1:** Write the harness, plus a trivial template test
  rendering `roles/common/templates/multihop.env.j2`. Assert it contains
  `PUBLIC_IFACE=eth0` with fixture `public_iface: eth0`.
- [ ] **Step 2:** Run `uv run pytest tests/test_render.py -v`. Expected: PASS.
- [ ] **Step 3:** Commit with `test: template render harness`.

### Task 5: `exit` role

**Files:**
- Create:
  - role: `roles/exit/{defaults,tasks,handlers}/main.yml`;
  - templates: `roles/exit/templates/awg-exit.conf.j2`,
    `roles/exit/templates/exit-start.sh.j2`;
  - scripts and test: `roles/exit/files/multihop-exit-net`,
    `tests/bats/exit_net.bats`.
- Modify: `tests/test_render.py`

**Interfaces:**
- Consumes: the `awg_params_lines` filter (Task 2); `multihop/awg-base:pinned`
  and env file (Task 3).
- Produces:
  - Container `multihop-exit` (`--network host`, `NET_ADMIN`,
    `/dev/net/tun`, `restart: always`). It mounts
    `/var/lib/multihop/exit/awg-exit.conf` and `exit-start.sh` read-only.
    The entrypoint is `dumb-init`, or `sh` if the image lacks it; check
    with `docker run --rm --entrypoint which`. The start script runs
    `awg-quick up /etc/amnezia/awg-exit.conf` and then `tail -f /dev/null`.
  - `multihop-exit-net up`, which reads `UPLINK_SUBNET` and `PUBLIC_IFACE`:
    - chain `MULTIHOP-FWD` is jumped from `DOCKER-USER`;
    - it accepts `-i awg-exit -o $PUBLIC_IFACE`, plus ESTABLISHED/RELATED
      back;
    - it masquerades with `nat POSTROUTING -s $UPLINK_SUBNET -o $PUBLIC_IFACE -j MASQUERADE`;
    - it clamps MSS on `-i awg-exit` and `-o awg-exit`.
  - `multihop-net.service` (oneshot, `After=docker.service`,
    `PartOf=docker.service`, `WantedBy=multi-user.target`).
  - `INPUT_UDP_PORTS` gets `exit_awg_port` added.

- [ ] **Step 1: Failing render tests**: `test_exit_conf`.
  - `[Interface]` has `PrivateKey = <fixture exit priv>`,
    `Address = 10.9.0.1/30`, `ListenPort = <exit_awg_port>`, `Table = off`
    and `MTU = 1280`.
  - The AWG params lines appear with I lines commented.
  - There is exactly one `[Peer]`, with
    `PublicKey = <fixture uplink entry pub>`, `PresharedKey`,
    `AllowedIPs = 10.9.0.2/32` and no `Endpoint`.
- [ ] **Step 2: Failing bats** in `exit_net.bats`:
  - `masquerade only uplink subnet`;
  - `forward rules in DOCKER-USER via MULTIHOP-FWD`;
  - `up is idempotent`: on a second run, `-C` checks precede inserts and
    the chain is flushed rather than duplicated.
- [ ] **Step 3:** Run both. Expected: FAIL.
- [ ] **Step 4:** Implement the templates, script and role tasks. Restart
  the container on config change via a handler that uses
  `community.docker.docker_container` `restart: true`.
- [ ] **Step 5:** Run `make test lint`. Expected: PASS.
- [ ] **Step 6:** Commit with `feat: exit role`.

### Task 6: `entry_app` role (app-compatible `amnezia-awg2`)

**Files:**
- Create:
  - role: `roles/entry_app/{defaults,tasks,handlers}/main.yml`,
    `roles/entry_app/tasks/restore.yml`;
  - vendored app files: `roles/entry_app/files/Dockerfile`, a copy of
    `server_scripts/awg/Dockerfile` with a top comment stating the source
    commit, `FROM multihop/awg-base:pinned`, and `COPY start.sh /opt/amnezia/start.sh`;
  - templates: `roles/entry_app/templates/start.sh.j2` (the app's
    `start.sh` with the vars substituted) and
    `roles/entry_app/templates/awg0.conf.j2`.
- Modify: `tests/test_render.py`

**Interfaces:**
- Consumes: `vault_entry_awg`, `entry_awg_subnet`, `entry_awg_port`, the filter (Task 2).
- Produces:
  - Host directory `/var/lib/multihop/entry-awg/`, mode 0700, bind-mounted
    at `/opt/amnezia/awg`.
  - Network `amnezia-dns-net`.
  - Image and container `amnezia-awg2`, run with the app's flags:
    - `-p {{ entry_awg_port }}:{{ entry_awg_port }}/udp`;
    - `--privileged`, `NET_ADMIN` and `SYS_MODULE`;
    - `-v /lib/modules:/lib/modules`;
    - `src_valid_mark=1`, `log_driver: none`, `restart: always`;
    - networks: default bridge first, then `amnezia-dns-net`.
  - The variable `entry_restore_archive` (a path to a decrypted tarball on
    the controller). When set, `tasks/restore.yml` stops the container,
    replaces the directory contents and starts it again.
  - The tag `entry_app_drift_check`, which asserts that `docker inspect
    amnezia-awg2` includes a mount with destination `/opt/amnezia/awg`.
    When it doesn't, it fails with a message naming `restore.yml`.

- [ ] **Step 1: Failing render tests:**
  - `test_awg0_conf_matches_app_layout`:
    - lines are `PrivateKey`, `Address = 10.8.1.1/24`,
      `ListenPort = <port>`, then the params;
    - I lines are commented;
    - there is no `[Peer]` section;
    - the format is ` = ` with spaces (the app splits on `" = "`).
  - `test_start_sh_substitutes_subnet`: the rendered `start.sh` contains
    `-s 10.8.1.0/24 -o eth0 -j MASQUERADE` and no `$AWG_SUBNET_IP`.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement the templates and role.
  - Seed the files with `stat` on `awg0.conf` first, and write the seed
    files only `when: not stat.exists`:
    - `awg0.conf`;
    - `wireguard_server_private_key.key`, `wireguard_server_public_key.key`
      and `wireguard_psk.key`, each holding the key plus a newline;
    - no `clientsTable`.
  - Build the image with `community.docker.docker_image` (`source: build`,
    path to a staged directory that contains the Dockerfile and rendered
    `start.sh`).
  - Run the drift check at the end of `main.yml`, and in a pre-task when the
    container already exists.
- [ ] **Step 4: Idempotency test (Review Focus 1)**: add
  `tests/test_entry_app_idempotency.py`. It runs the role's seed tasks
  twice against a temp directory, using `ansible-playbook` on localhost
  with `entry_state_dir` overridden. Between runs it appends a fake
  `[Peer]` to `awg0.conf` and writes `clientsTable`, then asserts both
  survive the second run byte-for-byte. This requires a variable
  `entry_state_dir` (default `/var/lib/multihop/entry-awg`) and a tag
  `entry_app_seed` isolating the seed tasks.
- [ ] **Step 5:** Run `make test lint`. Expected: PASS.
- [ ] **Step 6:** Commit with `feat: entry_app role with app-compatible amnezia-awg2 and bind-mounted state`.

### Task 7: `entry_uplink` role (uplink, routing, fail-closed, re-resolve)

**Files:**
- Create:
  - role: `roles/entry_uplink/{defaults,tasks,handlers}/main.yml`;
  - templates: `roles/entry_uplink/templates/awg-uplink.conf.j2`,
    `uplink-start.sh.j2`, `multihop-net.service.j2`,
    `multihop-reresolve.{service,timer}.j2`;
  - scripts: `roles/entry_uplink/files/multihop-entry-net`,
    `roles/entry_uplink/files/multihop-reresolve`;
  - tests: `tests/bats/entry_net.bats`, `tests/bats/reresolve.bats`.
- Modify: `tests/test_render.py`

**Interfaces:**
- Consumes: `vault_link_awg`, `vault_uplink_entry`, `exit_domain`, `exit_awg_port`, `uplink_mtu`, env file.
- Produces:
  - Container `multihop-uplink`, the same shape as `multihop-exit`. The
    config has:
    - `Address = 10.9.0.2/30`, `Table = off`, `MTU = {{ uplink_mtu }}`;
    - AWG params with I lines **uncommented** (client side);
    - `PostUp = ip route replace default dev %i table 51820 metric 1`;
    - a `[Peer]` with the exit pubkey, PSK, `AllowedIPs = 0.0.0.0/0`,
      `Endpoint = {{ exit_domain }}:{{ exit_awg_port }}` and
      `PersistentKeepalive = 25`.
  - `multihop-entry-net up|down` (env keys `PUBLIC_IFACE`,
    `ENTRY_AWG_PORT`, `BRIDGES="docker0 amn0"`):
    - `/etc/iproute2/rt_tables.d/multihop.conf` contains `51820 multihop`;
    - table 51820 has `blackhole default metric 4096`;
    - `ip rule` priorities 10100–10130 as in the Global Constraints. The
      10110 rule is `fwmark 0x5b00/0xff00 lookup main`;
    - mangle `MULTIHOP-MARK`, jumped from PREROUTING for each bridge:
      `-p udp --sport $ENTRY_AWG_PORT` → MARK `0x5b00/0xff00` (AWG server
      traffic, both directions), then `force_exit` set → RETURN, then
      `direct` set → MARK `0x5a/0xff`. Both ipsets are created empty if
      missing (`hash:net`). This relies on the `amnezia-awg2` start.sh
      (Task 6) masquerading user UDP into a port range that excludes
      `entry_awg_port`;
    - filter `MULTIHOP-FWD`, jumped from `DOCKER-USER`, per bridge:
      - `-i br -o PUBLIC_IFACE -m mark --mark 0x5a/0xff -j RETURN`;
      - `-i br -o PUBLIC_IFACE -p udp --sport ENTRY_AWG_PORT -j RETURN`;
      - `-i br -o PUBLIC_IFACE -j DROP`;
    - nat `-o awg-uplink -j MASQUERADE`;
    - mangle FORWARD TCPMSS clamp `-o awg-uplink`;
    - ip6tables: `FORWARD -i <br> -j DROP`, guarded with `|| true` if
      ip6tables is absent;
    - re-running `up` converges to exactly the same rule set.
  - `multihop-net.service` (`After=docker.service`,
    `PartOf=docker.service`, `Before=` nothing, `WantedBy=multi-user.target`),
    plus a drop-in on `docker.service`
    (`Wants=multihop-net.service`) so the rules come back after a Docker
    restart.
  - `multihop-reresolve`:
    - resolves `EXIT_DOMAIN` with `getent ahostsv4 | awk 'NR==1{print $1}'`;
    - if the result is empty, it logs and exits 0 without changing the
      endpoint;
    - reads the current endpoint with `docker exec multihop-uplink awg show awg-uplink endpoints`;
    - when it differs, runs
      `awg set awg-uplink peer <EXIT_PUBKEY> endpoint <ip>:<EXIT_PORT>`.
  - Timer: `OnUnitActiveSec=1min`.

- [ ] **Step 1: Failing bats** in `entry_net.bats`:
  - `rules have priorities 10100..10130 for both bridges`;
  - `blackhole default in table 51820`;
  - `drop bridge->public is last in MULTIHOP-FWD`;
  - `direct mark and awg reply are allowed before drop`;
  - `force_exit RETURN precedes direct MARK`;
  - `up twice yields no duplicate ip rules`: the stubbed `ip rule show`
    returns the first run's rules, and the test asserts `ip rule del` is
    called for priorities 10100–10130 before `add`.
- [ ] **Step 2: Failing bats** in `reresolve.bats`:
  - `updates endpoint when DNS changed`;
  - `no-op when same`;
  - `empty resolution keeps endpoint` (Review Focus 3): no `awg set` call;
  - `getent failure keeps endpoint`: no `awg set` call, exit 0.
- [ ] **Step 3: Failing render test** `test_uplink_conf` asserts the
  values listed above, including `Table = off` and uncommented `I1 =`.
- [ ] **Step 4:** Run. Expected: FAIL.
- [ ] **Step 5:** Implement the scripts, templates, units and role tasks.
- [ ] **Step 6:** Run `make test lint`. Expected: PASS.
- [ ] **Step 7:** Commit with `feat: entry uplink with policy routing, fail-closed firewall, exit re-resolve`.

### Task 8: `split_routing` role

**Files:**
- Create:
  - role: `roles/split_routing/{defaults,tasks}/main.yml`;
  - script and units: `roles/split_routing/files/multihop-split-refresh`,
    `roles/split_routing/templates/multihop-split-refresh.{service,timer}.j2`;
  - config: `roles/split_routing/templates/split.conf.j2`;
  - test: `tests/bats/split_refresh.bats`.

**Interfaces:**
- Consumes: the ipsets created by `multihop-entry-net` (Task 7); the
  `split_*` vars.
- Produces:
  - `/etc/multihop/split.conf` with the sections `COUNTRIES=`, `URL=`,
    `DIRECT_CIDRS=`, `DIRECT_DOMAINS=` and `FORCE_EXIT_CIDRS=`.
  - The script `multihop-split-refresh [--force-countries]`:
    - Country lists are cached in `$STATE/split/<cc>.zone`. They are
      re-downloaded when older than 24h or when forced. A download counts
      as valid only if it has at least 1 line and every non-empty line
      matches a CIDR or IPv4 regex; otherwise the cache is kept.
    - It builds `multihop_direct_new` from the cached zones, the direct
      CIDRs and the resolved A records of the direct domains, then runs
      `ipset swap multihop_direct_new multihop_direct` and destroys the
      temp set.
    - It rebuilds `multihop_force_exit` the same way.
    - When `split_routing_enabled` is false, the role installs nothing and
      flushes both sets.
  - Timer: `OnBootSec=30s`, `OnUnitActiveSec=10min`.

- [ ] **Step 1: Failing bats:**
  - `valid download replaces cache`;
  - `html error page keeps previous cache` (Review Focus 4);
  - `empty body keeps previous cache`;
  - `curl failure keeps previous cache`;
  - `first run with failed download builds set from static cidrs only`
    (never empty because of a failure, never `0.0.0.0/0`);
  - `0.0.0.0/0 in any input is rejected`;
  - `swap is used, not flush` (asserts `ipset swap` is called and no
    `ipset flush multihop_direct`);
  - `cache fresher than 24h is not re-downloaded`.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement the script and role.
- [ ] **Step 4:** Run `make test lint`. Expected: PASS.
- [ ] **Step 5:** Commit with `feat: server-side split routing`.

### Task 9: `backup` role

**Files:**
- Create:
  - role: `roles/backup/{defaults,tasks}/main.yml`;
  - script: `roles/backup/files/multihop-backup`;
  - templates: `roles/backup/templates/multihop-backup.{service,timer}.j2`,
    `roles/backup/templates/aws-credentials.j2`;
  - test: `tests/bats/backup.bats`.

**Interfaces:**
- Consumes: `vault_backup_writer`, `backup_*` vars, `entry_state_dir`.
- Produces:
  - `age` installed from apt, plus AWS CLI v2 from the official zip.
    `ansible_architecture` selects `x86_64` or `aarch64`, and the install is
    skipped if `aws --version` already reports `aws-cli/2`.
  - Credentials in `/etc/multihop/aws/credentials`, mode 0600, profile
    `multihop-backup`.
  - `multihop-backup`, with exit codes 0 = uploaded or unchanged, 2 = drift,
    1 = other error:
    1. **Drift check:** `docker inspect amnezia-awg2` must contain a mount
       to `/opt/amnezia/awg`. Otherwise it writes `$STATE/backup/DRIFT`,
       logs `ERROR: amnezia-awg2 lost its bind mount (app reinstall?) — see README "Recovery"`
       and exits 2.
    2. **Deterministic archive:** `tar --sort=name --mtime=@0 --owner=0
       --group=0 --numeric-owner -C $ENTRY_STATE_DIR -cf - .`, then
       sha256.
    3. **Unchanged:** if the hash equals `$STATE/backup/last.sha256`, exit
       0 with no upload.
    4. **Upload:** `age -r $AGE_RECIPIENT`, then
       `aws --profile multihop-backup --endpoint-url $S3_ENDPOINT s3 cp - s3://$BUCKET/$PREFIX/entry-<UTC %Y%m%dT%H%M%SZ>-<hash12>.tar.age`,
       then upload the object key text to `s3://$BUCKET/$PREFIX/latest`,
       then write the hash file.
    5. **Force:** `--force` skips the unchanged check.
  - Timer: `OnUnitActiveSec={{ backup_interval }}` and `OnBootSec=2min`.
  - The role also runs a one-shot, best-effort check:
    `aws s3api get-bucket-versioning`. If the result is not `Enabled`, it
    warns (debug message) and doesn't fail.

- [ ] **Step 1: Failing bats:**
  - `missing bind mount exits 2 and writes DRIFT` (Review Focus 5);
  - `unchanged state does not upload`;
  - `changed state uploads encrypted object and latest pointer`;
  - `--force uploads even if unchanged`;
  - `upload failure exits 1 and does not update last.sha256`;
  - `archive is deterministic`: two runs on the same directory produce
    the same hash (uses real `tar`).
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement the script and role.
- [ ] **Step 4:** Run `make test lint`. Expected: PASS.
- [ ] **Step 5:** Commit with `feat: encrypted change-only S3 backups with drift detection`.

### Task 10: Restore path and `dns_update` role

**Files:**
- Create:
  - restore: `playbooks/tasks/fetch-backup.yml`;
  - DNS role: `roles/dns_update/{defaults,tasks}/main.yml`,
    `roles/dns_update/tasks/backend_manual.yml`;
  - test: `tests/test_fetch_backup.py`.

**Interfaces:**
- Consumes: `vault_backup_reader`, `vault_backup_age_identity`, `backup_*`
  vars, `entry_restore_archive` (Task 6).
- Produces:
  - `playbooks/tasks/fetch-backup.yml`, which runs on localhost with input
    `backup_object` (optional; default is the content of `latest`):
    1. Download into a `tempfile` directory with `aws s3 cp` (reader
       credentials passed via environment, never written to disk).
    2. Decrypt with `age -d -i <(identity)`, writing the identity to a
       0600 temp file that is deleted in `always:`.
    3. Validate that the archive contains `./awg0.conf` and
       `./wireguard_server_private_key.key`.
    4. Set the fact `entry_restore_archive`.
    5. Warn if the archive's server private key differs from
       `vault_entry_awg.private_key` (backup wins).
  - `dns_update`, with inputs `dns_record` (fqdn) and `dns_ip`:
    1. Include `backend_{{ dns_backend }}.yml`. The manual backend calls
       `pause` with the prompt
       `Point {{ dns_record }} A record to {{ dns_ip }} (TTL 60-300), then press Enter`.
    2. Poll `dig +short {{ dns_record }} @1.1.1.1` and `@8.8.8.8` from the
       controller until both return `dns_ip`. That's 60 retries, 10 seconds
       apart.
- [ ] **Step 1: Failing test** in `tests/test_fetch_backup.py`. It
  generates an age identity with `age-keygen`, builds a tarball like the
  backup script's, encrypts it, and puts it in a local directory.
  `fetch-backup.yml` is run with `backup_fetch_source=local:<dir>`, a test
  seam that skips S3. The test asserts that `entry_restore_archive` exists
  and contains `awg0.conf`, and that a tarball without `awg0.conf` fails
  validation.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement both.
- [ ] **Step 4:** Run `make test lint`. Expected: PASS.
- [ ] **Step 5:** Commit with `feat: backup fetch/decrypt/validate and pluggable DNS step`.

### Task 11: Playbooks

**Files:**
- Create:
  - deploy: `playbooks/site.yml`, `playbooks/exit.yml`,
    `playbooks/entry.yml`;
  - backup and restore: `playbooks/backup.yml`, `playbooks/restore.yml`;
  - swaps: `playbooks/swap-exit.yml`, `playbooks/swap-entry.yml`;
  - checks: `playbooks/verify.yml`, `playbooks/tasks/verify-entry.yml`;
  - test: `tests/test_playbooks.py`.

**Interfaces:**
- Consumes: all roles; `fetch-backup.yml`; `dns_update`.
- Produces:
  - Deploy playbooks:
    - `exit.yml`: `hosts: exit`, roles `common` and `exit`.
    - `entry.yml`: `hosts: entry`, roles `common`, `entry_app`,
      `entry_uplink`, `split_routing` and `backup`.
    - `site.yml`: imports `exit.yml`, then `entry.yml`, then `verify.yml`.
  - Backup and restore playbooks:
    - `backup.yml`: runs `multihop-backup --force` on `entry`.
    - `restore.yml`:
      1. Asks for confirmation with `pause`, unless `-e confirm=yes`.
      2. Runs `fetch-backup.yml` on localhost.
      3. Applies `entry_app` with `entry_restore_archive` on `entry`.
  - `swap-exit.yml`:
    1. Runs `exit.yml` on the new `exit` host.
    2. Runs `dns_update` (`exit_domain` → the new exit's
       `ansible_host`).
    3. On `entry`, waits up to 5 minutes until
       `docker exec multihop-uplink awg show awg-uplink latest-handshakes`
       is less than 180 seconds old.
    4. Runs `verify-entry.yml`.
    5. Optionally stops `multihop-exit` on `exit_old` when
       `-e stop_old=yes`.
  - `swap-entry.yml`:
    1. **Probe** `entry_old` with `wait_for_connection timeout=20` and
       `ignore_unreachable`. Set `old_entry_reachable`.
    2. **If reachable:** run `multihop-backup --force` on `entry_old`, then
       stop and disable `amnezia-awg2`, `multihop-uplink` and the backup
       timer there.
    3. **If unreachable:**
       1. On localhost, run `scripts/gen-secrets.py uplink-key` and
          `ansible-vault encrypt --output
          inventories/<inv>/group_vars/all/vault_uplink.yml`.
       2. Use `include_vars` on the new file.
       3. Run the `exit` role on `exit`.
       4. Print `Users added on the old entry after its last backup are lost`.
    4. Run `fetch-backup.yml`.
    5. Run `entry.yml` with `entry_restore_archive`.
    6. Run `dns_update` for `entry_domain`.
    7. Run `verify-entry.yml`.
  - `verify.yml` / `tasks/verify-entry.yml`:
    - Check the handshake is less than 180 seconds old.
    - Read the exit's tunnel bytes, run
      `docker exec amnezia-awg2 curl -4 -s --max-time 10 https://api.ipify.org`,
      read the bytes again, and assert they increased.
    - If `verify_compare_ips` (default true), assert the curl output equals
      the exit's public IPv4 (`ansible_default_ipv4.address` of `exit`).
    - **Fail-closed check:** runs when `verify_fail_closed`
      (default false; also tagged `fail_closed`):
      1. Stop `multihop-uplink`.
      2. Assert the same curl fails (rc ≠ 0).
      3. Start the container again in an `always:` block.
- Not built: `rekey-entry.yml` (spec §7.5 marks it optional and deferrable).
  The README tells the owner how to rekey by hand: edit vault params, then
  delete `/var/lib/multihop/entry-awg/awg0.conf` and re-run `entry.yml`.

- [ ] **Step 1: Failing test:**
  `tests/test_playbooks.py::test_syntax_all` runs
  `ansible-playbook --syntax-check` on every `playbooks/*.yml` with the
  example inventory and a dummy vault. Generate the dummy vault in a
  fixture with `gen-secrets.py all` and leave it unencrypted under
  `tests/fixtures/`.
- [ ] **Step 2:** Run. Expected: FAIL (playbooks missing).
- [ ] **Step 3:** Implement the playbooks.
- [ ] **Step 4:** Run `make test lint`. Expected: PASS.
- [ ] **Step 5:** Commit with `feat: deploy, swap, backup, restore and verify playbooks`.

### Task 12: README

**Files:**
- Create: `README.md`, `inventories/example/group_vars/all/vault.yml.example`

- [ ] **Step 1:** Write the README with these sections:
  1. **What this is:** include the diagram from spec §7.
  2. **Requirements:** controller tools, plus the S3 bucket with
     versioning on and its credentials.
  3. **First deploy:**
     1. Copy the inventory.
     2. Run `uv run scripts/gen-secrets.py all > vault.yml`, fill in the S3
        and age fields, then run `ansible-vault encrypt`. Do the same for
        `uplink-key`.
     3. Create the DNS records.
     4. Run `make collections`.
     5. Run `uv run ansible-playbook playbooks/site.yml`.
  4. **Adding the server in the Amnezia app:** use the domain and SSH user
     with sudo; the app detects AmneziaWG as already installed.
  5. **Do not change AmneziaWG settings in the app:** explain why (spec
     §6) and what the detection looks like.
  6. **Recovery:** `restore.yml`.
  7. **Swap exit.**
  8. **Swap entry:** both the reachable and unreachable cases.
  9. **Restore an older backup** (`-e backup_object=...`).
  10. **Split routing variables.**
  11. **Adding a DNS backend:** one task file `backend_<name>.yml` with
      inputs `dns_record` and `dns_ip`.
  12. **Updating the pinned image:** how to get a new digest, using
      `curl -s https://hub.docker.com/v2/repositories/amneziavpn/amneziawg-go/tags/latest | jq -r .digest`.
  13. **Troubleshooting:** the `awg show` commands, `ip rule`, and
      `journalctl -u multihop-*`.
- [ ] **Step 2:** Run `make lint`. Expected: PASS.
- [ ] **Step 3:** Commit with `docs: README`.

### Task 13: Integration test on two Multipass VMs

**Files:**
- Create: `tests/integration/run.sh`, `inventories/multipass/hosts.yml`, `inventories/multipass/group_vars/all/vars.yml`

**Interfaces:**
- Produces: `tests/integration/run.sh up|deploy|check|down`.
  - `up` launches `mh-entry` and `mh-exit` (Ubuntu 24.04, 2 GB RAM) and
    injects the SSH key through cloud-init. It writes `hosts.yml` with the
    VM IPs and sets `exit_domain` to `<exit-ip>.sslip.io` and
    `verify_compare_ips: false` (both VMs share the Mac's public IP).
  - In the test inventory, `split_direct_domains: [ifconfig.me]`.
  - S3 points at a MinIO container started on the `mh-exit` VM by `run.sh`,
    with a versioned bucket.

- [ ] **Step 1:** Resolve the real image digest with the README command.
  Put it in both inventories' `awg_base_image_digest`.
- [ ] **Step 2:** Run `run.sh up && run.sh deploy`.
  Expected: `site.yml` completes and `verify.yml` passes.
- [ ] **Step 3:** Run `run.sh check`. The script asserts each step and
  prints PASS/FAIL per line:
  1. Re-run `entry.yml`. Expected: `changed=0` for the seed tasks.
  2. Add a fake peer with
     `docker exec amnezia-awg2 awg set awg0 peer <pub> allowed-ips 10.8.1.2/32`.
     Append it to `awg0.conf` and `clientsTable` the way the app does
     (`echo` to the file), then re-run `entry.yml`. Expected: the peer is
     still in the file (Review Focus 1).
  3. Run `verify.yml -e verify_fail_closed=true`. Expected: PASS.
  4. Run `systemctl restart docker` on `mh-entry`, then `verify.yml`.
     Expected: PASS.
  5. Run `multipass restart mh-entry`, then
     `verify.yml -e verify_fail_closed=true`. Expected: PASS (Review
     Focus 2).
  6. `docker exec amnezia-awg2 curl -s ifconfig.me` uses the direct path:
     the `MULTIHOP-FWD` direct RETURN counter increases.
  7. Run `backup.yml`. Expected: an object exists in MinIO. Run backup
     again with no change. Expected: no new object.
  8. **Drift test:**
     1. Recreate `amnezia-awg2` without the mount by hand.
     2. Run `systemctl start multihop-backup`. Expected: exit 2.
     3. Run `entry.yml`. Expected: it fails, naming `restore.yml`.
     4. Run `restore.yml -e confirm=yes`. Expected: the fake peer is back
        and `verify.yml` passes (Review Focus 5).
  9. Run the swap-exit simulation: launch `mh-exit2`, point `exit` at
     it and `exit_old` at `mh-exit`, change the sslip name, then run
     `swap-exit.yml` with `dns_backend: manual` (press Enter). Expected:
     the handshake comes back without any task running on `mh-entry`
     except the verify tasks.
- [ ] **Step 4:** If an assertion fails, fix it in the owning task's files,
  add a regression test there, and re-run.
- [ ] **Step 5:** Run `run.sh down`. Commit with `test: multipass integration harness`.
- [ ] **Step 6: Manual acceptance (owner)** on real servers:
  1. Add the server in the Amnezia app by domain. AmneziaWG shows
     "(version 3.1)".
  2. Add a user and connect from a phone. The external IP shows as the
     exit, and a domestic site goes out with the entry's IP.
  3. Revoke the user in the app. The phone stops working.
