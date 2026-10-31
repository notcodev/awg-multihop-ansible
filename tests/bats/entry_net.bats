load helpers

# Stateful fakes: iptables keeps one file per table.chain (rules as lines),
# ip keeps the rule list and table 51820 routes. Tests assert the end state.
setup() {
  export MULTIHOP_ENV="$BATS_TEST_TMPDIR/multihop.env"
  export MULTIHOP_RT_TABLES_DIR="$BATS_TEST_TMPDIR/rt_tables.d"
  export STUB_LOG="$BATS_TEST_TMPDIR/stub.log"
  export IPT_DIR="$BATS_TEST_TMPDIR/ipt"
  export IP_DIR="$BATS_TEST_TMPDIR/ip"
  export IPT_GUARD="$BATS_TEST_TMPDIR/ipt_guard"
  cat > "$MULTIHOP_ENV" <<'ENV'
PUBLIC_IFACE=eth9
SSH_PORT=22
ENTRY_AWG_PORT=51470
BRIDGES="docker0 amn0"
ENV
  mkdir -p "$BATS_TEST_TMPDIR/bin" "$IPT_DIR" "$IP_DIR"
  # Built-in chains only: Docker is not running yet, DOCKER-USER is absent.
  touch "$IPT_DIR/filter.FORWARD" "$IPT_DIR/nat.POSTROUTING" \
        "$IPT_DIR/mangle.FORWARD" "$IPT_DIR/mangle.PREROUTING"
  cat > "$BATS_TEST_TMPDIR/bin/iptables" <<'STUB'
#!/bin/sh
echo "iptables $*" >> "$STUB_LOG"
d="$IPT_DIR"; t=filter
[ "$1" = -t ] && { t="$2"; shift 2; }
op="$1"; shift
f() { echo "$d/$t.$1"; }
case "$op" in
  -N) [ ! -f "$(f "$1")" ] || exit 1; : > "$(f "$1")" ;;
  -L) [ -f "$(f "$1")" ] ;;
  -F) [ -f "$(f "$1")" ] || exit 1; : > "$(f "$1")" ;;
  -X) [ -f "$(f "$1")" ] || exit 1
      ! cat "$d/$t".* | grep -q -E -e "(^| )-j $1\$" || exit 1; rm "$(f "$1")" ;;
  -E) [ -f "$(f "$1")" ] || exit 1; mv "$(f "$1")" "$(f "$2")"
      for x in "$d/$t".*; do sed -E "s/(^| )-j $1\$/\1-j $2/" "$x" > "$x.t"; mv "$x.t" "$x"; done ;;
  -S) [ -f "$(f "$1")" ] || exit 1; echo "-N $1"; sed "s/^/-A $1 /" "$(f "$1")" ;;
  -A) c="$1"; shift; [ -f "$(f "$c")" ] || exit 1; echo "$*" >> "$(f "$c")" ;;
  -I) c="$1"; shift; [ -f "$(f "$c")" ] || exit 1
      { echo "$*"; cat "$(f "$c")"; } > "$(f "$c").t"; mv "$(f "$c").t" "$(f "$c")" ;;
  -C) c="$1"; shift; [ -f "$(f "$c")" ] && grep -qxF -e "$*" "$(f "$c")" ;;
  -D) c="$1"; shift; grep -qxF -e "$*" "$(f "$c")" || exit 1
      awk -v t="$*" '$0==t && !done {done=1; next} {print}' "$(f "$c")" > "$(f "$c").t"; mv "$(f "$c").t" "$(f "$c")" ;;
  *) exit 9 ;;
esac
rc=$?
# Guard: when $IPT_GUARD lists bridges, every filter -D/-F/-X must leave
# DOCKER-USER jumping to a chain that drops each bridge -> eth9.
if [ "$t" = filter ] && [ -f "$IPT_GUARD" ]; then
  case "$op" in -D|-F|-X)
    ok=
    for j in $(sed -n 's/^-j //p' "$d/filter.DOCKER-USER"); do
      all=1
      for br in $(cat "$IPT_GUARD"); do
        grep -qxF -e "-i $br -o eth9 -j DROP" "$d/filter.$j" 2>/dev/null || all=
      done
      [ -n "$all" ] && ok=1
    done
    [ -n "$ok" ] || echo "iptables -t filter $op $* left DOCKER-USER without backstop" >> "$IPT_GUARD.violations"
  esac
fi
exit $rc
STUB
  # Fake ip. When $IP_DIR/guard lists bridges, every rule deletion checks that
  # each of them still has a rule into table 51820 (no fall-through to main).
  cat > "$BATS_TEST_TMPDIR/bin/ip" <<'STUB'
#!/bin/sh
echo "ip $*" >> "$STUB_LOG"
d="$IP_DIR"; touch "$d/rules" "$d/routes"
case "$1 $2" in
  "rule add")
    shift 2; [ "$1" = pref ] || exit 9
    line="$2"; shift 2; line="$line $*"
    if grep -qxF -e "$line" "$d/rules"; then echo "RTNETLINK answers: File exists" >&2; exit 2; fi
    echo "$line" >> "$d/rules" ;;
  "rule del")
    shift 2; { [ "$1" = pref ] && [ $# -eq 2 ]; } || exit 9
    grep -q "^$2 " "$d/rules" || { echo "RTNETLINK answers: No such file or directory" >&2; exit 2; }
    awk -v p="$2" '$1==p && !done {done=1; next} {print}' "$d/rules" > "$d/rules.t"; mv "$d/rules.t" "$d/rules"
    if [ -f "$d/guard" ]; then
      for br in $(cat "$d/guard"); do
        grep -q " iif $br lookup 51820\$" "$d/rules" || echo "ip rule del pref $2 left $br uncovered" >> "$d/violations"
      done
    fi ;;
  "route replace")
    shift 2; line="$*"
    { grep -vxF -e "$line" "$d/routes"; echo "$line"; } > "$d/routes.t"; mv "$d/routes.t" "$d/routes" ;;
  "route del")
    shift 2; line="$*"; grep -qxF -e "$line" "$d/routes" || exit 2
    grep -vxF -e "$line" "$d/routes" > "$d/routes.t"; mv "$d/routes.t" "$d/routes" ;;
  "link set")
    [ "$3 $5" = "dev group" ] || exit 9
    echo "$4 group $6" > "$d/link.$4" ;;
  *) exit 9 ;;
esac
STUB
  chmod +x "$BATS_TEST_TMPDIR/bin/iptables" "$BATS_TEST_TMPDIR/bin/ip"
  stub ipset
  stub ip6tables "" 1
  : > "$STUB_LOG"
}

# Line number of the first stub-log line matching the regex.
first_line() { grep -n -m1 -e "$1" "$STUB_LOG" | cut -d: -f1; }

expected_rules() {
  cat <<'R'
10100 fwmark 0x5a/0xff lookup main
10110 fwmark 0x5b00/0xff00 lookup main
10120 iif docker0 lookup main suppress_prefixlength 0 suppress_ifgroup 51820
10120 iif amn0 lookup main suppress_prefixlength 0 suppress_ifgroup 51820
10130 iif docker0 lookup 51820
10130 iif amn0 lookup 51820
R
}

expected_fwd() {
  cat <<'R'
-i docker0 -o eth9 -m mark --mark 0x5a/0xff -j RETURN
-i docker0 -o eth9 -p udp --sport 51470 -j RETURN
-i amn0 -o eth9 -m mark --mark 0x5a/0xff -j RETURN
-i amn0 -o eth9 -p udp --sport 51470 -j RETURN
-i docker0 -o eth9 -j DROP
-i amn0 -o eth9 -j DROP
R
}

# Snapshot of every iptables chain and the ip state, for convergence checks.
snapshot() {
  for x in "$IPT_DIR"/* "$IP_DIR/rules" "$IP_DIR/routes"; do
    echo "== ${x##*/}"; cat "$x"
  done
}

@test "rules have priorities 10100..10130 for both bridges" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  diff <(sort -s -n -k1,1 "$IP_DIR/rules") <(expected_rules)
}

# Providers install DHCP host routes (e.g. to their resolvers) via the public
# interface; bridge traffic must not take them (dropped by the backstop, so
# DNS from containers failed) but go through the uplink like the default route.
@test "bridge traffic never takes a main route via the public interface" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  [ "$(cat "$IP_DIR/link.eth9")" = "eth9 group 51820" ]
  grp=$(first_line '^ip link set dev eth9 group 51820$')
  r=$(first_line '^ip rule add pref 10120 .*suppress_ifgroup 51820$')
  [ -n "$grp" ] && [ -n "$r" ] && [ "$grp" -lt "$r" ]
}

@test "a missing public interface does not stop the rules" {
  cat > "$BATS_TEST_TMPDIR/bin/ip.real" < "$BATS_TEST_TMPDIR/bin/ip"
  cat > "$BATS_TEST_TMPDIR/bin/ip" <<STUB
#!/bin/sh
[ "\$1 \$2" = "link set" ] && { echo "ip \$*" >> "\$STUB_LOG"; echo 'Cannot find device "eth9"' >&2; exit 1; }
exec sh "$BATS_TEST_TMPDIR/bin/ip.real" "\$@"
STUB
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  diff <(sort -s -n -k1,1 "$IP_DIR/rules") <(expected_rules)
}

@test "blackhole default in table 51820" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  [ "$(cat "$IP_DIR/routes")" = "blackhole default metric 4096 table 51820" ]
  # the blackhole exists before any rule can send traffic to table 51820,
  # so an empty table never falls through to main
  bh=$(first_line '^ip route replace blackhole default metric 4096 table 51820$')
  r=$(first_line '^ip rule add .*lookup 51820$')
  [ -n "$bh" ] && [ -n "$r" ] && [ "$bh" -lt "$r" ]
}

@test "routing table name is registered" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  [ "$(cat "$MULTIHOP_RT_TABLES_DIR/multihop.conf")" = "51820 multihop" ]
}

@test "drop bridge->public is last in MULTIHOP-FWD" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  diff "$IPT_DIR/filter.MULTIHOP-FWD" <(expected_fwd)
  [ "$(tail -n1 "$IPT_DIR/filter.MULTIHOP-FWD")" = "-i amn0 -o eth9 -j DROP" ]
  [ "$(cat "$IPT_DIR/filter.DOCKER-USER")" = "-j MULTIHOP-FWD" ]
}

@test "direct mark and awg reply are allowed before drop" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  for br in docker0 amn0; do
    f="$IPT_DIR/filter.MULTIHOP-FWD"
    mark=$(grep -n -x -e "-i $br -o eth9 -m mark --mark 0x5a/0xff -j RETURN" "$f" | cut -d: -f1)
    reply=$(grep -n -x -e "-i $br -o eth9 -p udp --sport 51470 -j RETURN" "$f" | cut -d: -f1)
    drop=$(grep -n -x -e "-i $br -o eth9 -j DROP" "$f" | cut -d: -f1)
    [ -n "$mark" ] && [ -n "$reply" ] && [ -n "$drop" ]
    [ "$mark" -lt "$drop" ] && [ "$reply" -lt "$drop" ]
  done
  # nothing else is let through
  [ "$(grep -c -e '-j RETURN' "$IPT_DIR/filter.MULTIHOP-FWD")" -eq 4 ]
}

@test "force_exit RETURN precedes direct MARK" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  diff "$IPT_DIR/mangle.MULTIHOP-MARK" - <<'R'
-p udp --sport 51470 -j MARK --set-mark 0x5b00/0xff00
-m set --match-set multihop_force_exit dst -j RETURN
-m set --match-set multihop_direct dst -j MARK --set-mark 0x5a/0xff
R
  diff <(sort "$IPT_DIR/mangle.PREROUTING") - <<'R'
-i amn0 -j MULTIHOP-MARK
-i docker0 -j MULTIHOP-MARK
R
  # both sets exist (empty if new) before the rules reference them, and
  # creating them does not delay the backstop
  fwd=$(first_line '^iptables -t filter -I DOCKER-USER -j MULTIHOP-FWD-NEW$')
  for s in multihop_direct multihop_force_exit; do
    n=$(first_line "^ipset create $s hash:net -exist\$")
    [ -n "$n" ] && [ "$n" -lt "$(first_line '^iptables -t mangle -A MULTIHOP-MARK-NEW')" ]
    [ "$n" -gt "$fwd" ]
  done
}

@test "awg traffic is marked by source port and routed by the reply mark" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  # UDP from the AWG port gets the reply mark in both conntrack directions
  # (the app container keeps user UDP off that port, see entry_app start.sh)
  [ "$(head -n1 "$IPT_DIR/mangle.MULTIHOP-MARK")" = "-p udp --sport 51470 -j MARK --set-mark 0x5b00/0xff00" ]
  ! grep -q -e conntrack "$IPT_DIR/mangle.MULTIHOP-MARK" "$IPT_DIR/filter.MULTIHOP-FWD" || false
  # routing exception keys on that mark only
  grep -qx -e '10110 fwmark 0x5b00/0xff00 lookup main' "$IP_DIR/rules"
  ! grep -q -e 'sport\|ipproto' "$IP_DIR/rules" || false
  # backstop lets exactly that through, per bridge, to the public iface only
  [ "$(grep -c -e '--sport' "$IPT_DIR/filter.MULTIHOP-FWD")" -eq 2 ]
  grep -qx -e '-i docker0 -o eth9 -p udp --sport 51470 -j RETURN' "$IPT_DIR/filter.MULTIHOP-FWD"
  grep -qx -e '-i amn0 -o eth9 -p udp --sport 51470 -j RETURN' "$IPT_DIR/filter.MULTIHOP-FWD"
  # reply mark and direct mark use disjoint mask bytes
  ! grep -q -e '0x5b00/0xff ' "$IPT_DIR/mangle.MULTIHOP-MARK" || false
}

@test "nat and mss clamp on awg-uplink" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  [ "$(cat "$IPT_DIR/nat.MULTIHOP-NAT")" = "-o awg-uplink -j MASQUERADE" ]
  [ "$(cat "$IPT_DIR/nat.POSTROUTING")" = "-j MULTIHOP-NAT" ]
  [ "$(cat "$IPT_DIR/mangle.MULTIHOP-MSS")" = "-o awg-uplink -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu" ]
  [ "$(cat "$IPT_DIR/mangle.FORWARD")" = "-j MULTIHOP-MSS" ]
}

@test "DOCKER-USER is created and jumped to before docker runs" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  [ "$(cat "$IPT_DIR/filter.FORWARD")" = "-j DOCKER-USER" ]
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  [ "$(cat "$IPT_DIR/filter.FORWARD")" = "-j DOCKER-USER" ]
}

@test "existing DOCKER-USER rules and jump are kept" {
  echo "-j DOCKER-USER" > "$IPT_DIR/filter.FORWARD"
  echo "-j RETURN" > "$IPT_DIR/filter.DOCKER-USER"
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  [ "$(cat "$IPT_DIR/filter.FORWARD")" = "-j DOCKER-USER" ]
  [ "$(cat "$IPT_DIR/filter.DOCKER-USER")" = "$(printf -- '-j MULTIHOP-FWD\n-j RETURN')" ]
}

@test "backstop is installed before ip rules are touched" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  fwd=$(first_line '^iptables -t filter -I DOCKER-USER -j MULTIHOP-FWD-NEW$')
  rule=$(first_line '^ip rule ')
  [ -n "$fwd" ] && [ -n "$rule" ] && [ "$fwd" -lt "$rule" ]
}

@test "ipv6 forwarding from bridges is dropped" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  grep -qx -e 'ip6tables -I FORWARD -i docker0 -j DROP' "$STUB_LOG"
  grep -qx -e 'ip6tables -I FORWARD -i amn0 -j DROP' "$STUB_LOG"
}

@test "ipv6 drop is not duplicated when already present" {
  stub ip6tables "" 0   # -C succeeds: rule present
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  ! grep -q -e '^ip6tables -I' "$STUB_LOG" || false
}

@test "missing ip6tables is tolerated" {
  stub ip6tables "" 127
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
}

@test "up twice yields no duplicate ip rules" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  before=$(snapshot)
  echo "docker0 amn0" > "$IP_DIR/guard"
  echo "docker0 amn0" > "$IPT_GUARD"
  : > "$STUB_LOG"
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  # every priority is cleared before it is re-added
  for p in 10100 10110 10120 10130; do
    del=$(first_line "^ip rule del pref $p\$")
    add=$(first_line "^ip rule add pref $p ")
    [ -n "$del" ] && [ -n "$add" ] && [ "$del" -lt "$add" ]
  done
  # bridge traffic was never left without a rule into table 51820, and
  # DOCKER-USER never without the bridge -> public DROP
  [ ! -f "$IP_DIR/violations" ]
  [ ! -f "$IPT_GUARD.violations" ]
  diff <(sort -s -n -k1,1 "$IP_DIR/rules") <(expected_rules)
  # whole state (iptables and ip) converged to exactly the same set
  [ "$(snapshot)" = "$before" ]
  ! ls "$IPT_DIR" | grep -e '-NEW' || false
}

@test "changed port and bridges drop stale rules" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  cat > "$MULTIHOP_ENV" <<'ENV'
PUBLIC_IFACE=eth9
ENTRY_AWG_PORT=40000
BRIDGES="docker0"
ENV
  echo "docker0" > "$IP_DIR/guard"
  echo "docker0" > "$IPT_GUARD"
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  [ ! -f "$IP_DIR/violations" ]
  [ ! -f "$IPT_GUARD.violations" ]
  diff <(sort -s -n -k1,1 "$IP_DIR/rules") - <<'R'
10100 fwmark 0x5a/0xff lookup main
10110 fwmark 0x5b00/0xff00 lookup main
10120 iif docker0 lookup main suppress_prefixlength 0 suppress_ifgroup 51820
10130 iif docker0 lookup 51820
R
  ! grep -q amn0 "$IPT_DIR/filter.MULTIHOP-FWD" "$IPT_DIR/mangle.PREROUTING" || false
  ! grep -q 51470 "$IPT_DIR/filter.MULTIHOP-FWD" "$IPT_DIR/mangle.MULTIHOP-MARK" || false
  grep -qx -e '-i docker0 -o eth9 -p udp --sport 40000 -j RETURN' "$IPT_DIR/filter.MULTIHOP-FWD"
}

@test "down removes rules, routes and chains" {
  run_script multihop-entry-net up
  run_script multihop-entry-net down
  [ "$status" -eq 0 ]
  [ ! -s "$IP_DIR/rules" ]
  [ ! -s "$IP_DIR/routes" ]
  [ "$(cat "$IP_DIR/link.eth9")" = "eth9 group default" ]
  [ ! -s "$IPT_DIR/filter.DOCKER-USER" ]
  [ ! -s "$IPT_DIR/mangle.PREROUTING" ]
  [ ! -s "$IPT_DIR/nat.POSTROUTING" ]
  [ ! -s "$IPT_DIR/mangle.FORWARD" ]
  ! ls "$IPT_DIR" | grep -e MULTIHOP || false
}

@test "unknown command fails" {
  run_script multihop-entry-net sideways
  [ "$status" -eq 2 ]
}
