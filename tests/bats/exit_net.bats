load helpers

setup() {
  export MULTIHOP_ENV="$BATS_TEST_TMPDIR/multihop.env"
  export STUB_LOG="$BATS_TEST_TMPDIR/stub.log"
  export IPT_DIR="$BATS_TEST_TMPDIR/ipt"
  cat > "$MULTIHOP_ENV" <<ENV
PUBLIC_IFACE=eth9
UPLINK_SUBNET=10.9.0.0/30
ENV
  mkdir -p "$BATS_TEST_TMPDIR/bin" "$IPT_DIR"
  # Fake iptables: one file per table/chain, rules and jumps as lines.
  touch "$IPT_DIR/filter.DOCKER-USER" "$IPT_DIR/nat.POSTROUTING" "$IPT_DIR/mangle.FORWARD"
  cat > "$BATS_TEST_TMPDIR/bin/iptables" <<'STUB'
#!/bin/sh
echo "iptables $*" >> "$STUB_LOG"
d="$IPT_DIR"; t=filter
[ "$1" = -t ] && { t="$2"; shift 2; }
op="$1"; shift
f() { echo "$d/$t.$1"; }
case "$op" in
  -N) [ ! -f "$(f "$1")" ] || exit 1; : > "$(f "$1")" ;;
  -F) [ -f "$(f "$1")" ] || exit 1; : > "$(f "$1")" ;;
  -X) [ -f "$(f "$1")" ] || exit 1
      ! cat "$d/$t".* | grep -qx -e "-j $1" || exit 1; rm "$(f "$1")" ;;
  -E) [ -f "$(f "$1")" ] || exit 1; mv "$(f "$1")" "$(f "$2")"
      for x in "$d/$t".*; do sed "s/^-j $1\$/-j $2/" "$x" > "$x.t"; mv "$x.t" "$x"; done ;;
  -A) c="$1"; shift; [ -f "$(f "$c")" ] || exit 1; echo "$*" >> "$(f "$c")" ;;
  -I) c="$1"; shift; [ -f "$(f "$c")" ] || exit 1
      { echo "$*"; cat "$(f "$c")"; } > "$(f "$c").t"; mv "$(f "$c").t" "$(f "$c")" ;;
  -C) c="$1"; shift; [ -f "$(f "$c")" ] && grep -qx -e "$*" "$(f "$c")" ;;
  -D) c="$1"; shift; grep -qx -e "$*" "$(f "$c")" || exit 1
      awk -v t="$*" '$0==t && !done {done=1; next} {print}' "$(f "$c")" > "$(f "$c").t"; mv "$(f "$c").t" "$(f "$c")" ;;
esac
STUB
  chmod +x "$BATS_TEST_TMPDIR/bin/iptables"
  : > "$STUB_LOG"
}

@test "masquerade only uplink subnet" {
  run_script multihop-exit-net up
  [ "$status" -eq 0 ]
  [ "$(cat "$IPT_DIR/nat.MULTIHOP-NAT")" = "-s 10.9.0.0/30 -o eth9 -j MASQUERADE" ]
  [ "$(cat "$IPT_DIR/nat.POSTROUTING")" = "-j MULTIHOP-NAT" ]
  [ "$(grep -c -e 'MASQUERADE' "$STUB_LOG")" -eq 1 ]
}

@test "forward rules in DOCKER-USER via MULTIHOP-FWD" {
  run_script multihop-exit-net up
  [ "$status" -eq 0 ]
  [ "$(cat "$IPT_DIR/filter.DOCKER-USER")" = "-j MULTIHOP-FWD" ]
  grep -qx -e '-i awg-exit -o eth9 -j ACCEPT' "$IPT_DIR/filter.MULTIHOP-FWD"
  grep -qx -e '-i eth9 -o awg-exit -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' "$IPT_DIR/filter.MULTIHOP-FWD"
}

@test "mss clamp on both directions of awg-exit" {
  run_script multihop-exit-net up
  [ "$status" -eq 0 ]
  grep -qx -e '-i awg-exit -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu' "$IPT_DIR/mangle.MULTIHOP-MSS"
  grep -qx -e '-o awg-exit -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu' "$IPT_DIR/mangle.MULTIHOP-MSS"
  [ "$(cat "$IPT_DIR/mangle.FORWARD")" = "-j MULTIHOP-MSS" ]
}

@test "up is idempotent" {
  run_script multihop-exit-net up
  : > "$STUB_LOG"
  run_script multihop-exit-net up
  [ "$status" -eq 0 ]
  # jumps are checked (-C) before any insert; old jump is removed only after
  # the new one is in place; old chain is flushed, not duplicated
  chk=$(grep -n -m1 -e '^iptables -t filter -C DOCKER-USER' "$STUB_LOG" | cut -d: -f1)
  ins=$(grep -n -m1 -e '^iptables -t filter -I DOCKER-USER -j MULTIHOP-FWD-NEW$' "$STUB_LOG" | cut -d: -f1)
  del=$(grep -n -m1 -e '^iptables -t filter -D DOCKER-USER -j MULTIHOP-FWD$' "$STUB_LOG" | cut -d: -f1)
  [ -n "$chk" ] && [ -n "$ins" ] && [ -n "$del" ]
  [ "$chk" -lt "$ins" ]
  [ "$ins" -lt "$del" ]
  grep -q -e '^iptables -t filter -F MULTIHOP-FWD$' "$STUB_LOG"
  # no duplicates and no leftover temp chains
  [ "$(cat "$IPT_DIR/filter.DOCKER-USER")" = "-j MULTIHOP-FWD" ]
  [ "$(grep -c -e '-j ACCEPT' "$IPT_DIR/filter.MULTIHOP-FWD")" -eq 2 ]
  [ "$(wc -l < "$IPT_DIR/nat.MULTIHOP-NAT")" -eq 1 ]
  [ "$(wc -l < "$IPT_DIR/mangle.MULTIHOP-MSS")" -eq 2 ]
  ! ls "$IPT_DIR" | grep -e '-NEW'
}

@test "new chain is populated before the jump swap" {
  run_script multihop-exit-net up
  first_i=$(grep -n -m1 -e '^iptables -t filter -I DOCKER-USER -j MULTIHOP-FWD-NEW$' "$STUB_LOG" | cut -d: -f1)
  last_a=$(grep -n -e '^iptables -t filter -A MULTIHOP-FWD-NEW' "$STUB_LOG" | tail -n1 | cut -d: -f1)
  [ "$last_a" -lt "$first_i" ]
}

@test "down removes all jumps and chains" {
  run_script multihop-exit-net up
  run_script multihop-exit-net down
  [ "$status" -eq 0 ]
  [ ! -s "$IPT_DIR/filter.DOCKER-USER" ]
  [ ! -s "$IPT_DIR/nat.POSTROUTING" ]
  [ ! -s "$IPT_DIR/mangle.FORWARD" ]
  [ ! -f "$IPT_DIR/filter.MULTIHOP-FWD" ]
}
