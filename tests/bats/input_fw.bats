load helpers

setup() {
  export MULTIHOP_ENV="$BATS_TEST_TMPDIR/multihop.env"
  export STUB_LOG="$BATS_TEST_TMPDIR/stub.log"
  export IPT_DIR="$BATS_TEST_TMPDIR/ipt"
  cat > "$MULTIHOP_ENV" <<ENV
PUBLIC_IFACE=eth9
SSH_PORT=2222
INPUT_UDP_PORTS="51820 443"
INPUT_TCP_PORTS="9000"
ENV
  # Fake iptables modelling chains and the INPUT jump list.
  mkdir -p "$BATS_TEST_TMPDIR/bin" "$IPT_DIR"
  cat > "$BATS_TEST_TMPDIR/bin/iptables" <<'STUB'
#!/bin/sh
echo "iptables $*" >> "$STUB_LOG"
d="$IPT_DIR"; touch "$d/INPUT"
op="$1"; shift
case "$op" in
  -N) [ ! -f "$d/chain.$1" ] || exit 1; : > "$d/chain.$1" ;;
  -F) [ -f "$d/chain.$1" ] || exit 1; : > "$d/chain.$1" ;;
  -X) [ -f "$d/chain.$1" ] || exit 1; ! grep -qx -e "-j $1" "$d/INPUT" || exit 1; rm "$d/chain.$1" ;;
  -E) [ -f "$d/chain.$1" ] || exit 1; mv "$d/chain.$1" "$d/chain.$2"
      sed "s/^-j $1\$/-j $2/" "$d/INPUT" > "$d/INPUT.t"; mv "$d/INPUT.t" "$d/INPUT" ;;
  -A) c="$1"; shift; [ -f "$d/chain.$c" ] || exit 1; echo "$*" >> "$d/chain.$c" ;;
  -I) [ "$1" = INPUT ] || exit 1; shift; { echo "$*"; cat "$d/INPUT"; } > "$d/INPUT.t"; mv "$d/INPUT.t" "$d/INPUT" ;;
  -C) shift; grep -qx -e "$*" "$d/INPUT" ;;
  -D) shift; grep -qx -e "$*" "$d/INPUT" || exit 1
      awk -v t="$*" '$0==t && !done {done=1; next} {print}' "$d/INPUT" > "$d/INPUT.t"; mv "$d/INPUT.t" "$d/INPUT" ;;
esac
STUB
  chmod +x "$BATS_TEST_TMPDIR/bin/iptables"
  : > "$STUB_LOG"
}

@test "up leaves exactly one jump after repeated runs" {
  run_script multihop-input-fw up
  [ "$status" -eq 0 ]
  run_script multihop-input-fw up
  [ "$status" -eq 0 ]
  [ "$(cat "$IPT_DIR/INPUT")" = "-j MULTIHOP-IN" ]
  [ -f "$IPT_DIR/chain.MULTIHOP-IN" ]
  [ ! -f "$IPT_DIR/chain.MULTIHOP-IN-NEW" ]
  [ "$(grep -c -e '-j DROP' "$IPT_DIR/chain.MULTIHOP-IN")" -eq 1 ]
}

@test "new chain is fully populated before the jump swap" {
  run_script multihop-input-fw up
  [ "$status" -eq 0 ]
  first_i=$(grep -n -m1 -e '^iptables -I INPUT -j MULTIHOP-IN-NEW$' "$STUB_LOG" | cut -d: -f1)
  last_a=$(grep -n -e '^iptables -A MULTIHOP-IN-NEW' "$STUB_LOG" | tail -n1 | cut -d: -f1)
  [ -n "$first_i" ]
  [ "$last_a" -lt "$first_i" ]
}

@test "second up inserts new jump before removing old one" {
  run_script multihop-input-fw up
  : > "$STUB_LOG"
  run_script multihop-input-fw up
  [ "$status" -eq 0 ]
  ins=$(grep -n -e '^iptables -I INPUT -j MULTIHOP-IN-NEW$' "$STUB_LOG" | cut -d: -f1)
  del=$(grep -n -e '^iptables -D INPUT -j MULTIHOP-IN$' "$STUB_LOG" | cut -d: -f1)
  [ "$ins" -lt "$del" ]
}

@test "up allows ssh port from env" {
  run_script multihop-input-fw up
  [ "$status" -eq 0 ]
  grep -q -e '^iptables -A MULTIHOP-IN-NEW -p tcp --dport 2222 -j ACCEPT$' "$STUB_LOG"
}

@test "up allows each INPUT_UDP_PORTS entry" {
  run_script multihop-input-fw up
  [ "$status" -eq 0 ]
  grep -q -e '^iptables -A MULTIHOP-IN-NEW -p udp --dport 51820 -j ACCEPT$' "$STUB_LOG"
  grep -q -e '^iptables -A MULTIHOP-IN-NEW -p udp --dport 443 -j ACCEPT$' "$STUB_LOG"
}

@test "up allows each INPUT_TCP_PORTS entry" {
  run_script multihop-input-fw up
  [ "$status" -eq 0 ]
  grep -q -e '^iptables -A MULTIHOP-IN-NEW -p tcp --dport 9000 -j ACCEPT$' "$STUB_LOG"
}

@test "final rule drops on PUBLIC_IFACE only" {
  run_script multihop-input-fw up
  [ "$status" -eq 0 ]
  [ "$(tail -n1 "$IPT_DIR/chain.MULTIHOP-IN")" = "-i eth9 -j DROP" ]
  [ "$(grep -c -e '-j DROP' "$STUB_LOG")" -eq 1 ]
}

@test "down removes the jump" {
  run_script multihop-input-fw up
  run_script multihop-input-fw down
  [ "$status" -eq 0 ]
  [ ! -s "$IPT_DIR/INPUT" ]
  [ ! -f "$IPT_DIR/chain.MULTIHOP-IN" ]
}
