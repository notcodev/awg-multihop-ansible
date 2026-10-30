load helpers

setup() {
  export MULTIHOP_ENV="$BATS_TEST_TMPDIR/multihop.env"
  export STUB_LOG="$BATS_TEST_TMPDIR/stub.log"
  export IPT_STATE="$BATS_TEST_TMPDIR/jump.present"
  cat > "$MULTIHOP_ENV" <<ENV
PUBLIC_IFACE=eth9
SSH_PORT=2222
INPUT_UDP_PORTS="51820 443"
INPUT_TCP_PORTS="9000"
ENV
  # Stateful iptables stub: -C of the INPUT jump fails until -I/-A adds it.
  mkdir -p "$BATS_TEST_TMPDIR/bin"
  cat > "$BATS_TEST_TMPDIR/bin/iptables" <<'STUB'
#!/bin/sh
echo "iptables $*" >> "$STUB_LOG"
case "$*" in
  "-C INPUT -j MULTIHOP-IN") [ -f "$IPT_STATE" ]; exit $? ;;
  "-I INPUT -j MULTIHOP-IN"|"-I INPUT 1 -j MULTIHOP-IN") : > "$IPT_STATE" ;;
  "-D INPUT -j MULTIHOP-IN") rm -f "$IPT_STATE" ;;
esac
exit 0
STUB
  chmod +x "$BATS_TEST_TMPDIR/bin/iptables"
  : > "$STUB_LOG"
}

@test "up adds jump once" {
  run_script multihop-input-fw up
  [ "$status" -eq 0 ]
  run_script multihop-input-fw up
  [ "$status" -eq 0 ]
  first_c=$(grep -n -m1 -e '^iptables -C INPUT -j MULTIHOP-IN$' "$STUB_LOG" | cut -d: -f1)
  first_i=$(grep -n -m1 -e '^iptables -I INPUT' "$STUB_LOG" | cut -d: -f1)
  [ -n "$first_c" ]
  [ "$first_c" -lt "$first_i" ]
  [ "$(grep -c -e '^iptables -I INPUT' "$STUB_LOG")" -eq 1 ]
  [ "$(grep -c -e '^iptables -C INPUT -j MULTIHOP-IN$' "$STUB_LOG")" -eq 2 ]
}

@test "up allows ssh port from env" {
  run_script multihop-input-fw up
  [ "$status" -eq 0 ]
  grep -q -e '^iptables -A MULTIHOP-IN -p tcp --dport 2222 -j ACCEPT$' "$STUB_LOG"
}

@test "up allows each INPUT_UDP_PORTS entry" {
  run_script multihop-input-fw up
  [ "$status" -eq 0 ]
  grep -q -e '^iptables -A MULTIHOP-IN -p udp --dport 51820 -j ACCEPT$' "$STUB_LOG"
  grep -q -e '^iptables -A MULTIHOP-IN -p udp --dport 443 -j ACCEPT$' "$STUB_LOG"
}

@test "up allows each INPUT_TCP_PORTS entry" {
  run_script multihop-input-fw up
  [ "$status" -eq 0 ]
  grep -q -e '^iptables -A MULTIHOP-IN -p tcp --dport 9000 -j ACCEPT$' "$STUB_LOG"
}

@test "final rule drops on PUBLIC_IFACE only" {
  run_script multihop-input-fw up
  [ "$status" -eq 0 ]
  last_a=$(grep -e '^iptables -A MULTIHOP-IN' "$STUB_LOG" | tail -n1)
  [ "$last_a" = "iptables -A MULTIHOP-IN -i eth9 -j DROP" ]
  [ "$(grep -c -e '-j DROP' "$STUB_LOG")" -eq 1 ]
}

@test "down removes the jump" {
  run_script multihop-input-fw up
  run_script multihop-input-fw down
  [ "$status" -eq 0 ]
  grep -q -e '^iptables -D INPUT -j MULTIHOP-IN$' "$STUB_LOG"
}
