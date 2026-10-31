load helpers

# Stateful fakes: ipset keeps one file per set (one element per line), so the
# tests assert the end state. curl serves $CURL_BODY (or fails with $CURL_RC),
# dig prints $DIG_OUT.
setup() {
  export MULTIHOP_SPLIT_CONF="$BATS_TEST_TMPDIR/split.conf"
  export MULTIHOP_STATE_DIR="$BATS_TEST_TMPDIR/state"
  export STUB_LOG="$BATS_TEST_TMPDIR/stub.log"
  export IPSET_DIR="$BATS_TEST_TMPDIR/ipset"
  export CURL_BODY="$BATS_TEST_TMPDIR/curl.body"
  export DIG_OUT="$BATS_TEST_TMPDIR/dig.out"
  mkdir -p "$BATS_TEST_TMPDIR/bin" "$IPSET_DIR" "$MULTIHOP_STATE_DIR/split"
  : > "$STUB_LOG"; : > "$DIG_OUT"
  conf ru "" "" ""

  cat > "$BATS_TEST_TMPDIR/bin/ipset" <<'STUB'
#!/bin/sh
echo "ipset $*" >> "$STUB_LOG"
d="$IPSET_DIR"
exist=0
for a in "$@"; do [ "$a" = -exist ] && exist=1; done
op="$1"; shift
case "$op" in
  create)
    [ -f "$d/$1" ] && { [ "$exist" -eq 1 ] && exit 0; echo "already exists" >&2; exit 1; }
    : > "$d/$1" ;;
  destroy) [ -f "$d/$1" ] || exit 1; rm -f "$d/$1" ;;
  flush) [ -f "$d/$1" ] || exit 1; : > "$d/$1" ;;
  swap)
    [ -f "$d/$1" ] && [ -f "$d/$2" ] || exit 1
    mv "$d/$1" "$d/swap.tmp"; mv "$d/$2" "$d/$1"; mv "$d/swap.tmp" "$d/$2" ;;
  restore)
    while read -r verb set elem; do
      [ "$verb" = add ] || exit 1
      [ -f "$d/$set" ] || exit 1
      echo "$elem" >> "$d/$set"
    done ;;
  *) exit 1 ;;
esac
STUB
  cat > "$BATS_TEST_TMPDIR/bin/curl" <<'STUB'
#!/bin/sh
echo "curl $*" >> "$STUB_LOG"
out=""
while [ $# -gt 0 ]; do
  case "$1" in -o) out="$2"; shift ;; esac
  shift
done
[ "${CURL_RC:-0}" -eq 0 ] || exit "$CURL_RC"
cat "$CURL_BODY" > "$out"
STUB
  cat > "$BATS_TEST_TMPDIR/bin/dig" <<'STUB'
#!/bin/sh
echo "dig $*" >> "$STUB_LOG"
cat "$DIG_OUT"
STUB
  chmod +x "$BATS_TEST_TMPDIR/bin/"*
}

# conf <countries> <direct cidrs> <direct domains> <force-exit cidrs>
conf() {
  cat > "$MULTIHOP_SPLIT_CONF" <<CONF
COUNTRIES="$1"
URL="https://lists.example/{cc}.zone"
DIRECT_CIDRS="$2"
DIRECT_DOMAINS="$3"
FORCE_EXIT_CIDRS="$4"
CONF
}

set_has() { grep -qxF -e "$2" "$IPSET_DIR/$1"; }
set_count() { wc -l < "$IPSET_DIR/$1" | tr -d ' '; }

# Pre-existing live set and cache, as left by an earlier good run.
seed_previous() {
  printf '10.1.0.0/16\n10.2.0.0/16\n' > "$IPSET_DIR/multihop_direct"
  : > "$IPSET_DIR/multihop_force_exit"
  printf '10.1.0.0/16\n10.2.0.0/16\n' > "$MULTIHOP_STATE_DIR/split/ru.zone"
  touch -t 202001010000 "$MULTIHOP_STATE_DIR/split/ru.zone"
}

@test "valid download replaces cache" {
  seed_previous
  printf '192.0.2.0/24\n198.51.100.0/24\n\n' > "$CURL_BODY"
  run_script multihop-split-refresh
  [ "$status" -eq 0 ]
  grep -q 'https://lists.example/ru.zone' "$STUB_LOG"
  grep -qxF '192.0.2.0/24' "$MULTIHOP_STATE_DIR/split/ru.zone"
  ! grep -q '10.1.0.0' "$MULTIHOP_STATE_DIR/split/ru.zone" || false
  set_has multihop_direct 192.0.2.0/24
  set_has multihop_direct 198.51.100.0/24
  [ "$(set_count multihop_direct)" -eq 2 ]
}

@test "country code is lowercased in the URL" {
  conf RU "" "" ""
  printf '192.0.2.0/24\n' > "$CURL_BODY"
  run_script multihop-split-refresh
  [ "$status" -eq 0 ]
  grep -q 'https://lists.example/ru.zone' "$STUB_LOG"
}

@test "html error page keeps previous cache" {
  seed_previous
  printf '<html><body>503 Service Unavailable</body></html>\n' > "$CURL_BODY"
  run_script multihop-split-refresh
  grep -q 'https://lists.example/ru.zone' "$STUB_LOG"
  grep -qxF '10.1.0.0/16' "$MULTIHOP_STATE_DIR/split/ru.zone"
  ! grep -q html "$MULTIHOP_STATE_DIR/split/ru.zone" || false
  set_has multihop_direct 10.1.0.0/16
  set_has multihop_direct 10.2.0.0/16
  [ "$(set_count multihop_direct)" -eq 2 ]
}

@test "partially valid body (one garbage line) is rejected as a whole" {
  seed_previous
  printf '192.0.2.0/24\nnot-a-cidr\n198.51.100.0/24\n' > "$CURL_BODY"
  run_script multihop-split-refresh
  grep -qxF '10.1.0.0/16' "$MULTIHOP_STATE_DIR/split/ru.zone"
  [ "$(set_count multihop_direct)" -eq 2 ]
  ! set_has multihop_direct 192.0.2.0/24 || false
}

@test "empty body keeps previous cache" {
  seed_previous
  : > "$CURL_BODY"
  run_script multihop-split-refresh
  grep -qxF '10.1.0.0/16' "$MULTIHOP_STATE_DIR/split/ru.zone"
  set_has multihop_direct 10.2.0.0/16
  [ "$(set_count multihop_direct)" -eq 2 ]
}

@test "curl failure keeps previous cache" {
  seed_previous
  export CURL_RC=22
  run_script multihop-split-refresh
  grep -qxF '10.2.0.0/16' "$MULTIHOP_STATE_DIR/split/ru.zone"
  set_has multihop_direct 10.1.0.0/16
  [ "$(set_count multihop_direct)" -eq 2 ]
}

@test "first run with failed download builds set from static cidrs only" {
  conf ru "203.0.113.0/24 203.0.113.77" "" ""
  export CURL_RC=6
  run_script multihop-split-refresh
  [ "$status" -eq 0 ]
  set_has multihop_direct 203.0.113.0/24
  set_has multihop_direct 203.0.113.77
  [ "$(set_count multihop_direct)" -eq 2 ]
  ! set_has multihop_direct 0.0.0.0/0 || false
  [ ! -e "$MULTIHOP_STATE_DIR/split/ru.zone" ]
}

@test "first run, failed download and no static entries leaves set empty but existing and does not swap" {
  export CURL_RC=6
  run_script multihop-split-refresh
  [ -f "$IPSET_DIR/multihop_direct" ]
  [ "$(set_count multihop_direct)" -eq 0 ]
  ! grep -q 'ipset swap multihop_direct_new multihop_direct' "$STUB_LOG" || false
}

@test "cache lost and download failed does not empty a populated set" {
  conf ru "" "" ""
  printf '10.1.0.0/16\n' > "$IPSET_DIR/multihop_direct"
  export CURL_RC=6
  run_script multihop-split-refresh
  set_has multihop_direct 10.1.0.0/16
}

@test "0.0.0.0/0 in a country list is rejected" {
  seed_previous
  printf '192.0.2.0/24\n0.0.0.0/0\n' > "$CURL_BODY"
  run_script multihop-split-refresh
  ! grep -q '0.0.0.0/0' "$MULTIHOP_STATE_DIR/split/ru.zone" || false
  ! grep -q '0.0.0.0/0' "$IPSET_DIR/multihop_direct" || false
  [ "$(set_count multihop_direct)" -eq 2 ]
}

@test "0.0.0.0/0 in a cached zone, static cidrs and force-exit is never loaded" {
  conf ru "0.0.0.0/0 203.0.113.0/24 1.2.3.4/0 0.0.0.0" "" "0.0.0.0/0 198.51.100.0/24"
  printf '0.0.0.0/0\n192.0.2.0/24\n' > "$MULTIHOP_STATE_DIR/split/ru.zone"
  run_script multihop-split-refresh
  [ "$status" -eq 0 ]
  set_has multihop_direct 203.0.113.0/24
  set_has multihop_direct 192.0.2.0/24
  ! set_has multihop_direct 0.0.0.0 || false
  ! grep -q '/0$' "$IPSET_DIR/multihop_direct" || false
  ! grep -q '/0$' "$IPSET_DIR/multihop_force_exit" || false
  set_has multihop_force_exit 198.51.100.0/24
  [ "$(set_count multihop_force_exit)" -eq 1 ]
}

@test "only 0.0.0.0/0 configured leaves the live set alone" {
  conf "" "0.0.0.0/0" "" ""
  printf '10.1.0.0/16\n' > "$IPSET_DIR/multihop_direct"
  run_script multihop-split-refresh
  set_has multihop_direct 10.1.0.0/16
  ! grep -q '/0$' "$IPSET_DIR/multihop_direct" || false
}

@test "swap is used, not flush" {
  seed_previous
  printf '192.0.2.0/24\n' > "$CURL_BODY"
  run_script multihop-split-refresh
  [ "$status" -eq 0 ]
  grep -qxF 'ipset swap multihop_direct_new multihop_direct' "$STUB_LOG"
  grep -qxF 'ipset swap multihop_force_exit_new multihop_force_exit' "$STUB_LOG"
  ! grep -q 'ipset flush' "$STUB_LOG" || false
  [ ! -e "$IPSET_DIR/multihop_direct_new" ]
  [ ! -e "$IPSET_DIR/multihop_force_exit_new" ]
}

@test "cache fresher than 24h is not re-downloaded" {
  printf '192.0.2.0/24\n' > "$MULTIHOP_STATE_DIR/split/ru.zone"
  printf '198.51.100.0/24\n' > "$CURL_BODY"
  run_script multihop-split-refresh
  [ "$status" -eq 0 ]
  ! grep -q '^curl' "$STUB_LOG" || false
  set_has multihop_direct 192.0.2.0/24
}

@test "--force-countries re-downloads a fresh cache" {
  printf '192.0.2.0/24\n' > "$MULTIHOP_STATE_DIR/split/ru.zone"
  printf '198.51.100.0/24\n' > "$CURL_BODY"
  run_script multihop-split-refresh --force-countries
  [ "$status" -eq 0 ]
  grep -q '^curl' "$STUB_LOG"
  set_has multihop_direct 198.51.100.0/24
  ! set_has multihop_direct 192.0.2.0/24 || false
}

@test "domain answers are validated: only IPv4 addresses are added" {
  conf "" "" "example.org" ""
  cat > "$DIG_OUT" <<'A'
cdn.example.net.
203.0.113.10
<html>
999.1.1.1
0.0.0.0
2001:db8::1
203.0.113.11
A
  run_script multihop-split-refresh
  [ "$status" -eq 0 ]
  grep -q 'dig .*example.org' "$STUB_LOG"
  set_has multihop_direct 203.0.113.10
  set_has multihop_direct 203.0.113.11
  [ "$(set_count multihop_direct)" -eq 2 ]
}

@test "unresolvable domain with no other source keeps live set" {
  conf "" "" "example.org" ""
  printf '10.1.0.0/16\n' > "$IPSET_DIR/multihop_direct"
  run_script multihop-split-refresh
  set_has multihop_direct 10.1.0.0/16
}

@test "force-exit set is built from its cidrs" {
  conf "" "192.0.2.0/24" "" "192.0.2.128/25 198.51.100.9"
  run_script multihop-split-refresh
  [ "$status" -eq 0 ]
  set_has multihop_force_exit 192.0.2.128/25
  set_has multihop_force_exit 198.51.100.9
  [ "$(set_count multihop_force_exit)" -eq 2 ]
  set_has multihop_direct 192.0.2.0/24
}

@test "empty configuration produces empty sets" {
  conf "" "" "" ""
  run_script multihop-split-refresh
  [ "$status" -eq 0 ]
  [ "$(set_count multihop_direct)" -eq 0 ]
  [ "$(set_count multihop_force_exit)" -eq 0 ]
}

@test "unknown option is rejected" {
  run_script multihop-split-refresh --bogus
  [ "$status" -eq 2 ]
}
