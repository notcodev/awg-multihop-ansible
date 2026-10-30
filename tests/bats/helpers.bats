load helpers

@test "stub records invocations" {
  stub ip "default via 1.1.1.1"
  PATH="$BATS_TEST_TMPDIR/bin:$PATH" run ip rule show
  [ "$status" -eq 0 ]
  [ "$output" = "default via 1.1.1.1" ]
  grep -q "ip rule show" "$STUB_LOG"
}
