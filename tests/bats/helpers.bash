# Shared bats helpers.
REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"

# stub <cmd> [stdout] [exit]
# Creates an executable in $BATS_TEST_TMPDIR/bin that logs "<cmd> $*" to
# $STUB_LOG and prints stdout.
stub() {
  local cmd="$1" out="${2:-}" code="${3:-0}"
  export STUB_LOG="${STUB_LOG:-$BATS_TEST_TMPDIR/stub.log}"
  mkdir -p "$BATS_TEST_TMPDIR/bin"
  : >> "$STUB_LOG"
  {
    echo '#!/bin/sh'
    echo "echo \"$cmd \$*\" >> \"\$STUB_LOG\""
    if [ -n "$out" ]; then
      printf 'printf "%%s\\n" %q\n' "$out"
    fi
    echo "exit $code"
  } > "$BATS_TEST_TMPDIR/bin/$cmd"
  chmod +x "$BATS_TEST_TMPDIR/bin/$cmd"
}

# run_script <name> <args...>
# Runs roles/*/files/<name> with the stub dir first on PATH.
run_script() {
  local name="$1"; shift
  local path
  path="$(ls "$REPO_ROOT"/roles/*/files/"$name" 2>/dev/null | head -n1)"
  [ -n "$path" ] || { echo "script not found: $name" >&2; return 127; }
  PATH="$BATS_TEST_TMPDIR/bin:$PATH" run "$path" "$@"
}
