load helpers

# docker/aws/age are stubs. aws saves each uploaded stdin under $UPLOADS/<last
# path component>; age marks its output so tests can tell plaintext from
# ciphertext. tar is the real one: GNU tar runs the script's flags as-is, bsdtar
# (macOS) goes through a wrapper selected by MULTIHOP_TAR.
setup() {
  export MULTIHOP_ENV="$BATS_TEST_TMPDIR/multihop.env"
  export MULTIHOP_STATE_DIR="$BATS_TEST_TMPDIR/state"
  export STUB_LOG="$BATS_TEST_TMPDIR/stub.log"
  export UPLOADS="$BATS_TEST_TMPDIR/uploads"
  export ENTRY_DIR="$BATS_TEST_TMPDIR/entry-awg"
  mkdir -p "$BATS_TEST_TMPDIR/bin" "$UPLOADS" "$ENTRY_DIR" "$MULTIHOP_STATE_DIR"
  : > "$STUB_LOG"
  cat > "$MULTIHOP_ENV" <<ENV
ENTRY_STATE_DIR=$ENTRY_DIR
S3_ENDPOINT=https://s3.example.com
S3_REGION=eu-1
BUCKET=bkt
PREFIX=multihop
AGE_RECIPIENT=age1recipient
ENV
  echo "[Interface]" > "$ENTRY_DIR/awg0.conf"
  echo "key" > "$ENTRY_DIR/wireguard_server_private_key.key"

  stub docker "/opt/amnezia/awg"
  cat > "$BATS_TEST_TMPDIR/bin/age" <<'STUB'
#!/bin/sh
echo "age $*" >> "$STUB_LOG"
echo "AGE-ENCRYPTED"
cat
STUB
  cat > "$BATS_TEST_TMPDIR/bin/aws" <<'STUB'
#!/bin/sh
echo "aws $*" >> "$STUB_LOG"
[ -n "$AWS_FAIL" ] && { cat > /dev/null; exit 1; }
for a in "$@"; do last="$a"; done
cat > "$UPLOADS/$(basename "$last")"
STUB
  chmod +x "$BATS_TEST_TMPDIR/bin/age" "$BATS_TEST_TMPDIR/bin/aws"

  if ! tar --version 2>/dev/null | grep -q GNU; then
    cat > "$BATS_TEST_TMPDIR/bin/tar-compat" <<'STUB'
#!/bin/sh
# bsdtar stand-in for the GNU flags in multihop-backup.
args=""
for a in "$@"; do
  case "$a" in
    --sort=name|--mtime=@0|--owner=0|--group=0) ;;
    *) args="$args $a" ;;
  esac
done
# shellcheck disable=SC2086
exec tar --uid 0 --gid 0 $args
STUB
    chmod +x "$BATS_TEST_TMPDIR/bin/tar-compat"
    export MULTIHOP_TAR="$BATS_TEST_TMPDIR/bin/tar-compat"
  fi
}

uploaded_objects() { ls "$UPLOADS" | grep '^entry-.*\.tar\.age$' || true; }

@test "missing bind mount exits 2 and writes DRIFT" {
  stub docker "/var/lib/other"
  run_script multihop-backup
  [ "$status" -eq 2 ]
  [ -f "$MULTIHOP_STATE_DIR/backup/DRIFT" ]
  [[ "$output" == *'ERROR: amnezia-awg2 lost its bind mount (app reinstall?) — see README "Recovery"'* ]]
  ! grep -q '^aws ' "$STUB_LOG" || false
}

@test "unchanged state does not upload" {
  run_script multihop-backup
  [ "$status" -eq 0 ]
  : > "$STUB_LOG"
  rm -f "$UPLOADS"/*
  run_script multihop-backup
  [ "$status" -eq 0 ]
  ! grep -q '^aws ' "$STUB_LOG" || false
  [ -z "$(ls "$UPLOADS")" ]
}

@test "changed state uploads encrypted object and latest pointer" {
  run_script multihop-backup
  [ "$status" -eq 0 ]
  grep -q '^age -r age1recipient' "$STUB_LOG"
  grep -q -- '^aws --profile multihop-backup --endpoint-url https://s3.example.com s3 cp - s3://bkt/multihop/entry-' "$STUB_LOG"
  grep -q -- 's3://bkt/multihop/latest' "$STUB_LOG"
  obj="$(uploaded_objects)"
  [[ "$obj" =~ ^entry-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}\.tar\.age$ ]]
  head -n1 "$UPLOADS/$obj" | grep -qx AGE-ENCRYPTED
  [ "$(cat "$UPLOADS/latest")" = "multihop/$obj" ]
  [ -s "$MULTIHOP_STATE_DIR/backup/last.sha256" ]
  [[ "$obj" == *"$(head -c12 "$MULTIHOP_STATE_DIR/backup/last.sha256").tar.age" ]]

  # A change uploads again.
  echo extra > "$ENTRY_DIR/clientsTable"
  : > "$STUB_LOG"
  run_script multihop-backup
  [ "$status" -eq 0 ]
  grep -q '^aws .*s3 cp - s3://bkt/multihop/entry-' "$STUB_LOG"
}

@test "archive has state files at the archive root" {
  run_script multihop-backup
  [ "$status" -eq 0 ]
  obj="$(uploaded_objects)"
  tail -n +2 "$UPLOADS/$obj" | tar -tf - | grep -qx './awg0.conf'
}

@test "--force uploads even if unchanged" {
  run_script multihop-backup
  [ "$status" -eq 0 ]
  : > "$STUB_LOG"
  run_script multihop-backup --force
  [ "$status" -eq 0 ]
  grep -q '^aws .*s3 cp - s3://bkt/multihop/entry-' "$STUB_LOG"
}

@test "upload failure exits 1 and does not update last.sha256" {
  export AWS_FAIL=1
  run_script multihop-backup
  [ "$status" -eq 1 ]
  [ ! -e "$MULTIHOP_STATE_DIR/backup/last.sha256" ]
}

@test "archive is deterministic" {
  run_script multihop-backup
  [ "$status" -eq 0 ]
  first="$(cat "$MULTIHOP_STATE_DIR/backup/last.sha256")"
  rm -f "$MULTIHOP_STATE_DIR/backup/last.sha256"
  run_script multihop-backup
  [ "$status" -eq 0 ]
  [ "$first" = "$(cat "$MULTIHOP_STATE_DIR/backup/last.sha256")" ]
}
