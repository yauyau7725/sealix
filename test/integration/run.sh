
#!/usr/bin/env bash

# Usage:
# bash test/integration/run.sh IMAGE ALGORITHM OUT_DIR

set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo 'usage: run.sh IMAGE ALGORITHM OUT_DIR' >&2
  exit 2
fi

IMAGE="$1"
ALGORITHM="$2"
OUT_DIR="$3"

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd -P)"

WORK_ROOT="$(mktemp -d)"
trap 'rm -rf "$WORK_ROOT"' EXIT

case "$ALGORITHM" in
  rsa-pss-sha256|ecdsa-p256-sha2|ed25519)
    ;;
  *)
    echo "unsupported algorithm: $ALGORITHM" >&2
    exit 2
    ;;
esac


sealix() {
  local dir="$1"
  shift

  docker run --rm \
    --network none \
    --read-only \
    --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$dir,dst=/work" \
    "$IMAGE" "$@"
}

prepare_case() {
  local id="$1"
  local dir="$WORK_ROOT/$id"

  mkdir -p "$dir"

  printf 'test release for %s\n' \
    "$ALGORITHM" > "$dir/app.bin"

  sealix "$dir" keygen \
    --algorithm "$ALGORITHM" \
    --out /work/key

  sealix "$dir" trust add \
    --store /work/trust.json \
    --key /work/key.pub.pem \
    --package contoh-app

  sealix "$dir" sign \
    --file /work/app.bin \
    --package contoh-app \
    --version 1.0.0 \
    --key /work/key.key.pem \
    --out /work/release.json
}

verify_case() {
  local id="$1"
  local expected_rc="$2"
  local expected_status="$3"
  local artifact="$4"
  local dir="$WORK_ROOT/$id"

  mkdir -p "$OUT_DIR/$id"

  local rc=0

  set +e

  sealix "$dir" verify \
    --file "$artifact" \
    --bundle /work/release.json \
    --trust-store /work/trust.json \
    --package contoh-app \
    --version 1.0.0 \
    --json \
    > "$OUT_DIR/$id/verification.json" \
    2> "$OUT_DIR/$id/verification.stderr"

  rc=$?

  set -e

  printf '%s\n' "$rc" \
    > "$OUT_DIR/$id/exit-code.txt"

  if [[ "$rc" -ne "$expected_rc" ]]; then
    echo \
      "$id failed: exit=$rc expected=$expected_rc" \
      >&2

    cat "$OUT_DIR/$id/verification.stderr" >&2
    exit 1
  fi

  jq -e \
    --arg status "$expected_status" \
    '.status == $status and .valid == ($status == "OK")' \
    "$OUT_DIR/$id/verification.json" \
    >/dev/null

  if [[ "$expected_status" != "OK" ]]; then
    test ! -e "$OUT_DIR/$id/deployed.marker"
  fi

  echo "PASS $id ($ALGORITHM): $expected_status"
}

# C01: rilis valid untuk setiap algoritma.
prepare_case C01

verify_case C01 0 OK /work/app.bin

sha256sum "$WORK_ROOT/C01/app.bin" \
  > "$OUT_DIR/C01/deployed.marker"

test -s "$OUT_DIR/C01/deployed.marker"

# C02-C05 cukup dijalankan dengan satu profil.
if [[ "$ALGORITHM" == "ed25519" ]]; then

  # C02: ubah satu byte, ukuran dan nama sama.
  prepare_case C02

  printf 'X' | dd \
    of="$WORK_ROOT/C02/app.bin" \
    bs=1 seek=0 conv=notrunc status=none

  verify_case C02 1 ARTIFACT_MISMATCH /work/app.bin

  # C03: trust store kosong.
  prepare_case C03

  printf '%s\n' \
    '{"schema":"minisign-trust/v1","keys":[]}' \
    > "$WORK_ROOT/C03/trust.json"

  verify_case C03 1 KEY_NOT_TRUSTED /work/app.bin

  # C04: artefak tidak ditemukan.
  prepare_case C04

  rm "$WORK_ROOT/C04/app.bin"

  verify_case C04 2 INPUT_ERROR /work/app.bin

  # C05: cek UID owner hasil container.
  prepare_case C05

  verify_case C05 0 OK /work/app.bin

  owner="$(
    stat -c '%u' "$WORK_ROOT/C05/release.json"
  )"

  test "$owner" = "$(id -u)"

  echo "PASS C05: uid=$owner" \
    | tee "$OUT_DIR/C05-ownership.txt"

fi
