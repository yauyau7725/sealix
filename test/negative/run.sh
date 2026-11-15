#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../../app"

go test ./internal/cli \
  -run '^TestNegativeU02ToU13$|^TestVerifyPrecedence$' \
  -count=1 -v