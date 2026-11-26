#!/usr/bin/env bash
# Unit test for list_tests in test_functions.sh: AppleDouble (._*) files and
# node_modules are skipped, real test files are listed in order.
set -euo pipefail
# shellcheck source=test_functions.sh
source "$(dirname "$0")/test_functions.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/_shared/node_modules/x" "$tmp/_shared/sub"
touch "$tmp/_shared/pricing.test.ts" "$tmp/_shared/._pricing.test.ts" "$tmp/_shared/._pricing.ts" \
  "$tmp/_shared/a.test.ts" "$tmp/_shared/sub/b.test.ts" "$tmp/_shared/sub/._b.test.ts" \
  "$tmp/_shared/node_modules/x/c.test.ts" "$tmp/_shared/pricing.ts"

got="$(cd "$tmp" && list_tests _shared)"
want="$(printf '%s\n' _shared/a.test.ts _shared/pricing.test.ts _shared/sub/b.test.ts)"
if [ "$got" != "$want" ]; then
  printf 'FAIL list_tests\n got:\n%s\n want:\n%s\n' "$got" "$want"
  exit 1
fi
echo "PASS list_tests skips ._* and node_modules"
