#!/usr/bin/env bash
# Run the edge function unit tests with deno.
#
# Lists the test files itself so macOS AppleDouble files (._name.ts, made when
# a folder is copied from an external or network drive) are never loaded: deno
# test on a folder picks them up and fails to parse them. Nothing is deleted.
#
# Usage: supabase/scripts/test_functions.sh [extra deno test flags]
# Tests for this script: supabase/scripts/test_functions_test.sh
set -euo pipefail

# list_tests prints the *.test.ts files under a folder, sorted, skipping ._*
# files and anything under node_modules.
list_tests() {
  find "$1" -type f -name '*.test.ts' ! -name '._*' ! -path '*/node_modules/*' | LC_ALL=C sort
}

main() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../functions"
  local deno="${DENO:-deno}" status=0
  local -a shared synth
  local f

  # A read loop, not mapfile: macOS ships bash 3.2.
  shared=()
  while IFS= read -r f; do shared+=("$f"); done < <(list_tests _shared)
  if [ "${#shared[@]}" -gt 0 ]; then
    echo "== _shared (${#shared[@]} files)"
    "$deno" test --allow-env --allow-read "$@" "${shared[@]}" || status=1
  fi

  # synthesize stubs supabase-js with an import map (gitignored folder, so it
  # may be absent in a fresh clone).
  if [ -f synthesize/test_import_map.json ]; then
    synth=()
    while IFS= read -r f; do synth+=("$f"); done < <(list_tests synthesize)
    if [ "${#synth[@]}" -gt 0 ]; then
      echo "== synthesize (${#synth[@]} files)"
      "$deno" test --allow-env --import-map=synthesize/test_import_map.json "$@" "${synth[@]}" || status=1
    fi
  fi
  return "$status"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
