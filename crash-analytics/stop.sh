#!/usr/bin/env bash
#
# Stop the Trojan Errors stack.
#
# Only touches processes recorded in crash-analytics/.data/*.pid by start.sh.
# Anything you started by hand is left alone on purpose. Safe to run twice.
#
# Usage:
#   ./crash-analytics/stop.sh [name ...]      # default: sample-app shim bugsink
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$HERE/.data"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[1;32mok\033[0m   %s\n' "$*"; }
info() { printf '    \033[1;33m--\033[0m   %s\n' "$*"; }

# Reverse of start order: the producer goes down before its backend.
# (Written this way rather than SERVICES=("$@") because bash 3.2, which is what
# macOS ships, trips over an empty array under `set -u`.)
if [ $# -eq 0 ]; then
  set -- sample-app shim bugsink
fi

stop_one() {
  local name="$1"
  local pidfile="$DATA_DIR/$name.pid"
  local pid

  if [ ! -f "$pidfile" ]; then
    info "$name: no pid file, nothing to stop"
    return 0
  fi

  pid="$(tr -dc '0-9' <"$pidfile" 2>/dev/null || true)"
  if [ -z "$pid" ]; then
    info "$name: pid file was empty, removing it"
    rm -f "$pidfile"
    return 0
  fi

  if ! kill -0 "$pid" >/dev/null 2>&1; then
    info "$name: pid $pid is not running, clearing stale pid file"
    rm -f "$pidfile"
    return 0
  fi

  say "Stopping $name (pid $pid)"
  kill -TERM "$pid" >/dev/null 2>&1 || true

  # Give it up to 10s to shut down cleanly, then insist.
  local waited=0
  while kill -0 "$pid" >/dev/null 2>&1 && [ "$waited" -lt 20 ]; do
    sleep 0.5
    waited=$((waited + 1))
  done

  if kill -0 "$pid" >/dev/null 2>&1; then
    info "$name: still alive after 10s, sending SIGKILL"
    kill -KILL "$pid" >/dev/null 2>&1 || true
    sleep 0.5
  fi

  rm -f "$pidfile"
  ok "$name stopped"
}

for svc in "$@"; do
  stop_one "$svc"
done

LEFTOVERS=""
for port in 3003 3002 8000; do
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    LEFTOVERS="$LEFTOVERS  :$port  pid(s) $(lsof -nP -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null | tr '\n' ' ')
"
  fi
done

echo
if [ -n "$LEFTOVERS" ]; then
  echo "Still listening, started outside this script and left alone:"
  printf '%s' "$LEFTOVERS"
  echo
  echo "Stop those yourself if you want a clean slate."
else
  echo "Trojan Errors stack is down."
fi
echo
