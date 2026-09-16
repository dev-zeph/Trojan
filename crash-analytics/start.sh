#!/usr/bin/env bash
#
# Bring the Trojan Errors stack up.
#
#   Bugsink (storage backend)   :8000
#   Trojan Errors shim          :3002
#   Sample "checkout service"   :3003   (skip with --no-sample)
#
# Idempotent. If something is already listening on a port, this script adopts
# the running service and says so rather than starting a second copy.
#
# Usage:
#   ./crash-analytics/start.sh [--no-sample] [--sample-port N]
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

DATA_DIR="$HERE/.data"
LOG_DIR="$HERE/logs"
RUNTIME_JSON="$HERE/runtime.json"

BUGSINK_PORT="${BUGSINK_PORT:-8000}"
SHIM_PORT="${SHIM_PORT:-3002}"
SAMPLE_PORT="${SAMPLE_PORT:-3003}"

WITH_SAMPLE=1
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-45}"

while [ $# -gt 0 ]; do
  case "$1" in
    --no-sample)   WITH_SAMPLE=0 ;;
    --sample-port) shift; SAMPLE_PORT="${1:?--sample-port needs a value}" ;;
    -h|--help)
      sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^#\{0,1\} \{0,1\}//'
      exit 0 ;;
    *) printf 'Unknown option: %s (try --help)\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[1;32mok\033[0m   %s\n' "$*"; }
info() { printf '    \033[1;33m--\033[0m   %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

mkdir -p "$DATA_DIR" "$LOG_DIR"

# ── 0. Preconditions ──────────────────────────────────────────────────────
if [ ! -f "$RUNTIME_JSON" ]; then
  die "crash-analytics/runtime.json is missing.
       Run ./crash-analytics/setup.sh first, then re-run this script."
fi

command -v node >/dev/null 2>&1 || die "node is not on PATH. Node 22+ is required."

BUGSINK_MANAGE="$HERE/bugsink/.venv/bin/bugsink-manage"
[ -x "$BUGSINK_MANAGE" ] || die "$BUGSINK_MANAGE is missing. Run ./crash-analytics/setup.sh first."

SHIM_ENTRY="$ROOT/backend/src/errors/server.ts"
[ -f "$SHIM_ENTRY" ] || die "$SHIM_ENTRY is missing."

# ── helpers ───────────────────────────────────────────────────────────────

# Is anything listening on this TCP port?
port_busy() {
  lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
}

port_pids() {
  lsof -nP -tiTCP:"$1" -sTCP:LISTEN 2>/dev/null | tr '\n' ' ' | sed 's/ *$//'
}

pid_alive() {
  [ -n "${1:-}" ] && kill -0 "$1" >/dev/null 2>&1
}

# wait_http <url> <timeout-seconds> <allow-3xx:0|1>
# Bugsink answers 302 on /, so it needs allow-3xx.
wait_http() {
  local url="$1" timeout="$2" allow3xx="$3" deadline code
  deadline=$(( $(date +%s) + timeout ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$url" 2>/dev/null || true)"
    case "$code" in
      2??) return 0 ;;
      3??) [ "$allow3xx" = "1" ] && return 0 ;;
    esac
    sleep 0.5
  done
  return 1
}

# launch <name> <port> <workdir> <command...>
launch() {
  local name="$1" port="$2" workdir="$3"; shift 3
  local pidfile="$DATA_DIR/$name.pid"
  local logfile="$LOG_DIR/$name.log"

  if port_busy "$port"; then
    local pids; pids="$(port_pids "$port")"
    if [ -f "$pidfile" ] && pid_alive "$(cat "$pidfile" 2>/dev/null || true)"; then
      info "$name: already running on :$port (pid $(cat "$pidfile")), reusing it"
    else
      info "$name: port :$port is already in use by pid(s) ${pids:-unknown}; reusing that service"
      info "      (not started by this script, so ./crash-analytics/stop.sh will leave it alone)"
      rm -f "$pidfile"
    fi
    return 0
  fi

  # Stale pid file from a process that died.
  if [ -f "$pidfile" ]; then rm -f "$pidfile"; fi

  say "Starting $name on :$port"
  ( cd "$workdir" && exec "$@" ) >>"$logfile" 2>&1 &
  local pid=$!
  echo "$pid" >"$pidfile"
  info "$name: pid $pid, log $logfile"
  return 0
}

fail_with_log() {
  local name="$1" port="$2"
  printf '\033[1;31mERROR:\033[0m %s did not become healthy on :%s within %ss.\n' "$name" "$port" "$HEALTH_TIMEOUT" >&2
  printf '       Last 25 lines of %s/%s.log:\n\n' "$LOG_DIR" "$name" >&2
  tail -n 25 "$LOG_DIR/$name.log" 2>/dev/null | sed 's/^/       /' >&2 || true
  printf '\n       Stop what did start with: ./crash-analytics/stop.sh\n' >&2
  exit 1
}

# ── 1. Bugsink (storage backend) ──────────────────────────────────────────
# bugsink-manage resolves DJANGO_SETTINGS_MODULE from the CWD, so it must run
# from crash-analytics/bugsink.
launch bugsink "$BUGSINK_PORT" "$HERE/bugsink" \
  "$BUGSINK_MANAGE" runserver "$BUGSINK_PORT" --noreload

say "Waiting for Bugsink on :$BUGSINK_PORT"
# Bugsink redirects / to the login page, so 3xx counts as healthy.
wait_http "http://127.0.0.1:$BUGSINK_PORT/" "$HEALTH_TIMEOUT" 1 || fail_with_log bugsink "$BUGSINK_PORT"
ok "Bugsink answering on http://localhost:$BUGSINK_PORT"

# ── 2. Trojan Errors shim ─────────────────────────────────────────────────
# Node 25 runs TypeScript natively. No build step, no tsx, no npm install.
launch shim "$SHIM_PORT" "$ROOT" \
  node backend/src/errors/server.ts

say "Waiting for the Trojan Errors shim on :$SHIM_PORT"
wait_http "http://127.0.0.1:$SHIM_PORT/api/errors/health" "$HEALTH_TIMEOUT" 0 || fail_with_log shim "$SHIM_PORT"
ok "Shim answering on http://localhost:$SHIM_PORT/api/errors/health"

# ── 3. Sample app ─────────────────────────────────────────────────────────
if [ "$WITH_SAMPLE" = "1" ]; then
  if [ ! -d "$HERE/sample-app/node_modules/@sentry/node" ]; then
    die "sample-app dependencies are missing.
       Run: (cd crash-analytics/sample-app && npm install)
       Or start without it: ./crash-analytics/start.sh --no-sample"
  fi

  # The sample app reads PORT, and discovers its DSN from the shim's config
  # endpoint at boot, so nothing is hardcoded.
  export PORT="$SAMPLE_PORT"
  export TROJAN_CONFIG_URL="http://127.0.0.1:$SHIM_PORT/api/errors/config"

  launch sample-app "$SAMPLE_PORT" "$HERE/sample-app" \
    node index.js

  say "Waiting for the sample app on :$SAMPLE_PORT"
  wait_http "http://127.0.0.1:$SAMPLE_PORT/healthz" "$HEALTH_TIMEOUT" 0 || fail_with_log sample-app "$SAMPLE_PORT"
  ok "Sample app answering on http://localhost:$SAMPLE_PORT"
else
  info "sample app skipped (--no-sample)"
fi

# ── 4. Summary ────────────────────────────────────────────────────────────
DSN="$(curl -s --max-time 3 "http://127.0.0.1:$SHIM_PORT/api/errors/config" \
        | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{process.stdout.write(JSON.parse(s).dsn||"")}catch{}})' 2>/dev/null || true)"

echo
printf '\033[1mTrojan Errors is up.\033[0m\n'
echo
echo "  Storage backend (internal)  http://localhost:$BUGSINK_PORT"
echo "  Trojan Errors shim          http://localhost:$SHIM_PORT"
echo "    health                    http://localhost:$SHIM_PORT/api/errors/health"
echo "    config / DSN              http://localhost:$SHIM_PORT/api/errors/config"
echo "    issues                    http://localhost:$SHIM_PORT/api/errors/issues?filter=all"
if [ "$WITH_SAMPLE" = "1" ]; then
  echo "  Sample checkout service     http://localhost:$SAMPLE_PORT"
fi
if [ -n "$DSN" ]; then
  echo "  Customer DSN                $DSN"
fi
echo
echo "  Logs   $LOG_DIR"
echo "  PIDs   $DATA_DIR"
echo
if [ "$WITH_SAMPLE" = "1" ]; then
  printf '\033[1mDrive the demo\033[0m\n'
  echo "  Click the buttons:  open http://localhost:$SAMPLE_PORT"
  echo "  Or from a terminal:"
  echo "      curl -s http://localhost:$SAMPLE_PORT/boom"
  echo "      curl -s http://localhost:$SAMPLE_PORT/boom/db"
  echo "      curl -s http://localhost:$SAMPLE_PORT/boom/async"
  echo "      curl -s \"http://localhost:$SAMPLE_PORT/boom/repeat?n=5\""
  echo "      curl -s -X POST http://localhost:$SAMPLE_PORT/boom/pii"
  echo "  Then read them back:"
  echo "      curl -s \"http://localhost:$SHIM_PORT/api/errors/issues?filter=all\""
fi
echo
echo "  Stop everything this script started:  ./crash-analytics/stop.sh"
