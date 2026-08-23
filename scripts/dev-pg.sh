#!/usr/bin/env bash
#
# dev-pg.sh - manage the local (non-root) PostgreSQL instance for development.
#
# Instance: data dir <project>/target/pgdata, port 55432, log <project>/target/pg.log
# Binaries: <project>/tools/pg/bin (a symlink to the real lib/postgresql/16/bin),
#           with LD_LIBRARY_PATH pointing at <project>/tools/pg/lib when present.
#
# Usage: scripts/dev-pg.sh {init|start|stop|status}

set -euo pipefail

# Resolve the project root relative to this script so it works from any cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PG_BIN="$PROJECT_ROOT/tools/pg/bin"
PG_LIB="$PROJECT_ROOT/tools/pg/lib"
PGDATA="$PROJECT_ROOT/target/pgdata"
PGLOG="$PROJECT_ROOT/target/pg.log"

PORT="${PGPORT:-55432}"
HOST="${PGHOST:-127.0.0.1}"
PGUSER="${PGUSER:-postgres}"

# Expose the bundled binaries and libraries.
export PATH="$PG_BIN:$PATH"
if [ -d "$PG_LIB" ]; then
    export LD_LIBRARY_PATH="$PG_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

PG_CTL="$PG_BIN/pg_ctl"
INITDB="$PG_BIN/initdb"
PSQL="$PG_BIN/psql"

cmd="${1:-}"
shift || true

is_running() {
    "$PG_CTL" -D "$PGDATA" status >/dev/null 2>&1
}

require_data_dir() {
    if [ ! -f "$PGDATA/PG_VERSION" ]; then
        echo "error: data directory '$PGDATA' is not initialized. Run '$0 init' first." >&2
        exit 1
    fi
}

do_init() {
    if [ -d "$PGDATA" ]; then
        if is_running; then
            echo "Stopping running instance before re-initializing..."
            "$PG_CTL" -D "$PGDATA" stop -m fast
        fi
        echo "Removing existing data directory: $PGDATA"
        rm -rf "$PGDATA"
    fi
    mkdir -p "$(dirname "$PGDATA")"
    "$INITDB" -D "$PGDATA" -A trust -U "$PGUSER" --encoding=UTF8 --no-locale
    echo "Initialized PostgreSQL data directory at $PGDATA (port $PORT, log $PGLOG)."
}

do_start() {
    require_data_dir
    if is_running; then
        echo "PostgreSQL is already running on port $PORT."
        return 0
    fi
    "$PG_CTL" -D "$PGDATA" -l "$PGLOG" \
        -o "-p $PORT -c listen_addresses=$HOST -c unix_socket_directories=$PGDATA" \
        start
    echo "PostgreSQL started on ${HOST}:${PORT} (log: $PGLOG)."
}

do_stop() {
    require_data_dir
    if ! is_running; then
        echo "PostgreSQL is not running."
        return 0
    fi
    "$PG_CTL" -D "$PGDATA" stop
}

do_status() {
    require_data_dir
    if is_running; then
        echo "PostgreSQL is running on ${HOST}:${PORT} (data dir: $PGDATA)."
        "$PSQL" -h "$HOST" -p "$PORT" -U "$PGUSER" -d postgres -tAc 'select version();' \
            || true
        return 0
    else
        echo "PostgreSQL is not running (data dir: $PGDATA)."
        return 3
    fi
}

case "$cmd" in
    init)   do_init ;;
    start)  do_start ;;
    stop)   do_stop ;;
    status) do_status ;;
    *)
        echo "Usage: $0 {init|start|stop|status}" >&2
        exit 2
        ;;
esac
