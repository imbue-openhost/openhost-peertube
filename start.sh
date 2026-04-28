#!/bin/bash
# OpenHost-side bootstrap for PeerTube.
#
# Layout:
#   $OPENHOST_APP_DATA_DIR/
#     postgres/                  -- PGDATA (initdb on first boot)
#     redis/                     -- redis appendonly + RDB snapshots
#     peertube-data/             -- /data inside PeerTube (videos,
#                                   thumbnails, plugins, etc.)
#     secrets/db_password        -- generated on first boot
#     secrets/peertube_secret    -- generated on first boot
#     secrets/redis_password     -- generated on first boot
#     admin-password.txt         -- root admin password, generated
#                                   on first boot, surfaced for
#                                   the operator
#     hostname                   -- cached canonical webserver
#                                   hostname; written once and
#                                   never overwritten because
#                                   PeerTube's federation identity
#                                   is permanent at the first
#                                   recorded hostname
#
# We configure PeerTube entirely via PEERTUBE_* env vars rather
# than writing a production.yaml — the upstream image already
# loads its base config from
# /app/support/docker/production/config/production.yaml and the
# adjacent custom-environment-variables.yaml provides env-var
# overrides for every key we care about.
#
# We use `wait -n` so a single failed child takes the whole
# container down and OpenHost notices and restarts us. That
# requires bash, not /bin/sh.
#
# Long-lived children supervised here:
#   * postgres (started via pg_ctl, not a direct shell child;
#     watched by a separate poller that signals us if it dies)
#   * redis-server
#   * the PeerTube node process
#   * Caddy (Host-header rewriter, sits between auth-proxy and PeerTube)
#   * auth-proxy.py (the only listener on the public-facing port;
#     verifies zone_auth on owner HTML navigations and 302-bounces
#     to the in-PeerTube SSO plugin's auto-login route, otherwise
#     reverse-proxies straight through to Caddy)

set -euo pipefail

log() { echo "[openhost-peertube] $*" >&2; }

PERSIST="${OPENHOST_APP_DATA_DIR:-/data/app_data/peertube}"
TEMP="${OPENHOST_APP_TEMP_DIR:-/data/app_temp_data/peertube}"

PG_DATA="$PERSIST/postgres"
REDIS_DIR="$PERSIST/redis"
PEERTUBE_DATA_DIR="$PERSIST/peertube-data"
SECRETS_DIR="$PERSIST/secrets"

# Internal port layout (every listener binds 127.0.0.1 only;
# only the auth-proxy listens on 0.0.0.0:9000 because that's the
# port openhost.toml advertises and the OpenHost router connects
# to from outside the rootless network namespace).
#
#     auth-proxy   :9000   ── public, OpenHost-facing
#       │
#       ▼
#     Caddy        :9090   ── loopback, rewrites Host header
#       │
#       ▼
#     PeerTube     :9001   ── loopback, the actual node app
AUTH_PROXY_LISTEN_PORT=9000
CADDY_PORT=9090

mkdir -p "$PERSIST" "$TEMP" \
         "$PEERTUBE_DATA_DIR" \
         "$SECRETS_DIR" "$REDIS_DIR"

chmod 700 "$SECRETS_DIR"

# -----------------------------------------------------------------
# Resolve canonical hostname
# -----------------------------------------------------------------
# PeerTube embeds the canonical hostname into ActivityPub object
# IDs and into the URLs of every uploaded video. Once the database
# is seeded with a hostname, changing it later breaks federation
# (remote instances can't dereference the old IDs) and breaks
# every existing video URL. So: write the hostname once and keep
# it. If anyone ever wants to move PeerTube to a new hostname,
# they have to use the upstream `update-host` script after
# re-running migrations and accept that all federation history is
# lost.
HOSTNAME_CACHE="$PERSIST/hostname"
if [[ -s "$HOSTNAME_CACHE" ]]; then
    PT_HOSTNAME="$(cat "$HOSTNAME_CACHE")"
    log "Using cached hostname: $PT_HOSTNAME"
elif [[ -n "${OPENHOST_ZONE_DOMAIN:-}" ]]; then
    APP_SUBDOMAIN="${OPENHOST_APP_NAME:-peertube}"
    PT_HOSTNAME="${APP_SUBDOMAIN}.${OPENHOST_ZONE_DOMAIN}"
    # Atomic write so a partial write can't leave the cache in a
    # state that the next boot would mistake for valid.
    TMP_HOSTNAME="${HOSTNAME_CACHE}.tmp.$$"
    printf '%s' "$PT_HOSTNAME" > "$TMP_HOSTNAME"
    mv "$TMP_HOSTNAME" "$HOSTNAME_CACHE"
    log "First boot — recorded hostname: $PT_HOSTNAME (PERMANENT)"
else
    log "FATAL: \$OPENHOST_ZONE_DOMAIN unset and no cached hostname"
    exit 1
fi
if [[ -z "$PT_HOSTNAME" ]]; then
    log "FATAL: hostname cache resolved to empty string"
    exit 1
fi

# Determine HTTPS / port for federation URL construction. In dev
# (lvh.me / localhost) the OpenHost router serves plain HTTP on a
# non-standard port; in production it's HTTPS on 443.
case "${OPENHOST_ZONE_DOMAIN:-}" in
    lvh.me|*.lvh.me|localhost|*.localhost)
        PT_HTTPS="false"
        PT_PORT="80"
        if [[ -n "${OPENHOST_ROUTER_URL:-}" ]]; then
            # Strip the scheme and any path component, leaving
            # `host:port` (or just `host` when port is implicit).
            # Then peel off the trailing port. ${var##*:} returns
            # the unmodified string when there's no `:`, so guard
            # with both a substring test and a numeric regex
            # before trusting the extracted value.
            HOSTPORT="${OPENHOST_ROUTER_URL#*://}"
            HOSTPORT="${HOSTPORT%%/*}"
            ROUTER_PORT="${HOSTPORT##*:}"
            if [[ "$HOSTPORT" == *:* && "$ROUTER_PORT" =~ ^[0-9]+$ ]]; then
                PT_PORT="$ROUTER_PORT"
            fi
        fi
        ;;
    *)
        PT_HTTPS="true"
        PT_PORT="443"
        ;;
esac

# -----------------------------------------------------------------
# Generate / load shared secrets
# -----------------------------------------------------------------
# All three secrets are persisted on first boot and re-loaded
# verbatim on every subsequent boot. Rotating them in place is
# unsafe: the DB password is encoded into PeerTube's session
# tokens, and the peertube secret signs HTTP signature keys for
# federation.

# Persist a secret on first boot, return its value on every boot.
# Generates a 32-character hex secret by default. Pass `admin` for
# a URL-safe base64-style password (used for the root admin).
# Atomic-write so a `set -e`-aborted openssl call can never leave
# a half-written secret behind for a later boot to misread.
gen_secret() {
    local file="$1" kind="${2:-hex32}"
    if [[ ! -f "$file" ]]; then
        local tmp="${file}.tmp.$$"
        case "$kind" in
            hex24)
                openssl rand -hex 24 > "$tmp"
                ;;
            hex32)
                openssl rand -hex 32 > "$tmp"
                ;;
            admin)
                # 18 raw bytes -> 24 base64 chars; strip the
                # non-URL-safe characters (=, +, /). Net length
                # ~22 chars after stripping: still well above
                # PeerTube's 6-char minimum.
                openssl rand -base64 18 | tr -d '=+/\n' > "$tmp"
                ;;
            *)
                log "FATAL: unknown gen_secret kind: $kind"
                rm -f "$tmp"
                exit 1
                ;;
        esac
        if [[ ! -s "$tmp" ]]; then
            rm -f "$tmp"
            log "FATAL: secret generator produced empty output for $file"
            exit 1
        fi
        chmod 600 "$tmp"
        mv "$tmp" "$file"
    fi
    # Surface corruption rather than hand a zero-length secret to
    # postgres / redis / PeerTube.
    if [[ ! -s "$file" ]]; then
        log "FATAL: secret $file exists but is empty; refusing to use it"
        exit 1
    fi
    cat "$file"
}

DB_PASSWORD="$(gen_secret "$SECRETS_DIR/db_password" hex24)"
REDIS_PASSWORD="$(gen_secret "$SECRETS_DIR/redis_password" hex24)"
PEERTUBE_SECRET_VAL="$(gen_secret "$SECRETS_DIR/peertube_secret" hex32)"

# Admin password: PeerTube reads PT_INITIAL_ROOT_PASSWORD on the
# very first DB seed (see server/core/initializers/installer.ts
# in the upstream tree — that file checks for the env var before
# falling back to a randomly generated one). On subsequent boots
# the env var is ignored because PeerTube only seeds the root
# user once.
ADMIN_PW_FILE="$PERSIST/admin-password.txt"
PT_ADMIN_PW="$(gen_secret "$ADMIN_PW_FILE" admin)"
# gen_secret only logs on failure; emit a friendly message on
# the very first boot so the operator knows where to look.
if [[ ! -e "$SECRETS_DIR/.admin-pw-announced" ]]; then
    log "Initial root admin password is in $ADMIN_PW_FILE"
    : > "$SECRETS_DIR/.admin-pw-announced"
fi

# -----------------------------------------------------------------
# Initialize Postgres on first boot
# -----------------------------------------------------------------
# We run Postgres on a unix socket in /run/postgresql (only
# accessible inside the container) plus localhost TCP for
# PeerTube — PeerTube uses pg through node-postgres which expects
# a TCP host:port pair (no unix socket support in the production
# config schema).
mkdir -p "$PG_DATA"
chown -R postgres:postgres "$PG_DATA"
mkdir -p /run/postgresql
chown postgres:postgres /run/postgresql

if [[ ! -f "$PG_DATA/PG_VERSION" ]]; then
    log "Initializing PostgreSQL cluster at $PG_DATA"
    # initdb requires the target dir to be empty *and* owned by
    # the postgres user (not just writable). The chown above
    # handles the latter.
    su postgres -c "/usr/lib/postgresql/15/bin/initdb -D '$PG_DATA' \
        --auth-local=peer --auth-host=md5 \
        --encoding=UTF8 --locale=C.UTF-8"

    # Tighten pg_hba: only md5 over loopback TCP (PeerTube), and
    # peer over the unix socket (us, when we createuser/createdb).
    cat > "$PG_DATA/pg_hba.conf" <<'EOF'
# TYPE  DATABASE  USER  ADDRESS         METHOD
local   all       all                   peer
host    all       all   127.0.0.1/32    md5
host    all       all   ::1/128         md5
EOF

    # Tune for an in-container Postgres: small but reasonable
    # buffers, keep TCP listener on localhost only, log to
    # stderr so the OpenHost log pipeline picks it up.
    cat >> "$PG_DATA/postgresql.conf" <<'EOF'

# OpenHost overrides
listen_addresses = '127.0.0.1'
unix_socket_directories = '/run/postgresql'
shared_buffers = 256MB
work_mem = 8MB
maintenance_work_mem = 64MB
max_connections = 50
log_destination = 'stderr'
logging_collector = off
EOF
fi

# Clean up stale postmaster.pid from unclean shutdown
rm -f "$PG_DATA/postmaster.pid"

log "Starting PostgreSQL"
PG_LOG="$PG_DATA/postgresql.log"
su postgres -c "/usr/lib/postgresql/15/bin/pg_ctl -D '$PG_DATA' -l '$PG_LOG' -w start \
    -o '-k /run/postgresql'"

# Create peertube DB + user on first boot (idempotent).
DB_USER="peertube"
DB_NAME="peertube_prod"

# Run psql admin commands as the postgres OS user via the unix
# socket. We use `runuser` (util-linux, present in bookworm) to
# drop privileges without spawning a login shell.
#
# For DDL that contains the generated DB_PASSWORD, we write the
# statements to a mode-0600 file owned by postgres and pass that
# file with `psql -f`. This keeps the password out of:
#   * argv  — psql -c is not used for password-bearing DDL,
#             so /proc/<pid>/cmdline never contains the secret.
#   * env   — env vars work but psql's :'name' interpolation
#             only expands psql-side variables (set with -v
#             name=value), not OS env vars. Using -v would put
#             the password back into argv. The temp-file route
#             is the only approach that meets both constraints.
PSQL_BASE=(psql -h /run/postgresql --no-psqlrc -X -v ON_ERROR_STOP=1)

psql_postgres() {
    # Run psql with the supplied args (no password leakage by caller).
    runuser -u postgres -- "${PSQL_BASE[@]}" "$@"
}

run_password_sql() {
    # Args: SQL with literal placeholders __DBUSER__ and __DBPW__.
    # We materialise the SQL into a per-boot tmp file with 0600
    # perms, owned by postgres, run psql -f, then unlink. The
    # subshell-scoped EXIT trap guarantees the file is removed
    # even if psql fails — `set -euo pipefail` would otherwise
    # exit the start.sh leaving the rendered SQL (with embedded
    # password) on disk for forensic recovery.
    local sql_template="$1"
    (
        local sql_file
        # mktemp creates the file with mode 0600 by default; we
        # chown it to postgres so psql can read it after runuser
        # drops privileges. The file lives just long enough to
        # be read by psql once.
        sql_file="$(mktemp -p "$TEMP" peertube-ddl.XXXXXX.sql)"
        trap 'rm -f "$sql_file"' EXIT
        chmod 600 "$sql_file"
        chown postgres:postgres "$sql_file"
        local rendered
        rendered="${sql_template//__DBUSER__/$DB_USER}"
        rendered="${rendered//__DBPW__/$DB_PASSWORD}"
        printf '%s\n' "$rendered" > "$sql_file"
        psql_postgres -f "$sql_file"
    )
}

if ! psql_postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1; then
    log "Creating peertube database role"
    # CAUTION: __DBPW__ is interpolated as a SQL string literal.
    # The hex-only output of `openssl rand -hex` cannot contain a
    # single quote, so we don't need additional escaping. If the
    # generator is ever changed to emit other characters, this
    # path must also start escaping single quotes.
    run_password_sql "CREATE USER \"__DBUSER__\" WITH PASSWORD '__DBPW__';"
fi
# Always re-set the password to the current secret to recover
# from operator-side rotation of secrets/db_password. Idempotent.
run_password_sql "ALTER USER \"__DBUSER__\" WITH PASSWORD '__DBPW__';"

if ! psql_postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" | grep -q 1; then
    log "Creating $DB_NAME database"
    psql_postgres -c "CREATE DATABASE $DB_NAME OWNER $DB_USER"
fi

# PeerTube needs unaccent + pg_trgm extensions. They must be
# created by a superuser (postgres), not the peertube role.
psql_postgres -d "$DB_NAME" -c 'CREATE EXTENSION IF NOT EXISTS unaccent'
psql_postgres -d "$DB_NAME" -c 'CREATE EXTENSION IF NOT EXISTS pg_trgm'

# -----------------------------------------------------------------
# Start Redis
# -----------------------------------------------------------------
# Generate a minimal redis.conf each boot. Redis runs as the
# `redis` user (created by the apt package) with appendonly
# persistence under $PERSIST/redis.
chown -R redis:redis "$REDIS_DIR"

REDIS_CONF="$REDIS_DIR/redis.conf"
# Redis stores requirepass in plaintext, so the conf file must
# not be world-readable. Create with a restrictive umask in a
# subshell, then explicitly chmod 600 in case the umask doesn't
# stick on this filesystem.
(
    umask 077
    cat > "$REDIS_CONF" <<EOF
bind 127.0.0.1 -::1
port 6379
unixsocket /run/redis/redis.sock
unixsocketperm 770
dir $REDIS_DIR
appendonly yes
appendfilename "appendonly.aof"
dbfilename dump.rdb
requirepass $REDIS_PASSWORD
# Redis spawns AOF rewrite children. Keep their working dir under
# $REDIS_DIR so they don't leak into /tmp.
maxmemory 256mb
# noeviction is REQUIRED by PeerTube's bull queue (and by Redis
# generally for any system using it as a job/state store, not
# a cache). With allkeys-lru, Redis will silently drop pending
# upload chunks, federation outbox jobs, and live-stream state
# to stay under maxmemory — corrupting PeerTube's behaviour
# in subtle ways.
maxmemory-policy noeviction
# Run in foreground; supervisor relies on stdout for process
# liveness and signal forwarding.
daemonize no
loglevel notice
EOF
)
chmod 600 "$REDIS_CONF"
chown redis:redis "$REDIS_CONF"
mkdir -p /run/redis && chown redis:redis /run/redis

# Centralised "stop the postgres daemon if it's running" helper
# used by both the early-exit teardown (Redis or PeerTube failed
# to start) and the supervisor `teardown` (a child died after
# everything was up). pg_ctl stop -m fast flushes WAL and exits
# cleanly even if the postmaster never came up; the `|| true`
# absorbs that benign failure.
stop_postgres() {
    su postgres -c \
        "/usr/lib/postgresql/15/bin/pg_ctl -D '$PG_DATA' -m fast -w stop" \
        2>/dev/null || true
}

# Helper used by all the early-exit code paths below (Redis,
# PeerTube, or Caddy never came up). Mirrors the eventual
# `teardown` function used by the supervisor proper. Defined
# here because it's referenced by the readiness-check failure
# branches; the supervisor `teardown` is defined later because
# it depends on $PG_WATCHER_PID which doesn't exist yet.
#
# Each child PID is checked-then-killed if set, so callers
# don't need to know which children have started by the time
# they hit a failure. Variables not yet assigned are absorbed
# by `${...:-}` so `set -u` doesn't trip.
early_exit_teardown() {
    for child in "${PEERTUBE_PID:-}" "${REDIS_PID:-}" \
                 "${CADDY_PID:-}" "${AUTH_PROXY_PID:-}"; do
        if [[ -n "$child" ]]; then
            kill -TERM "$child" 2>/dev/null || true
        fi
    done
    # Postgres outlives this start.sh as an orphan daemon
    # otherwise (the container runtime would eventually reap
    # it, but stopping it here flushes WAL).
    stop_postgres
}

log "Starting Redis"
# Drop privileges to the `redis` user via runuser so the path is
# parsed once by *our* shell (not re-parsed by su's spawned
# shell, which would word-split a $REDIS_CONF that contains
# spaces). With `runuser -u redis -- redis-server "$REDIS_CONF"`
# we hand redis-server its argv directly.
runuser -u redis -- redis-server "$REDIS_CONF" &
REDIS_PID=$!

redis_ping() {
    # Pass the Redis password via REDISCLI_AUTH so it doesn't
    # land in argv (and therefore /proc/<pid>/cmdline and `ps`
    # output) every readiness-check iteration. redis-cli reads
    # this env var natively when -a is absent.
    REDISCLI_AUTH="$REDIS_PASSWORD" \
        redis-cli --no-auth-warning -h 127.0.0.1 -p 6379 \
        ping 2>/dev/null | grep -q PONG
}

# Wait for Redis to come up before starting PeerTube — PeerTube
# crash-exits if its initial Redis connect fails.
REDIS_READY=0
for _ in $(seq 1 30); do
    if redis_ping; then
        REDIS_READY=1
        break
    fi
    sleep 0.5
done
if [[ "$REDIS_READY" -ne 1 ]]; then
    log "FATAL: Redis didn't come up in 15s"
    early_exit_teardown
    exit 1
fi

# -----------------------------------------------------------------
# Configure PeerTube via env vars
# -----------------------------------------------------------------
# The upstream image's NODE_CONFIG_DIR is
#   /app/config:/app/support/docker/production/config:/config
# so /app/support/docker/production/config/production.yaml is the
# base config (which sets `database.hostname: postgres` etc.) and
# the env-mapping in custom-environment-variables.yaml in the same
# dir overrides specific keys from PEERTUBE_* env vars at startup.
# We rely entirely on env vars; no need to write production.yaml.

export PEERTUBE_DB_HOSTNAME=127.0.0.1
export PEERTUBE_DB_PORT=5432
export PEERTUBE_DB_USERNAME="$DB_USER"
export PEERTUBE_DB_PASSWORD="$DB_PASSWORD"
export PEERTUBE_DB_NAME="$DB_NAME"
export PEERTUBE_DB_SSL=false

export PEERTUBE_REDIS_HOSTNAME=127.0.0.1
export PEERTUBE_REDIS_PORT=6379
export PEERTUBE_REDIS_AUTH="$REDIS_PASSWORD"

# PeerTube runs on 9001 internally; the auth-proxy on 9000 fronts
# Caddy on 9090 fronts PeerTube on 9001 (see openhost.toml + the
# README.md "Auth model" section for the full topology and the
# rationale for the auth-proxy mid-tier).
#
# The v7.3.0 production image's custom-environment-variables.yaml
# does NOT map PEERTUBE_LISTEN_PORT — that mapping was added on
# the develop branch but is not in any released tag. So we have
# to write a small per-boot YAML override into the
# $PEERTUBE_LOCAL_CONFIG=/config directory which node-config
# layers on top of the production.yaml. The directory is set
# via the upstream Dockerfile's
#   ENV NODE_CONFIG_DIR /app/config:/app/support/docker/production/config:/config
# so anything we drop in /config wins.
LOCAL_CONFIG_DIR=/config
mkdir -p "$LOCAL_CONFIG_DIR"
chown peertube:peertube "$LOCAL_CONFIG_DIR"
cat > "$LOCAL_CONFIG_DIR/local.yaml" <<'EOF'
listen:
  hostname: 127.0.0.1
  port: 9001
EOF
chown peertube:peertube "$LOCAL_CONFIG_DIR/local.yaml"
chmod 644 "$LOCAL_CONFIG_DIR/local.yaml"

export PEERTUBE_WEBSERVER_HOSTNAME="$PT_HOSTNAME"
export PEERTUBE_WEBSERVER_PORT="$PT_PORT"
export PEERTUBE_WEBSERVER_HTTPS="$PT_HTTPS"

# trust_proxy is JSON-format per the upstream config schema. We
# trust loopback because that is exactly where the OpenHost router
# proxies in from inside the rootless network namespace.
export PEERTUBE_TRUST_PROXY='["127.0.0.1","loopback"]'

export PEERTUBE_SECRET="$PEERTUBE_SECRET_VAL"

# Make storage paths land inside our persistent peertube-data dir.
# The upstream production.yaml uses relative paths like
# `../data/avatars/` interpreted from /app, which would map them
# to /data inside the container — but on OpenHost /data is the
# OpenHost data root, not specifically PeerTube's. We point each
# storage root explicitly at $PEERTUBE_DATA_DIR/<subdir>.
mkdir -p \
    "$PEERTUBE_DATA_DIR/tmp-persistent" \
    "$PEERTUBE_DATA_DIR/bin" \
    "$PEERTUBE_DATA_DIR/avatars" \
    "$PEERTUBE_DATA_DIR/web-videos" \
    "$PEERTUBE_DATA_DIR/streaming-playlists" \
    "$PEERTUBE_DATA_DIR/original-video-files" \
    "$PEERTUBE_DATA_DIR/redundancy" \
    "$PEERTUBE_DATA_DIR/logs" \
    "$PEERTUBE_DATA_DIR/previews" \
    "$PEERTUBE_DATA_DIR/thumbnails" \
    "$PEERTUBE_DATA_DIR/storyboards" \
    "$PEERTUBE_DATA_DIR/torrents" \
    "$PEERTUBE_DATA_DIR/captions" \
    "$PEERTUBE_DATA_DIR/cache" \
    "$PEERTUBE_DATA_DIR/plugins" \
    "$PEERTUBE_DATA_DIR/well-known" \
    "$PEERTUBE_DATA_DIR/uploads" \
    "$PEERTUBE_DATA_DIR/client-overrides"

# /tmp is on app_temp_data — it's huge and ephemeral, perfect for
# in-flight uploads and ffmpeg scratch space.
PEERTUBE_TMP_DIR="$TEMP/peertube-tmp"
mkdir -p "$PEERTUBE_TMP_DIR"

export PEERTUBE_STORAGE_TMP="$PEERTUBE_TMP_DIR"
export PEERTUBE_STORAGE_TMP_PERSISTENT="$PEERTUBE_DATA_DIR/tmp-persistent"
export PEERTUBE_STORAGE_BIN="$PEERTUBE_DATA_DIR/bin"
export PEERTUBE_STORAGE_AVATARS="$PEERTUBE_DATA_DIR/avatars"
export PEERTUBE_STORAGE_WEB_VIDEOS="$PEERTUBE_DATA_DIR/web-videos"
export PEERTUBE_STORAGE_STREAMING_PLAYLISTS="$PEERTUBE_DATA_DIR/streaming-playlists"
export PEERTUBE_STORAGE_ORIGINAL_VIDEO_FILES="$PEERTUBE_DATA_DIR/original-video-files"
export PEERTUBE_STORAGE_REDUNDANCY="$PEERTUBE_DATA_DIR/redundancy"
export PEERTUBE_STORAGE_LOGS="$PEERTUBE_DATA_DIR/logs"
export PEERTUBE_STORAGE_PREVIEWS="$PEERTUBE_DATA_DIR/previews"
export PEERTUBE_STORAGE_THUMBNAILS="$PEERTUBE_DATA_DIR/thumbnails"
export PEERTUBE_STORAGE_STORYBOARDS="$PEERTUBE_DATA_DIR/storyboards"
export PEERTUBE_STORAGE_TORRENTS="$PEERTUBE_DATA_DIR/torrents"
export PEERTUBE_STORAGE_CAPTIONS="$PEERTUBE_DATA_DIR/captions"
export PEERTUBE_STORAGE_CACHE="$PEERTUBE_DATA_DIR/cache"
export PEERTUBE_STORAGE_PLUGINS="$PEERTUBE_DATA_DIR/plugins"
export PEERTUBE_STORAGE_WELL_KNOWN="$PEERTUBE_DATA_DIR/well-known"
export PEERTUBE_STORAGE_UPLOADS="$PEERTUBE_DATA_DIR/uploads"
export PEERTUBE_STORAGE_CLIENT_OVERRIDES="$PEERTUBE_DATA_DIR/client-overrides"

# First-boot admin password. PeerTube only reads this env var
# when its installer hasn't seeded the application table yet, so
# leaving it set on subsequent boots is safe — it's a no-op.
export PT_INITIAL_ROOT_PASSWORD="$PT_ADMIN_PW"

# Provide an admin email so password-reset emails would have a
# from-address set if SMTP is later configured. Setting it now
# means the operator can later add SMTP and existing accounts
# already have an admin contact recorded. We use a noreply at the
# canonical hostname — purely a placeholder.
: "${PEERTUBE_ADMIN_EMAIL:=admin@${PT_HOSTNAME}}"
export PEERTUBE_ADMIN_EMAIL

# -----------------------------------------------------------------
# Ensure peertube user can write to data dirs
# -----------------------------------------------------------------
# The upstream image runs PeerTube as the `peertube` system user
# (uid 999). $PEERTUBE_DATA_DIR was created by us as root above;
# fix ownership so node can write to it. We do this every boot to
# self-heal any external `chown` mishaps.
chown -R peertube:peertube \
    "$PEERTUBE_DATA_DIR" \
    "$PEERTUBE_TMP_DIR"

# -----------------------------------------------------------------
# Start PeerTube
# -----------------------------------------------------------------
# Drop privileges to peertube via gosu (already in the base image).
# We pass --max-old-space-size to give node enough heap for video
# upload buffering; PeerTube's own docs recommend 1500 MiB on a
# 2 GiB host.
log "Starting PeerTube on $PT_HOSTNAME (loopback :9001)"
cd /app
gosu peertube node --max-old-space-size=1500 dist/server &
PEERTUBE_PID=$!

# Wait for PeerTube to start listening on its loopback port
# before we put Caddy in front of it. Caddy bootstraps in
# ~100ms and the OpenHost router begins health-checking
# immediately; if Caddy is up but PeerTube isn't, the router
# sees 502s and may give up before PeerTube has finished
# its initial DB migrate + Sequelize sync (which can take
# 30-60s on first boot).
log "Waiting for PeerTube to listen on 127.0.0.1:9001"
PT_READY=0
for _ in $(seq 1 120); do
    if ! kill -0 "$PEERTUBE_PID" 2>/dev/null; then
        log "FATAL: PeerTube node process exited during startup"
        early_exit_teardown
        exit 1
    fi
    # /dev/tcp is a bash builtin: opens a TCP probe and exits 0
    # if the connect handshake completes. Avoids depending on
    # `nc` which isn't always installed.
    if (echo > /dev/tcp/127.0.0.1/9001) 2>/dev/null; then
        PT_READY=1
        break
    fi
    sleep 1
done
if [[ "$PT_READY" -ne 1 ]]; then
    log "FATAL: PeerTube didn't bind 127.0.0.1:9001 within 120s"
    early_exit_teardown
    exit 1
fi
log "PeerTube is listening; bringing up Caddy"

# -----------------------------------------------------------------
# Start Caddy (host-rewriter mid-tier)
# -----------------------------------------------------------------
# Caddy binds :9090 (loopback only — the auth-proxy sidecar is
# what actually listens on the OpenHost-router-facing port 9000)
# and proxies every request to PeerTube on 127.0.0.1:9001 with
# the Host header reconstituted from X-Forwarded-Host. This
# satisfies PeerTube's hard-coded canonical-Host check on
# /api/v1/oauth-clients/local without needing to dig that
# behaviour out of upstream.
#
# Caddy is a static binary; start it under nobody to avoid having
# yet another running-as-root daemon. The bookworm package ships
# a `caddy` system user we could use, but `nobody` is universal
# and Caddy doesn't need persistent state for this config.
log "Starting Caddy host-rewriter on :${CADDY_PORT} -> :9001"
# Caddy uses XDG_CONFIG_HOME / XDG_DATA_HOME to find a writable
# directory for autosave state. Under `runuser -u nobody` the
# default points at /nonexistent which (correctly) doesn't
# exist. Point both at $TEMP — Caddy needs neither for our
# stateless reverse-proxy config but logs a noisy error every
# boot otherwise.
CADDY_HOME="$TEMP/caddy-home"
mkdir -p "$CADDY_HOME"
chmod 1777 "$CADDY_HOME"
XDG_CONFIG_HOME="$CADDY_HOME" XDG_DATA_HOME="$CADDY_HOME" \
    HOME="$CADDY_HOME" \
    runuser -u nobody --preserve-environment -- caddy run \
        --config /opt/openhost-peertube/Caddyfile \
        --adapter caddyfile &
CADDY_PID=$!

# Caddy startup is fast (~100ms) but give it a moment to bind
# the port before the OpenHost router's first health check.
# Bail loudly if it never came up — without Caddy the whole
# stack is unreachable.
sleep 1
if ! kill -0 "$CADDY_PID" 2>/dev/null; then
    log "FATAL: Caddy exited before supervisor started"
    early_exit_teardown
    exit 1
fi

# -----------------------------------------------------------------
# Install + configure the OpenHost SSO PeerTube plugin
# -----------------------------------------------------------------
# The plugin lives in /opt/openhost-peertube/peertube-plugin-auth-openhost-sso/
# (copied in by the Dockerfile) and is installed into the running
# PeerTube via the standard plugin admin API.  Mirroring the
# pattern openhost-miniflux uses for AUTH_PROXY_HEADER and
# openhost-plane.so uses for its check-session sidecar:
# the app's own auth machinery is what logs the user in.  The
# sidecar's only job is bouncing the owner browser to the
# plugin's auto-login URL on first visit.
#
# We talk to the PeerTube admin API as the root user using the
# admin password generated above.  Idempotent: we read the
# current plugin list first and skip install if already present.
# Same for the openhost-router-url setting — we always re-PUT it
# because OPENHOST_ROUTER_URL can change across container
# restarts (e.g. when the operator moves to a new host).

export PLUGIN_DIR=/opt/openhost-peertube/peertube-plugin-auth-openhost-sso
PLUGIN_NPM_NAME=peertube-plugin-auth-openhost-sso

if [[ -z "${OPENHOST_ROUTER_URL:-}" ]]; then
    log "FATAL: \$OPENHOST_ROUTER_URL is not set; the SSO plugin needs it"
    log "  to fetch the OpenHost router's JWKS for owner JWT verification."
    log "  This variable is normally injected by OpenHost; if it isn't,"
    log "  the openhost-core deployment is broken."
    early_exit_teardown
    exit 1
fi

# Mint a short-lived OAuth token for the local root user — exactly
# the same flow PeerTube's own admin UI uses on login.  The token
# is good for ~24h; we use it for a few seconds and let it expire
# naturally.
log "Minting admin OAuth token for plugin install"
PT_LOOPBACK="http://127.0.0.1:9001"

# Helper: curl with the canonical Host header so PeerTube's
# /api/v1/oauth-clients/local handler accepts the request.  That
# endpoint enforces a strict Host == webserver.hostname check;
# the loopback connect would otherwise fail with 403.
case "$PT_HTTPS:$PT_PORT" in
    true:443|false:80)
        CANONICAL_HOST="$PT_HOSTNAME"
        ;;
    *)
        CANONICAL_HOST="$PT_HOSTNAME:$PT_PORT"
        ;;
esac

# Wait for /api/v1/oauth-clients/local to respond — first-boot
# Sequelize sync can lag the TCP-listen by ~30s.  We poll up to
# 120 seconds in 1-second increments and explicitly fail if
# PeerTube never becomes ready, instead of falling through to
# the next curl with an empty / error body that would only
# surface as an opaque KeyError further down.
log "Waiting for PeerTube /api/v1/oauth-clients/local"
PT_API_READY=0
for _ in $(seq 1 120); do
    code=$(curl -sS -o /dev/null -w '%{http_code}' \
        -H "Host: $CANONICAL_HOST" \
        "$PT_LOOPBACK/api/v1/oauth-clients/local" || true)
    if [[ "$code" == "200" ]]; then
        PT_API_READY=1
        break
    fi
    sleep 1
done
if [[ "$PT_API_READY" -ne 1 ]]; then
    log "FATAL: PeerTube /api/v1/oauth-clients/local never returned 200 in 120s"
    early_exit_teardown
    exit 1
fi

# Helper: parse a JSON path from stdin and emit the value.  Wraps
# the python3 inline so a non-JSON / unexpected-shape upstream
# response surfaces as a clean operator-readable FATAL log line
# rather than an opaque KeyError traceback that the supervisor
# captures further along.  The path is a list of keys/indices
# (passed as separate argv entries) so callers don't have to
# string-mangle their own JSON path.
#
# We pass the script via ``python3 -c`` (NOT ``python3 -`` with a
# heredoc) because the heredoc form would feed the heredoc into
# python's stdin, which is the same channel ``json.load`` wants
# to read the JSON body from.  ``-c`` keeps stdin available for
# the JSON.
parse_json_field() {
    # Args: a stream-friendly description for logs ("plugins.list"
    # etc.), then 1+ keys describing the path.  Reads JSON from
    # stdin; emits the leaf value to stdout.  On any failure
    # returns 1 and logs FATAL — caller should propagate via
    # early_exit_teardown + exit.
    local label="$1"
    shift
    python3 -c '
import json, sys
label = sys.argv[1]
keys = sys.argv[2:]
try:
    data = json.load(sys.stdin)
except json.JSONDecodeError as exc:
    sys.stderr.write(f"[openhost-peertube] FATAL: {label}: response is not JSON: {exc}\n")
    sys.exit(1)
node = data
for k in keys:
    try:
        if isinstance(node, list):
            node = node[int(k)]
        else:
            node = node[k]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        sys.stderr.write(
            f"[openhost-peertube] FATAL: {label}: missing key {k!r} "
            f"(have keys={list(node.keys()) if isinstance(node, dict) else type(node).__name__})\n"
        )
        sys.exit(1)
if not isinstance(node, (str, int, float)):
    sys.stderr.write(
        f"[openhost-peertube] FATAL: {label}: leaf value is "
        f"{type(node).__name__}, expected scalar\n"
    )
    sys.exit(1)
print(node)
' "$label" "$@"
}

# HTTP helper: send a request to PeerTube on the loopback,
# capture the body + status code, and surface non-2xx / transport
# failures as clean FATAL log lines (returning 1) instead of
# letting ``set -e`` abort the script with no context and orphan
# the rest of the supervised children.
#
# Usage:
#     body=$(_pt_curl <label> <method> <bearer-or-empty> <url> \
#                     <ok-codes> [<content-type>] [<body>])
#
#  * ``label``        — short identifier for the FATAL log line.
#  * ``method``       — HTTP method (GET/POST/PUT/DELETE...).
#  * ``bearer``       — empty string or the OAuth access token.
#  * ``url``          — full URL.
#  * ``ok-codes``     — space-separated HTTP codes treated as
#                       success.  Anything else is a FATAL.
#  * ``content-type`` — optional; required for methods with bodies.
#  * ``body``         — optional request body, fed to curl on
#                       stdin via ``--data-binary @-`` so the
#                       value never lands in argv (and therefore
#                       /proc/<pid>/cmdline).
#
# stderr is left attached to the parent's stderr (curl with -sS
# emits transport-error diagnostics there); we deliberately do
# NOT merge stderr into the captured stdout because doing so
# could let a curl warning printed AFTER the HTTP body throw
# off the response splitter, which extracts the HTTP code as
# the LAST line of stdout.  Transport failures still surface
# via curl's non-zero exit code, which we check.
_pt_curl() {
    local label="$1" method="$2" bearer="$3" url="$4" ok_codes="$5"
    local content_type="${6:-}"
    local body="${7-}"

    # Per-call timeout.  Default 30s is enough for the OAuth
    # token mint and the settings PUT.  The plugin-install call
    # legitimately takes much longer because PeerTube's
    # ``pnpm add file:<path>`` reaches the npm registry to pull
    # the plugin's runtime deps; callers override the default
    # via the ``PT_CURL_MAX_TIME`` env var when they need more.
    local max_time="${PT_CURL_MAX_TIME:-30}"

    local -a curl_args=(curl -sS -w '\n%{http_code}'
        --connect-timeout 10
        --max-time "$max_time"
        -X "$method"
        -H "Host: $CANONICAL_HOST")
    if [[ -n "$bearer" ]]; then
        curl_args+=(-H "Authorization: Bearer $bearer")
    fi
    if [[ -n "$content_type" ]]; then
        curl_args+=(-H "Content-Type: $content_type")
    fi
    if [[ $# -ge 7 ]]; then
        curl_args+=(--data-binary @-)
    fi
    curl_args+=("$url")

    # Capture the substitution exit status without ``set -e``
    # killing the script before our explicit FATAL-log path runs.
    # Bash's ``set -e`` exits on a non-zero command substitution
    # in a plain assignment; the ``|| status=$?`` idiom (with
    # ``status`` initialised to 0) absorbs the failure into a
    # variable while still letting us branch on it explicitly.
    local raw status=0
    if [[ $# -ge 7 ]]; then
        raw=$(printf '%s' "$body" | "${curl_args[@]}") || status=$?
    else
        raw=$("${curl_args[@]}") || status=$?
    fi
    if [[ $status -ne 0 ]]; then
        log "FATAL: $label: curl transport failure (exit $status)"
        return 1
    fi
    local code resp
    code="${raw##*$'\n'}"
    resp="${raw%$'\n'*}"

    local matched=0
    for ok in $ok_codes; do
        if [[ "$code" == "$ok" ]]; then matched=1; break; fi
    done
    if [[ $matched -ne 1 ]]; then
        log "FATAL: $label: HTTP $code (expected one of: $ok_codes): $resp"
        return 1
    fi
    printf '%s' "$resp"
}

# Fetch + parse the OAuth client_id/client_secret.  Stash the
# JSON body in a variable first so we can run two parses against
# the SAME response; a per-parse curl invocation could race a
# client-creds rotation (rare but possible — PeerTube rotates
# the local client creds across restarts).
OAUTH_CLIENT_JSON=$(_pt_curl "oauth-clients.local" GET "" \
    "$PT_LOOPBACK/api/v1/oauth-clients/local" "200") || {
    early_exit_teardown
    exit 1
}
PT_CLIENT_ID=$(printf '%s' "$OAUTH_CLIENT_JSON" | parse_json_field oauth-clients.local client_id) || {
    early_exit_teardown
    exit 1
}
PT_CLIENT_SECRET=$(printf '%s' "$OAUTH_CLIENT_JSON" | parse_json_field oauth-clients.local client_secret) || {
    early_exit_teardown
    exit 1
}

# POST to /api/v1/users/token with grant_type=password.  Pass the
# admin password through stdin (--data-binary @-) so it never
# lands in argv.
#
# URL-encoding: the form-urlencoded body MUST escape any reserved
# characters (``+ = & %``) in the field values.  ``PT_ADMIN_PW``
# is generated from ``openssl rand -base64 18 | tr -d '=+/\n'``
# (see gen_secret() above) so it can ONLY contain the unreserved
# base64 alphabet minus =+/ — i.e. ``[A-Za-z0-9]`` — which is
# percent-encoding-safe verbatim.  But we still encode every
# field defensively because:
#  * client_id / client_secret are PeerTube-generated random
#    strings; the upstream code uses ``crypto.randomBytes`` →
#    base64 encoded, so they too can carry =+/ that would
#    fail to parse on the server.
#  * a future change to gen_secret() that enables a different
#    alphabet must NOT silently break this code path.
url_encode() {
    # Pass the secret via env var rather than argv so it never
    # appears in /proc/<pid>/cmdline for the duration of the
    # python3 process (visible to anyone with read access to
    # the procfs entry).  Same defensive pattern as the rest
    # of the file uses for password-bearing commands.
    URL_ENCODE_INPUT="$1" python3 -c '
import os, urllib.parse
print(urllib.parse.quote(os.environ["URL_ENCODE_INPUT"], safe=""))
'
}
TOKEN_BODY=$(printf 'client_id=%s&client_secret=%s&grant_type=password&response_type=code&username=root&password=%s' \
    "$(url_encode "$PT_CLIENT_ID")" \
    "$(url_encode "$PT_CLIENT_SECRET")" \
    "$(url_encode "$PT_ADMIN_PW")")
TOKEN_JSON=$(_pt_curl "users.token" POST "" \
    "$PT_LOOPBACK/api/v1/users/token" "200" \
    "application/x-www-form-urlencoded" "$TOKEN_BODY") || {
    early_exit_teardown
    exit 1
}
PT_ACCESS_TOKEN=$(printf '%s' "$TOKEN_JSON" | parse_json_field users.token access_token) || {
    log "FATAL: could not obtain PeerTube admin token for plugin install"
    early_exit_teardown
    exit 1
}

# Check whether the plugin is already installed.  The
# single-resource lookup ``GET /api/v1/plugins/<npmName>``
# returns 200 with the plugin's metadata if installed, or 404
# otherwise — avoids paginating the full plugin list (which
# could miss us on an instance with hundreds of installed
# plugins) AND lets us decide install-or-skip from a single
# request.
#
# We accept both 200 and 404 as "not a fatal error".  The body
# shape disambiguates: PeerTube's plugin object always carries
# a non-empty ``name`` field, so the presence of that field in
# a successfully parsed JSON object is the marker for
# "installed".  An error response (404) is also valid JSON
# (``{error: ...}``) which lacks ``name``.
LOOKUP_BODY=$(_pt_curl "plugins.lookup" GET "$PT_ACCESS_TOKEN" \
    "$PT_LOOPBACK/api/v1/plugins/$PLUGIN_NPM_NAME" \
    "200 404") || {
    early_exit_teardown
    exit 1
}
INSTALLED=$(printf '%s' "$LOOKUP_BODY" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except json.JSONDecodeError:
    print("no")
    sys.exit(0)
print("yes" if isinstance(data, dict) and data.get("name") else "no")
')

if [[ "$INSTALLED" == "yes" ]]; then
    log "Plugin auth-openhost-sso already installed"
else
    log "Installing plugin auth-openhost-sso from $PLUGIN_DIR"
    INSTALL_PAYLOAD=$(python3 -c 'import json,os; print(json.dumps({"path": os.environ["PLUGIN_DIR"]}))')
    # Bump the per-call timeout: PeerTube installs plugins via
    # ``pnpm add file:<path>``, which fetches the plugin's
    # runtime deps (jsonwebtoken, jwks-rsa) from the npm
    # registry.  Network round-trips to npm + pnpm's hash
    # verification dominate the time; 5 minutes is a generous
    # ceiling that still produces a clean FATAL log on a
    # genuinely-stuck install instead of hanging boot
    # indefinitely.
    PT_CURL_MAX_TIME=300 _pt_curl "plugins.install" POST "$PT_ACCESS_TOKEN" \
        "$PT_LOOPBACK/api/v1/plugins/install" \
        "200 204" \
        "application/json" "$INSTALL_PAYLOAD" >/dev/null || {
        early_exit_teardown
        exit 1
    }
fi

# Always re-set the openhost-router-url setting.  PeerTube
# accepts a JSON body of {settings: {<name>: <value>}} on
# PUT /api/v1/plugins/<npmName>/settings.  Even if the value
# hasn't changed across boots the PUT triggers
# settingsManager.onSettingsChange in the plugin, which
# re-builds the JWKS client — useful in case the operator
# rotated keys on the OpenHost router side without restarting
# us.
log "Configuring plugin (router URL: $OPENHOST_ROUTER_URL)"
SETTINGS_PAYLOAD=$(python3 -c "import json,os; print(json.dumps({'settings': {'openhost-router-url': os.environ['OPENHOST_ROUTER_URL']}}))")
_pt_curl "plugins.settings" PUT "$PT_ACCESS_TOKEN" \
    "$PT_LOOPBACK/api/v1/plugins/$PLUGIN_NPM_NAME/settings" \
    "204" \
    "application/json" "$SETTINGS_PAYLOAD" >/dev/null || {
    early_exit_teardown
    exit 1
}

# -----------------------------------------------------------------
# Start auth-proxy sidecar (OpenHost zone_auth → SSO bounce)
# -----------------------------------------------------------------
# The sidecar binds the public-facing port (9000) on behalf of
# the OpenHost router.  Two responsibilities:
#   * Pass-through proxy for federation + anonymous + asset
#     traffic.
#   * Owner bounce: when an HTML navigation arrives carrying
#     a verified ``zone_auth`` cookie and no marker cookie, the
#     sidecar 302-redirects the browser to the plugin's
#     auto-login route.  The plugin verifies the same JWT and
#     calls userAuthenticated, which redirects to
#     /login?externalAuthToken=… and the SPA finishes the login
#     via PeerTube's native flow.
#
# Runs as a dedicated ``openhost-authproxy`` user (not ``nobody``
# and not the same user as Caddy).  Least-privilege: isolating
# every container daemon to its own UID means a compromise of
# any one process can't read another's data files.

log "Starting auth-proxy sidecar on :${AUTH_PROXY_LISTEN_PORT} -> Caddy :${CADDY_PORT}"

AUTH_PROXY_LOG_LEVEL="${AUTH_PROXY_LOG_LEVEL:-INFO}" \
AUTH_PROXY_LISTEN_PORT="$AUTH_PROXY_LISTEN_PORT" \
AUTH_PROXY_UPSTREAM_HOST="127.0.0.1" \
AUTH_PROXY_UPSTREAM_PORT="$CADDY_PORT" \
OPENHOST_ROUTER_URL="$OPENHOST_ROUTER_URL" \
    runuser -u openhost-authproxy --preserve-environment -- \
        python3 /opt/openhost-peertube/auth_proxy.py &
AUTH_PROXY_PID=$!

# Wait for the auth-proxy to bind :9000.  Same probe pattern as
# Caddy.  If this never comes up the OpenHost router can't reach
# us at all and the container is unreachable, so fail loudly.
AP_READY=0
for _ in $(seq 1 30); do
    if ! kill -0 "$AUTH_PROXY_PID" 2>/dev/null; then
        log "FATAL: auth-proxy exited during startup"
        early_exit_teardown
        exit 1
    fi
    if (echo > /dev/tcp/127.0.0.1/$AUTH_PROXY_LISTEN_PORT) 2>/dev/null; then
        AP_READY=1
        break
    fi
    sleep 0.5
done
if [[ "$AP_READY" -ne 1 ]]; then
    log "FATAL: auth-proxy didn't bind 127.0.0.1:$AUTH_PROXY_LISTEN_PORT in 15s"
    early_exit_teardown
    exit 1
fi

# -----------------------------------------------------------------
# Supervisor
# -----------------------------------------------------------------
# Forward SIGTERM/SIGINT to all four direct children (PeerTube,
# Redis, Caddy, auth-proxy) plus the postgres postmaster. We
# don't track postmaster's PID directly (pg_ctl starts it as a
# daemonized child of postgres) so we send the signal via
# pg_ctl stop on shutdown. The four others have their PIDs.
#
# Renamed from the more obvious `shutdown` to avoid shadowing
# /usr/sbin/shutdown — a future maintainer who wants to
# system-halt the container would otherwise silently call this
# function instead.
PG_WATCHER_PID=""
TEARDOWN_DONE=0
teardown() {
    # Bash invokes the trap and the explicit post-`wait` cleanup
    # consecutively when the supervisor receives SIGTERM during
    # `wait -n`. Guard against the second invocation so we don't
    # log "Shutting down children" twice or send superfluous
    # signals into pid-recycled territory.
    if [[ "$TEARDOWN_DONE" -eq 1 ]]; then
        return
    fi
    TEARDOWN_DONE=1
    log "Shutting down children"
    if [[ -n "$PG_WATCHER_PID" ]]; then
        kill -TERM "$PG_WATCHER_PID" 2>/dev/null || true
    fi
    kill -TERM "$PEERTUBE_PID" "$REDIS_PID" "$CADDY_PID" \
        "$AUTH_PROXY_PID" 2>/dev/null || true
    stop_postgres
    wait || true
}
trap teardown TERM INT

# `wait -n` blocks until any of the bash-tracked children exits.
# Postgres is daemonized so it isn't in our wait set; we have to
# poll its postmaster.pid separately. We use a tiny background
# poller that signals SIGTERM to ourselves if Postgres ever exits
# unexpectedly so the supervisor unwinds.
(
    while true; do
        sleep 5
        if [[ ! -f "$PG_DATA/postmaster.pid" ]]; then
            log "Postgres died unexpectedly; tearing down"
            kill -TERM $$
            exit 0
        fi
    done
) &
PG_WATCHER_PID=$!

set +e
wait -n "$PEERTUBE_PID" "$REDIS_PID" "$CADDY_PID" "$AUTH_PROXY_PID"
EXIT_CODE=$?
set -e

# Identify which child died for diagnostics. By the time we get
# here at least one of the four pids is gone; the others may
# still be alive (the supervisor will TERM them in teardown).
DEAD=""
for tag_pid in \
        "peertube=$PEERTUBE_PID" \
        "redis=$REDIS_PID" \
        "caddy=$CADDY_PID" \
        "auth-proxy=$AUTH_PROXY_PID"; do
    tag="${tag_pid%%=*}"
    pid="${tag_pid##*=}"
    if ! kill -0 "$pid" 2>/dev/null; then
        DEAD="${DEAD:+$DEAD,}$tag"
    fi
done
log "Child exited (code=$EXIT_CODE, dead=${DEAD:-unknown}); shutting down container"
teardown
exit "$EXIT_CODE"
