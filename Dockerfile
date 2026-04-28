# PeerTube — federated video platform — packaged for OpenHost.
#
# We start from the upstream production image (which contains node 22,
# ffmpeg, the compiled PeerTube application at /app, and a `peertube`
# system user) and layer PostgreSQL + Redis on top so the whole stack
# runs in a single OpenHost-managed container.
#
# Why a single container? OpenHost runs one container per app and
# hands each app a single port. Splitting Postgres, Redis and PeerTube
# into separate containers would require introducing the OpenHost
# `cross_app_services` machinery — heavier, and the database is so
# tightly coupled to PeerTube's lifecycle that bundling is the right
# call here. This mirrors the openhost-miniflux pattern (Postgres +
# app in one container, supervised by a bash parent) extended with
# Redis. We considered s6-overlay (the openhost-jitsi pattern) but
# stuck with bash because the upstream PeerTube image does not ship
# s6 and pulling it in adds a moving part for three children.
#
# Image tag pin: production-bookworm == latest stable v7.x on
# Debian bookworm. We pin to a Debian release because we install
# postgresql-15 and redis-server from the bookworm apt repo on top
# and the package versions need to match the base distro.

FROM chocobozzz/peertube:production-bookworm

# We need to install system packages, so escalate from the
# upstream image's USER peertube back to root for this stage.
USER root

ARG DEBIAN_FRONTEND=noninteractive

# PostgreSQL 15 ships in bookworm-main; redis-server too. gosu is
# already in the base image (used by the upstream entrypoint to
# drop privileges to the peertube user).
#
# We also install:
#   * postgresql-contrib-15 — provides extensions PeerTube needs
#     (notably `unaccent` and `pg_trgm`, both required by the
#     migration that creates the search index).
#   * tini — a tiny init that reaps zombie children. Bash's `wait`
#     handles signal forwarding for the three processes we start
#     directly, but Postgres and Redis fork sub-processes whose
#     parents may exit; tini ensures none of them become zombies
#     under PID 1 and that SIGTERM propagates cleanly.
#   * procps — `ps` for diagnostics; cheap to ship.
#   * util-linux — provides `runuser`, used in start.sh to drop
#     privileges without spawning a login shell (su would
#     re-parse the command via a shell, which word-splits paths
#     containing spaces).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        postgresql-15 \
        postgresql-contrib-15 \
        postgresql-client-15 \
        redis-server \
        tini \
        procps \
        util-linux \
        caddy \
        python3 \
        python3-jwt \
        python3-requests \
        python3-cryptography \
 && rm -rf /var/lib/apt/lists/*

# Dedicated unprivileged user/group for the auth-proxy sidecar.
# We don't share the ``nobody`` user with Caddy because Caddy is
# also long-lived in this container and we want the auth-proxy's
# admin-password.txt to be readable ONLY by the auth-proxy
# process — not by every other "running as nobody" process.
# A dedicated user keeps the principle of least privilege: even
# if Caddy gets a remote-code execution bug, it can't read the
# PeerTube admin credential.
RUN groupadd --system openhost-authproxy \
 && useradd --system --no-create-home --shell /usr/sbin/nologin \
        --gid openhost-authproxy openhost-authproxy

# Postgres' Debian package ships a "main" cluster auto-created at
# install time under /var/lib/postgresql/15/main. We don't want
# that — our start script initdb's a fresh cluster under
# $OPENHOST_APP_DATA_DIR/postgres on first boot. Drop the
# auto-created cluster so it can't accidentally be started.
RUN if [ -d /var/lib/postgresql/15/main ]; then \
        pg_dropcluster --stop 15 main || rm -rf /var/lib/postgresql/15/main; \
    fi \
 && mkdir -p /run/postgresql \
 && chown postgres:postgres /run/postgresql

# Redis: clear out the Debian-shipped /etc/redis config and the
# default /var/lib/redis dir; our start script writes a minimal
# redis.conf at boot pointing at $OPENHOST_APP_DATA_DIR/redis.
RUN rm -rf /var/lib/redis/* /etc/redis/redis.conf || true

# Copy our startup wrapper + Caddyfile + auth-proxy sidecar +
# the bundled SSO plugin.
#
# start.sh generates DB + Redis + admin passwords on first boot,
# persists them under $OPENHOST_APP_DATA_DIR, starts postgres,
# redis, the PeerTube node process, Caddy (host-rewriter
# mid-tier), and the Python auth-proxy sidecar.  After PeerTube
# is up, start.sh authenticates as root and installs/configures
# the bundled ``peertube-plugin-auth-openhost-sso`` plugin via
# the standard PeerTube admin API — this is the plugin that
# implements the actual owner-sign-in flow via PeerTube's
# native ``registerExternalAuth`` machinery.  Five long-lived
# processes plus the in-PeerTube plugin, supervised by a single
# bash parent with `wait -n`.
COPY start.sh /opt/openhost-peertube/start.sh
COPY Caddyfile /opt/openhost-peertube/Caddyfile
COPY auth_proxy.py /opt/openhost-peertube/auth_proxy.py
COPY peertube-plugin-auth-openhost-sso /opt/openhost-peertube/peertube-plugin-auth-openhost-sso
RUN chmod +x /opt/openhost-peertube/start.sh \
 # The plugin install API hands the path to PeerTube which calls
 # ``pnpm add file:<path>``.  pnpm runs as the peertube user so
 # the path must be readable by that user.  /opt/...-sso is
 # owned by root by default; chown so peertube can read.
 && chown -R peertube:peertube \
        /opt/openhost-peertube/peertube-plugin-auth-openhost-sso

# OpenHost will route http://peertube.<zone>/... to this port.
# The auth-proxy sidecar (auth_proxy.py) binds :9000.  Behind it,
# Caddy on loopback :9090 rewrites the Host header for the SPA's
# canonical-Host check, and PeerTube itself listens on loopback
# :9001.  See auth_proxy.py module docstring + Caddyfile + the
# start.sh /config/local.yaml override.
EXPOSE 9000

# ENTRYPOINT inherited from the base image is the upstream
# entrypoint.sh which does `chown -R peertube:peertube /data /config`
# and then `gosu peertube "$@"`. We DO NOT want that behaviour
# here because:
#   1. We need to start postgres + redis as their own users (not
#      peertube) and we need to remain root long enough to set up
#      ownership on $OPENHOST_APP_DATA_DIR/{postgres,redis}.
#   2. The blanket chown of /data is wrong — /data is the OpenHost
#      data root and contains subdirs owned by other users
#      (postgres, redis).
# Override both ENTRYPOINT and CMD to point at our own start.sh
# wrapped in tini for proper signal handling and zombie reaping.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/opt/openhost-peertube/start.sh"]
