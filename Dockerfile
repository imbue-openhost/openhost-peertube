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
 && rm -rf /var/lib/apt/lists/*

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

# Copy our startup wrapper + Caddyfile. start.sh generates
# DB + Redis + admin passwords on first boot, persists them
# under $OPENHOST_APP_DATA_DIR, and starts postgres, redis,
# Caddy (host-rewriter front-door), and the PeerTube node
# process under a bash supervisor.
COPY start.sh /opt/openhost-peertube/start.sh
COPY Caddyfile /opt/openhost-peertube/Caddyfile
RUN chmod +x /opt/openhost-peertube/start.sh

# OpenHost will route http://peertube.<zone>/... to this port.
# Caddy (the host-rewriter front-door) binds :9000; PeerTube
# itself listens on the loopback at :9001. See Caddyfile and
# the start.sh /config/local.yaml override.
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
