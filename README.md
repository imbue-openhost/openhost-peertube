# openhost-peertube

[PeerTube](https://joinpeertube.org) — a federated video platform — packaged
as a single-container OpenHost app.

## What's in the container

* PostgreSQL 15
* Redis 7 (whatever bookworm-main ships)
* PeerTube (`chocobozzz/peertube:production-bookworm`, currently v7.x)
* ffmpeg, invoked on-demand by the PeerTube node process for transcoding
  (it is not a long-lived service)

The three long-lived services — Postgres, Redis, and PeerTube — are
supervised by a small bash parent (`start.sh`) that starts them in
that order and tears the whole container down if any one exits.
OpenHost notices the exit and restarts us.

## ⚠️ Federation hostname is permanent

PeerTube embeds its canonical hostname into:

* every ActivityPub object ID it generates (videos, comments, accounts,
  follows, likes, channels — all of them),
* HTTP-signature key URLs used to authenticate outbound federation
  requests,
* every direct video URL streamed to viewers.

**Once the database has been seeded with a hostname, you cannot change it
without breaking every video URL and every existing federation
relationship.** Remote instances cache our actor objects by IRI and have
no way to learn the new ones.

This package records the hostname on first boot from
`$OPENHOST_ZONE_DOMAIN` + `$OPENHOST_APP_NAME` (so on andrew-1 that's
`peertube.andrew-1.selfhost.imbue.com`) and writes it to
`$OPENHOST_APP_DATA_DIR/hostname`. The cache file is read on every
subsequent boot and is **never overwritten**, even if the OpenHost zone
changes. If you really need to relocate the instance, you have to:

1. Run upstream's [`update-host` script](https://docs.joinpeertube.org/maintain/migration#change-domain-name)
   which rewrites all the IDs in the database.
2. Accept that all federation history (followers, following, remote
   comments) is lost.
3. Wipe the `hostname` cache file and restart.

It is fine to deploy this app in a brand-new zone where you accept the
hostname permanently. It is **not** fine to deploy on a temporary
domain and then move to production.

## Resources

`memory_mb = 2048`, `cpu_millicores = 2000`. At rest Postgres uses
~300 MiB (the start script writes `shared_buffers = 256 MB`), Redis
~80 MiB (capped at 256 MiB max), and the PeerTube node process ~600 MiB.
ffmpeg spikes the rest during transcoding. Two CPU cores let two ffmpeg
threads run in parallel without starving the node event loop.

## Storage

All persistent state lives under `$OPENHOST_APP_DATA_DIR`:

```
postgres/                  PGDATA (initdb on first boot)
redis/                     redis appendonly + RDB
peertube-data/             videos, thumbnails, captions, plugins
secrets/db_password        generated on first boot
secrets/redis_password     generated on first boot
secrets/peertube_secret    generated on first boot — signs HTTP
                           signatures used in federation
admin-password.txt         the auto-generated `root` admin password
hostname                   permanent canonical hostname
```

Scratch state (in-flight uploads, ffmpeg work files) lives under
`$OPENHOST_APP_TEMP_DIR`. It is fine to lose this on container restart.

### Object storage

For a real deploy you'd want to point video/streaming-playlist storage
at S3-compatible object storage:

```
PEERTUBE_OBJECT_STORAGE_ENABLED=true
PEERTUBE_OBJECT_STORAGE_ENDPOINT=...
PEERTUBE_OBJECT_STORAGE_REGION=...
PEERTUBE_OBJECT_STORAGE_CREDENTIALS_ACCESS_KEY_ID=...
PEERTUBE_OBJECT_STORAGE_CREDENTIALS_SECRET_ACCESS_KEY=...
PEERTUBE_OBJECT_STORAGE_STREAMING_PLAYLISTS_BUCKET_NAME=...
PEERTUBE_OBJECT_STORAGE_WEB_VIDEOS_BUCKET_NAME=...
```

This package does not configure object storage — videos are kept on the
local container disk. **Large videos will fill the VM disk fast.**
Capacity-plan accordingly or wire up object storage before you let users
upload.

## Logging in for the first time

The `root` admin password is generated on first boot and written to
`$OPENHOST_APP_DATA_DIR/admin-password.txt`. From inside the container:

```
cat /data/app_data/peertube/admin-password.txt
```

(In the OpenHost dashboard's terminal-into-app feature, that path is
exactly where the file lives.) On first boot, the start script logs the
**path** to the password file — `[openhost-peertube] Initial root admin
password is in /data/app_data/peertube/admin-password.txt` — so the
password value is never written to the container log stream.

To reset the password later, exec into the container and run:

```
cd /app && gosu peertube npm run reset-password -- -u root
```

## What's not configured

* **SMTP** — email-required flows (signup confirmation, password reset)
  are inert. The `root` admin can still log in directly with its
  generated password. Add `PEERTUBE_SMTP_*` env vars to enable email.
* **Open registration** — disabled by default (PeerTube default). Admin
  can create accounts manually via the web UI.
* **Object storage** — see above.

## Trust proxy

The OpenHost router proxies in over loopback. PeerTube is configured
with `PEERTUBE_TRUST_PROXY=["127.0.0.1","loopback"]` so it honours
`X-Forwarded-For` / `X-Forwarded-Proto` / `X-Forwarded-Host` from the
router and constructs federation URLs with the canonical hostname
recorded above.

## Why bash supervisor instead of s6

s6-overlay is the right choice when the upstream base image already
ships it (which is what the openhost-jitsi package does — Jitsi's
upstream Docker images use s6-overlay v1). The PeerTube production
image does not, and bringing s6 in adds a moving part for three
children we can supervise just as well with `wait -n` from bash.
The miniflux package uses the same pattern and has been stable.
