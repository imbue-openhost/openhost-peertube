# openhost-peertube

[PeerTube](https://joinpeertube.org) — a federated video platform — packaged
as a single-container OpenHost app.

## What's in the container

* PostgreSQL 15
* Redis 7 (whatever bookworm-main ships)
* PeerTube (`chocobozzz/peertube:production-bookworm`, currently v7.x)
* Caddy 2 (Host-header rewriter mid-tier — see "Auth model" below)
* A small Python auth-proxy sidecar that fronts everything else
  on the OpenHost-router-facing port and bridges the zone owner's
  `zone_auth` cookie to a freshly-minted PeerTube OAuth2 token —
  see "Auth model" below
* ffmpeg, invoked on-demand by the PeerTube node process for transcoding
  (it is not a long-lived service)

The five long-lived services — Postgres, Redis, PeerTube, Caddy and
the auth-proxy sidecar — are supervised by a small bash parent
(`start.sh`) that starts them in that order and tears the whole
container down if any one exits. OpenHost notices the exit and
restarts us.

### Auth model: anonymous watch + owner SSO via trampoline

The container's listening surface looks like this:

```
   OpenHost router (HTTPS)
       │
       ▼
   :9000   auth-proxy sidecar (auth_proxy.py)
       │   ── trampoline-based owner SSO; pass-through for everyone else
       ▼
   :9090   Caddy (Host-header rewriter)
       │   ── rewrites Host: to X-Forwarded-Host before forwarding
       ▼
   :9001   PeerTube node (the actual app)
```

**Anonymous viewers and federation traffic** pass straight through
all three layers untouched. The OpenHost zone-level auth gate is
disabled (`public_paths = ["/"]` in `openhost.toml`) because remote
ActivityPub servers cannot present a `zone_auth` cookie — gating
federation paths would break inbound follows, video discovery,
comment delivery, and HLS streaming to remote viewers.

**The zone owner** (anyone holding a router-issued `zone_auth` JWT
cookie) gets a different experience. When the owner navigates to
the PeerTube web UI, the auth-proxy:

1. Verifies the `zone_auth` cookie against the OpenHost router's
   JWKS (RS256, `sub == "owner"`).
2. Redirects the owner to `/__openhost-sso/login`, a tiny static
   HTML page served by the sidecar itself.
3. That page calls `/__openhost-sso/mint-token` (also sidecar-served),
   which verifies the JWT a second time and then mints a fresh
   PeerTube OAuth2 access token by calling PeerTube's own
   `/api/v1/oauth-clients/local` and `/api/v1/users/token` over
   loopback, using the persisted `admin-password.txt` as the
   service-account credential.
4. The page writes `access_token`, `refresh_token`, and `token_type`
   to `localStorage` — the exact keys PeerTube's Angular SPA reads
   (verified against
   `/app/client/src/root-helpers/users/oauth-user-tokens.ts`
   in the upstream tree).
5. The sidecar's mint-token response sets a marker cookie
   `openhost_pt_sso_until=<unix-ts>` via `Set-Cookie` (the
   browser-side trampoline JS does not touch the cookie itself —
   only `localStorage`). Subsequent visits skip the trampoline
   until the marker expires. The marker is set to expire 1 hour
   before the OAuth token does (so for the typical 24-hour
   PeerTube token the marker lasts ~23 hours), giving the next
   trampoline a fresh opportunity to re-mint while the current
   token still has time left — the SPA never sees a 401 from a
   stale token.
6. Then the JS redirects to the original URL.

The end result: the owner clicks `https://peertube.<your-zone>` from
the OpenHost dashboard and lands directly in the PeerTube admin UI,
already logged in as `root`. No password prompt. The PeerTube mobile
app and other third-party clients still work via the regular
username + `admin-password.txt` flow — they don't see this trampoline.

**Single user.** This package is designed for the typical "personal
PeerTube instance" deployment shape (~20% of all real-world PeerTube
instances are explicitly single-user). The owner's PeerTube identity
is the bootstrap `root` admin. PeerTube's account/channel model is
unchanged — `root` can create unlimited channels (e.g.
`@gaming@peertube.zone`, `@cooking@peertube.zone`, etc.), each
discoverable as a separate ActivityPub actor by remote instances,
all owned by the same login.

#### Threat model / sanity-check

* The auth-proxy unconditionally strips `X-OpenHost-User` and
  `X-OpenHost-Is-Owner` from inbound requests on every path.
  Owner identity is determined exclusively by the JWT signature,
  not by client-supplied headers.
* The `/__openhost-sso/mint-token` endpoint is the only place the
  PeerTube admin password leaves the sidecar process, and it
  reaches only loopback. Without a valid owner JWT the endpoint
  returns 401.
* The trampoline page serves the same HTML to everyone (owner or
  not); only the JSON token endpoint enforces JWT validity. This
  means a non-owner who somehow lands on the trampoline gets a
  graceful 401 + anonymous bounce-through, not an oracle.
* The marker cookie is `SameSite=Lax; Path=/`, plus `Secure` when
  the connection arrived over HTTPS (always true on the OpenHost
  router; the sidecar omits `Secure` in dev / `lvh.me` setups so
  browsers don't silently drop a Secure cookie over plain HTTP
  and re-trigger the trampoline). It carries no privilege — it
  just opts the next visit out of the trampoline redirect. A
  forged cookie with `openhost_pt_sso_until=99999999999` causes
  the sidecar to skip the trampoline, but skipping means "leave
  the request alone" — the request is then anonymous to PeerTube
  unless the browser has the actual token in localStorage.

### Why Caddy is still in the path

Even with the auth-proxy added, Caddy still has the original
Host-header rewriting job: PeerTube's `/api/v1/oauth-clients/local`
handler hard-checks `req.headers.host == webserver.hostname[:port]`
and returns 403 otherwise. The OpenHost router strips the original
Host (httpx sets it to `127.0.0.1:9000`) and stuffs the public
hostname into `X-Forwarded-Host`. Caddy reads `X-Forwarded-Host` and
rewrites `Host` before forwarding. We could do this in Python in
the auth-proxy directly, but Caddy's reverse-proxy layer is rock-solid
and re-implementing it would be a regression risk.

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

**Through the OpenHost zone (preferred path).** The auth-proxy
sidecar (see "Auth model" above) auto-logs the zone owner in. Once
the container is healthy, click the PeerTube tile in your OpenHost
dashboard and you'll land directly in PeerTube's admin UI as the
`root` user. No password prompt. The first navigation triggers a
brief redirect through `/__openhost-sso/login` that mints an OAuth2
token and writes it to `localStorage`; subsequent visits skip the
trampoline until the token is close to expiry.

**From outside the zone (PeerTube mobile app, third-party clients,
break-glass).** Use the `root` username + the password in
`admin-password.txt`. Read it from inside the container:

```
cat /data/app_data/peertube/admin-password.txt
```

(In the OpenHost dashboard's terminal-into-app feature, that path is
exactly where the file lives.) On first boot, our start script logs
the **path** to the password file — `[openhost-peertube] Initial root
admin password is in /data/app_data/peertube/admin-password.txt`.
PeerTube's upstream installer separately logs the **value** of the
password to stdout once during the very first boot only
(`info: User password: ...`), so it appears in `/app_logs/peertube`
until the log rolls over. Treat the in-host log as sensitive on
first boot.

To reset the password later, exec into the container and run:

```
cd /app && gosu peertube npm run reset-password -- -u root
```

If you reset the password, the auth-proxy sidecar's cached
credential is now stale: it'll keep returning HTTP 502 from the SSO
trampoline until the container is restarted (the sidecar reads the
password file once at startup).

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
