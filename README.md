# openhost-peertube

[PeerTube](https://joinpeertube.org) — a federated video platform — packaged
as a single-container OpenHost app.

## What's in the container

* PostgreSQL 15
* Redis 7 (whatever bookworm-main ships)
* PeerTube (`chocobozzz/peertube:production-bookworm`, currently v7.x)
* Caddy 2 (Host-header rewriter mid-tier — see "Auth model" below)
* A small Python auth-proxy sidecar that fronts everything else on
  the OpenHost-router-facing port — see "Auth model" below
* `peertube-plugin-auth-openhost-sso` — a bundled PeerTube plugin
  that registers an external auth method, installed onto the
  running PeerTube on first boot via the standard plugin admin API.
* ffmpeg, invoked on-demand by the PeerTube node process for transcoding
  (it is not a long-lived service)

The five long-lived services — Postgres, Redis, PeerTube, Caddy and
the auth-proxy sidecar — are supervised by a small bash parent
(`start.sh`) that starts them in that order and tears the whole
container down if any one exits. OpenHost notices the exit and
restarts us.

### Auth model: anonymous watch + owner SSO via PeerTube's external-auth API

The container's listening surface looks like this:

```
   OpenHost router (HTTPS)
       │
       ▼
   :9000   auth-proxy sidecar (auth_proxy.py)
       │   ── owner-bounce; pass-through for everyone else
       ▼
   :9090   Caddy (Host-header rewriter)
       │   ── rewrites Host: to X-Forwarded-Host before forwarding
       ▼
   :9001   PeerTube node (the actual app, with the SSO plugin loaded)
```

**Anonymous viewers and federation traffic** pass straight through
all three layers untouched. The OpenHost zone-level auth gate is
disabled (`public_paths = ["/"]` in `openhost.toml`) because remote
ActivityPub servers cannot present a `zone_auth` cookie — gating
federation paths would break inbound follows, video discovery,
comment delivery, and HLS streaming to remote viewers.

**The zone owner** (anyone holding a router-issued `zone_auth` JWT
cookie, `sub == "owner"`) is auto-logged-in via PeerTube's own
external-auth API. Mirroring the openhost-miniflux pattern (where
miniflux's `AUTH_PROXY_HEADER` does the equivalent) and the
openhost-plane.so pattern (where `forward_auth` to `/check-session`
manufactures a Django session): instead of a hand-rolled
localStorage trampoline, the actual sign-in is delegated to
PeerTube's own login flow.

The flow:

1. Owner browser navigates to `https://peertube.<your-zone>/` (or
   any other HTML page on the instance).
2. The auth-proxy sidecar verifies the `zone_auth` cookie against
   the OpenHost router's JWKS (RS256, `sub == "owner"`). On a hit
   AND no `openhost_pt_sso_marker` cookie present, the sidecar
   responds with a 302 to
   `/plugins/auth-openhost-sso/router/auto-login` and a short-TTL
   marker cookie that prevents the bounce from re-firing during
   the redirect chain.
3. That `/auto-login` route is exposed by
   `peertube-plugin-auth-openhost-sso` (the bundled plugin
   installed on first boot). The plugin re-verifies the same
   `zone_auth` cookie against the same JWKS and calls
   PeerTube's `userAuthenticated()` external-auth helper with
   `username=openhost, role=0` (PeerTube's
   `UserRole.Administrator` is the integer `0` in the enum).
   The first SSO sign-in creates a dedicated PeerTube user
   named `openhost` via PeerTube's `createUserFromExternal`;
   subsequent sign-ins for the same zone owner re-use that
   user. The PeerTube installer's auto-generated `root` user
   stays as the break-glass password-login path.
4. PeerTube generates a one-time `externalAuthToken`, stores
   `(token → user)` in an in-memory map for ~5 minutes, and
   redirects the browser to `/login?externalAuthToken=…&username=root`.
5. The PeerTube SPA's standard login page reads those query
   params and POSTs to `/api/v1/users/token` with
   `grant_type=password`, `externalAuthToken=…`. PeerTube swaps
   the bypass token for a normal OAuth access/refresh pair.
6. The SPA's native login flow primes its localStorage with the
   token triple and the four user-identity fields exactly the
   way a regular password login does — no plugin/sidecar gymnastics
   required to track the SPA's internal contract. The SPA then
   navigates to the homepage with the owner logged in as `openhost`
   admin.

**Auto-relogin on session expiry.** The plugin also ships a small
client-side companion script that hooks
`action:auth-user.logged-out` and silently re-trampolines the
browser back through `/plugins/auth-openhost-sso/router/auto-login`
when the SPA's auth state collapses. Without this, an owner whose
OAuth refresh-token has aged out (or whose tokens were invalidated
by a PeerTube restart) sees PeerTube's "Your authentication has
expired, you need to reconnect" toast; with it, the SPA silently
re-logs-in if the owner's `zone_auth` cookie is still valid.
The same path falls through to `/login?externalAuthError=true`
for non-owners, matching what the toast's "reconnect" link would
have done.

The end result: the owner clicks `https://peertube.<your-zone>`
from the OpenHost dashboard and lands directly in the PeerTube
admin UI, already logged in as `openhost`. No password prompt.
The PeerTube mobile app and other third-party clients still work
via the regular username + `admin-password.txt` flow — they get
a plain password login form because they don't carry `zone_auth`.

**Single user.** This package is designed for the typical "personal
PeerTube instance" deployment shape (~20% of all real-world PeerTube
instances are explicitly single-user). The owner's PeerTube identity
is the bootstrap `root` admin. PeerTube's account/channel model is
unchanged — `root` can create unlimited channels (e.g.
`@gaming@peertube.zone`, `@cooking@peertube.zone`, etc.), each
discoverable as a separate ActivityPub actor by remote instances,
all owned by the same login.

**Why a plugin instead of header injection?** PeerTube's SPA
loads its OAuth token from `localStorage`, not from a cookie or
a request header. Stamping `X-Forwarded-User: root` on every
proxied request (the openhost-miniflux pattern) doesn't help
because there's no native PeerTube hook that reads such a
header. The plugin path uses the only API PeerTube provides for
"this visitor is the named user, log them in": the
`registerExternalAuth` callback. PeerTube generates an
externalAuthToken, redirects to its own login form with that
token in the query string, and the SPA's standard login flow
exchanges it for an OAuth pair via `/api/v1/users/token` —
which means PeerTube's native code is what writes localStorage,
not us.

#### Threat model / sanity-check

* The auth-proxy unconditionally strips `X-OpenHost-User` and
  `X-OpenHost-Is-Owner` from inbound requests on every PROXIED
  path. Owner identity is determined exclusively by the JWT
  signature on the `zone_auth` cookie, not by client-supplied
  headers.
* The plugin re-verifies the JWT itself rather than trusting the
  fact that the auth-proxy bounced the request. Belt-and-suspenders:
  if anyone bypasses the auth-proxy and directly hits
  `/plugins/auth-openhost-sso/router/auto-login`, they still need
  a valid owner `zone_auth` cookie to get logged in.
* The marker cookie is `SameSite=Lax; Path=/`, plus `Secure` when
  the connection arrived over HTTPS (always true on the OpenHost
  router; the sidecar omits `Secure` in dev / `lvh.me` setups so
  browsers don't silently drop a Secure cookie over plain HTTP
  and re-trigger the bounce). It carries no privilege — it just
  opts the next visit out of the bounce redirect. A forged
  cookie with the marker pre-set causes the sidecar to skip the
  bounce, but skipping means "leave the request alone" — the
  request is then anonymous to PeerTube unless the browser has
  valid OAuth tokens of its own.
* PeerTube's `externalAuthToken` is a 32-byte random nonce with
  a 5-minute TTL stored in an in-memory map; it can only be
  redeemed once, and the redemption is tied to the username.
  An attacker who somehow steals one would have a 5-minute
  window to log in as `root` once. The token is delivered via
  a `?externalAuthToken=` query parameter (not a header) so
  it appears in browser history and any logging tier that
  records URLs — which is why we keep the TTL tight.

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
sidecar (see "Auth model" above) bounces the zone owner through
PeerTube's external-auth flow. Once the container is healthy, click
the PeerTube tile in your OpenHost dashboard and you'll land
directly in PeerTube's admin UI as the `openhost` user (created on
first SSO sign-in via the bundled plugin). No password prompt. The
first navigation triggers a brief redirect through
`/plugins/auth-openhost-sso/router/auto-login` →
`/login?externalAuthToken=…` and the SPA's native login flow does
the rest; subsequent visits within ~5 minutes skip the bounce
entirely (the marker cookie suppresses it).

**From outside the zone (PeerTube mobile app, third-party clients,
break-glass).** Use the `root` username + the password in
`admin-password.txt`. The `root` user is the auto-generated
PeerTube installer admin; it remains separate from the SSO-managed
`openhost` user so password reset / mobile login keeps working
even if the OpenHost router or the SSO plugin is down.

Read the password from inside the container:

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

A password reset doesn't disturb the SSO flow: the SSO plugin
authenticates the owner against the OpenHost router's JWKS and
then calls PeerTube's `userAuthenticated()` helper, neither of
which involves the admin password. Resetting the password only
affects the `root` + password login form (the break-glass path
above and the path the PeerTube mobile app uses).

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
