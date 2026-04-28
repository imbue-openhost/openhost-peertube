"""OpenHost auth-sidecar for PeerTube — owner SSO without breaking federation.

Two rails, mirroring the openhost-nextcloud pattern but adapted to
PeerTube's localStorage-based OAuth2 client:

1. Anonymous + federation (the default).  Almost every URL on a
   PeerTube instance is reachable without login: a remote Mastodon
   server fetches an actor object, an anonymous browser watches a
   public video, the federated player downloads HLS chunks, the
   bittorrent tracker accepts WebTorrent peers.  All of these paths
   pass through this sidecar untouched — same body, same headers,
   no SSO header injected, no Authorization header rewritten.

2. Owner SSO via trampoline.  When the zone owner (someone holding
   a router-issued ``zone_auth`` JWT cookie) navigates to the SPA
   root or to a known-protected path, the sidecar serves a tiny
   self-contained HTML page from ``/__openhost-sso/login`` that:
       * receives a freshly minted PeerTube OAuth2 access token
         from the sidecar (the sidecar speaks PeerTube's own
         /api/v1/oauth-clients/local + /api/v1/users/token API,
         using the persisted ``admin-password.txt`` as a
         service-account credential just on the loopback);
       * writes ``access_token``, ``refresh_token``, ``token_type``
         to localStorage — the exact keys the PeerTube SPA reads
         (see /app/client/src/root-helpers/users/oauth-user-tokens.ts);
       * sets a marker cookie ``openhost_pt_sso_until=<unix-ts>``
         scoped to ``/`` so subsequent visits skip the trampoline
         until the marker expires;
       * redirects to the original URL.
   On subsequent visits, the marker cookie is present and unexpired,
   so the sidecar passes the request through untouched and the SPA
   reads the still-valid token from localStorage on its own.

The trampoline is the SPA-friendly equivalent of nextcloud's
header-stamping SSO.  PeerTube stores its OAuth token in
``localStorage`` (not a cookie) so we have no choice but to bridge
through a one-time client-side write.  Mastodon uses the same trick
in its various SSO plugins.

Why not just always inject ``Authorization: Bearer <token>`` on
proxied requests?  The SPA running in the browser does not know we
did that — it would still show the "Login" button, fetch the user's
own profile as anonymous, etc.  The trampoline is what propagates
the token into the browser's localStorage so the SPA's own auth
state machine sees the user as logged in.

Federation is wholly unaffected: federation requests come from
remote ActivityPub servers that don't carry zone_auth, don't go
through the trampoline, and don't see any rewriting at this layer.

Anonymous web visitors are also unaffected: with no zone_auth
cookie, the trampoline is never triggered and they get the standard
anonymous PeerTube experience.

Header sanitation: client-supplied ``X-OpenHost-User`` and
``X-OpenHost-Is-Owner`` headers are stripped on every request,
matching the openhost-nextcloud defence.  ``Authorization`` is
ALSO stripped on the trampoline path (otherwise a hostile remote
could send a forged Bearer in their request and have the
trampoline page echo it back in localStorage).
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
import socket
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

import jwt
import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ZONE_COOKIE = "zone_auth"
JWKS_PATH = "/.well-known/jwks.json"
JWKS_REFRESH_INTERVAL_SEC = 600

# SSO trampoline path.  Two underscores at the start by convention to
# minimise the chance of clashing with a real PeerTube route.  PeerTube
# does not currently route anything matching ``/__openhost-sso/*``.
SSO_BASE = "/__openhost-sso"
SSO_LOGIN_PATH = f"{SSO_BASE}/login"
SSO_TOKEN_PATH = f"{SSO_BASE}/mint-token"   # internal JSON endpoint
SSO_LOGOUT_PATH = f"{SSO_BASE}/logout"

# Marker cookie set by the trampoline so subsequent visits skip the
# round-trip.  Value is the unix epoch of expiry; presence-and-not-
# yet-expired is the trigger.
SSO_MARKER_COOKIE = "openhost_pt_sso_until"

# When we mint a PeerTube token, peer-tube returns ``expires_in`` in
# seconds (typically ~86400).  We refresh proactively when half the
# token's life is gone — anchored to the actual expires_in returned
# by PeerTube so a future change to PeerTube's token TTL doesn't
# strand us.
SSO_MIN_TOKEN_REMAINING_SEC = 60 * 60   # less than one hour left → re-mint

# Maximum number of bytes to copy in a single chunk between client and
# upstream.  64 KiB is comfortably below typical socket buffer sizes.
STREAM_CHUNK_BYTES = 64 * 1024

# Total time we'll spend reading/writing a single request, beyond which
# the connection is torn down.  Generous because PeerTube uploads can
# legitimately take many minutes for large videos on slow networks.
STREAM_TIMEOUT_SECONDS = 30 * 60

# Maximum size we'll readline() for an upstream response status line
# or response header.
HEADER_LINE_CAP = 64 * 1024

# Hop-by-hop headers (RFC 9110 §7.6.1) plus a few entries we rewrite
# ourselves at the proxy seam.
HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        "Host",
        "Content-Length",
    )
)

# Trust headers that a hostile client could try to forge.  ALWAYS
# stripped from inbound requests, even on bypass paths, before any
# routing decision.  Same defence as openhost-nextcloud.
ALWAYS_STRIP_HEADERS = frozenset(
    h.lower() for h in (
        "X-OpenHost-User",
        "X-Openhost-User",       # both casings, just in case
        "X-OpenHost-Is-Owner",
        "X-Openhost-Is-Owner",
    )
)

# ---------------------------------------------------------------------------
# Federation surface — paths that NEVER trigger the trampoline.
#
# These are the URL families a remote ActivityPub server, a federated
# video player on another instance, or an anonymous web viewer needs
# to reach.  They are wholly orthogonal to owner-SSO; we still strip
# trust headers and do not stamp Authorization on these paths.
#
# We don't NEED to enumerate every public path here — for an anonymous
# visitor with no zone_auth cookie, the trampoline isn't triggered
# anyway, so the bypass list is only relevant to OWNER traffic.  But
# being explicit about which paths skip the trampoline avoids
# surprising a Mastodon-server-behind-its-own-zone or an owner who
# happens to be following another zone account into accidentally
# bouncing through the SSO flow when they request remote content.
# ---------------------------------------------------------------------------
FEDERATION_PATH_PATTERNS = [
    # ActivityPub actor/object surface, per the upstream docs at
    # https://docs.joinpeertube.org/api/activitypub.  Every one of
    # these endpoints must be reachable without auth so remote
    # instances can dereference IDs.  Note that ``/videos`` is
    # NOT on this list — only the specific subpaths PeerTube
    # actually exposes as ActivityPub objects (``/videos/watch``
    # is the canonical Video object IRI, ``/videos/embed`` is the
    # iframe-embeddable player).  ``/videos/upload`` and
    # ``/videos/manage`` are SPA admin routes that benefit from
    # the trampoline; including them under a wildcard would skip
    # the trampoline incorrectly.
    re.compile(r"^/accounts(/|$)"),
    re.compile(r"^/video-channels(/|$)"),
    re.compile(r"^/videos/watch(/|$)"),
    re.compile(r"^/videos/embed(/|$)"),
    re.compile(r"^/video-playlists(/|$)"),
    re.compile(r"^/static(/|$)"),
    re.compile(r"^/lazy-static(/|$)"),
    re.compile(r"^/.well-known(/|$)"),
    re.compile(r"^/nodeinfo(/|$)"),
    re.compile(r"^/feeds(/|$)"),
    re.compile(r"^/tracker(/|$)"),
    re.compile(r"^/api/v1/ping$"),
    # The OAuth bootstrap endpoints — anonymous, used by the SPA's
    # own login flow and by any third-party app needing to
    # authenticate.  The trampoline ITSELF calls these (loopback)
    # to mint the owner's token; if we trampolined them we'd
    # infinite-loop.
    re.compile(r"^/api/v1/oauth-clients(/|$)"),
    re.compile(r"^/api/v1/users/token$"),
    re.compile(r"^/api/v1/users/revoke-token$"),
    # SPA assets — anonymous viewers need these to load the
    # client.  Asset paths are loaded with Accept: */* anyway so
    # the trampoline filter wouldn't fire on them, but listing
    # them explicitly is documentation-as-code.
    re.compile(r"^/client(/|$)"),
    re.compile(r"^/themes(/|$)"),
    re.compile(r"^/plugins(/|$)"),
    re.compile(r"^/manifest\.webmanifest$"),
    re.compile(r"^/main-[A-Z0-9]+\.js$"),
    re.compile(r"^/polyfills-[A-Z0-9]+\.js$"),
    re.compile(r"^/styles-[A-Z0-9]+\.css$"),
    re.compile(r"^/chunk-[A-Z0-9]+\.js$"),
    # The PeerTube live-streaming WebSocket and the WebRTC tracker.
    re.compile(r"^/socket\.io(/|$)"),
]


def _is_federation_path(path: str) -> bool:
    """True if ``path`` is part of PeerTube's federation/anonymous surface.

    The argument is the raw HTTP request-target ``BaseHTTPRequestHandler``
    receives (including any query string).  We split on ``?`` and ``#``
    before regex-matching so e.g. ``/static/web-videos/foo.mp4?q=1``
    matches ``^/static(/|$)``.
    """
    path_only = path.split("?", 1)[0].split("#", 1)[0]
    return any(p.match(path_only) for p in FEDERATION_PATH_PATTERNS)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


# ---------------------------------------------------------------------------
# JWKS cache + JWT verification (ported from openhost-nextcloud)
# ---------------------------------------------------------------------------
class JwksCache:
    """Fetches the OpenHost router's JWKS and caches it with stale fallback.

    On a successful fetch, keys are cached for JWKS_REFRESH_INTERVAL_SEC.
    On a failed refresh we keep serving the previously-cached keys
    rather than failing closed, so a transient router blip doesn't
    lock the owner out.
    """

    def __init__(self, router_url: str) -> None:
        self._router_url = router_url.rstrip("/")
        self._keys: list = []
        self._fetched_at: float = 0.0
        self._cache_lock = threading.Lock()
        self._fetch_lock = threading.Lock()

    def _fetch(self) -> list:
        url = f"{self._router_url}{JWKS_PATH}"
        with requests.get(url, timeout=5) as resp:
            resp.raise_for_status()
            jwks = resp.json()
        keys = []
        skipped = 0
        for jwk in jwks.get("keys", []):
            try:
                key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
            except Exception as exc:  # noqa: BLE001
                skipped += 1
                kid = jwk.get("kid") if isinstance(jwk, dict) else None
                log.warning("skipping malformed JWK (kid=%s): %s", kid, exc)
                continue
            keys.append(key)
        if not keys:
            raise RuntimeError(
                f"router JWKS contains no usable keys (skipped {skipped})"
            )
        return keys

    def get(self) -> list:
        with self._cache_lock:
            cached_keys = self._keys
            cached_at = self._fetched_at
        if cached_keys and (time.time() - cached_at) < JWKS_REFRESH_INTERVAL_SEC:
            return cached_keys
        with self._fetch_lock:
            with self._cache_lock:
                cached_keys = self._keys
                cached_at = self._fetched_at
            if cached_keys and (time.time() - cached_at) < JWKS_REFRESH_INTERVAL_SEC:
                return cached_keys
            try:
                keys = self._fetch()
            except Exception as exc:  # noqa: BLE001 - log+fallback
                if cached_keys:
                    log.warning(
                        "JWKS refresh failed, using cached keys: %s", exc
                    )
                    return cached_keys
                log.warning("JWKS fetch failed and no cache: %s", exc)
                raise
            now = time.time()
            with self._cache_lock:
                self._fetched_at = now
                self._keys = keys
            log.info("refreshed JWKS (%d key(s))", len(keys))
            return keys

    def prefetch(self) -> None:
        try:
            self.get()
        except Exception as exc:  # noqa: BLE001
            log.warning("initial JWKS prefetch failed (will retry on demand): %s", exc)


def _parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    """Parse an RFC6265 Cookie header into {name: value} (first-wins)."""
    if not cookie_header:
        return {}
    result: dict[str, str] = {}
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        result.setdefault(name.strip(), value.strip())
    return result


def _verify_owner(token: str, jwks: JwksCache) -> bool:
    """Return True if the JWT is a valid router-signed owner token."""
    if not token:
        return False
    try:
        keys = jwks.get()
    except Exception as exc:  # noqa: BLE001
        log.warning("JWKS unavailable; denying owner check: %s", exc)
        return False
    last_error: jwt.PyJWTError | None = None
    decode_succeeded = False
    last_sub: str | None = None
    for key in keys:
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                options={"require": ["exp"], "verify_aud": False},
            )
        except jwt.PyJWTError as exc:
            last_error = exc
            continue
        decode_succeeded = True
        if claims.get("sub") == "owner":
            return True
        last_sub = claims.get("sub")
    if decode_succeeded:
        log.debug("JWT verified but sub=%r != 'owner'; denying", last_sub)
    elif last_error is not None:
        log.debug(
            "JWT verification failed against all %d JWKS key(s): %s: %s",
            len(keys), type(last_error).__name__, last_error,
        )
    return False


# ---------------------------------------------------------------------------
# PeerTube OAuth2 bridge
# ---------------------------------------------------------------------------
class PeerTubeOauthBridge:
    """Mints OAuth2 access tokens for the ``root`` PeerTube user.

    PeerTube's standard local OAuth2 flow is a two-step:
        1. GET /api/v1/oauth-clients/local
           returns {"client_id": "...", "client_secret": "..."}
           (these rotate on PeerTube startup but only those two
           values, not the user credentials themselves).
        2. POST /api/v1/users/token  with
           grant_type=password, client_id, client_secret, username, password
           returns {"access_token": "...", "refresh_token": "...",
                    "token_type": "Bearer", "expires_in": 86400, ...}.

    Both calls go DIRECTLY to PeerTube on PEERTUBE_HOST:PEERTUBE_PORT
    — they bypass the Caddy mid-tier.  This is necessary because
    PeerTube's ``/api/v1/oauth-clients/local`` handler requires the
    inbound Host header to match the canonical webserver.hostname
    EXACTLY: any other value (including ``127.0.0.1:9090`` which
    Caddy would forward without an X-Forwarded-Host to rewrite from)
    returns 403.  The bridge has the canonical hostname available
    (it's in the env via $PEERTUBE_WEBSERVER_HOSTNAME, surfaced as
    ``canonical_host`` in our constructor), so we just send it
    directly.

    We DO NOT cache the access token globally; we mint a fresh one
    each time the trampoline fires for an owner visit, and let the
    SPA's localStorage be the per-browser cache.  PeerTube tokens
    are short enough (~24h) and minting is cheap (~50ms loopback),
    so the simplicity is worth it.

    Client_id / client_secret are cached because they don't change
    until PeerTube restarts.  We refresh them on any token-mint
    failure to recover from a PeerTube restart between mints.
    """

    def __init__(
        self,
        peertube_host: str,
        peertube_port: int,
        canonical_host: str,
        username: str,
        password: str,
    ) -> None:
        self._peertube_host = peertube_host
        self._peertube_port = peertube_port
        # The canonical Host header value PeerTube expects on its
        # ``/api/v1/oauth-clients/local`` endpoint.  Includes the
        # explicit port only when the public URL has a non-standard
        # one (PeerTube formats this as ``host`` for :443/HTTPS,
        # ``host:port`` otherwise).  We honor the value passed by
        # start.sh verbatim — it's authoritative.
        self._canonical_host = canonical_host
        self._username = username
        self._password = password
        self._client_id: str | None = None
        self._client_secret: str | None = None
        self._client_lock = threading.Lock()

    def _peertube_url(self, path: str) -> str:
        return f"http://{self._peertube_host}:{self._peertube_port}{path}"

    def _request_headers(self) -> dict[str, str]:
        # Override the Host header so PeerTube's canonical-Host
        # check passes.  Python's requests honors a Host header in
        # the user-supplied dict (it passes through to urllib3 which
        # passes through to http.client).
        return {"Host": self._canonical_host}

    def _fetch_client_creds(self, force: bool = False) -> tuple[str, str]:
        with self._client_lock:
            if not force and self._client_id and self._client_secret:
                return self._client_id, self._client_secret
            url = self._peertube_url("/api/v1/oauth-clients/local")
            with requests.get(
                url, headers=self._request_headers(), timeout=10
            ) as resp:
                resp.raise_for_status()
                data = resp.json()
            cid = data.get("client_id")
            csec = data.get("client_secret")
            if not cid or not csec:
                raise RuntimeError(
                    "PeerTube /oauth-clients/local returned no client_id"
                )
            self._client_id = cid
            self._client_secret = csec
            return cid, csec

    def mint_token(self) -> dict:
        """Mint a new OAuth2 access token for the configured user.

        Returns the parsed JSON response — the SPA expects keys
        ``access_token``, ``refresh_token``, ``token_type``, and
        ``expires_in``.  Raises on any error; caller logs.

        On a 400 from the token endpoint (which PeerTube returns when
        the client_id/secret are stale because PeerTube restarted),
        we transparently re-fetch the client creds and retry once.
        """
        for attempt in (0, 1):
            client_id, client_secret = self._fetch_client_creds(
                force=(attempt == 1)
            )
            url = self._peertube_url("/api/v1/users/token")
            data = {
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "password",
                "response_type": "code",
                "username": self._username,
                "password": self._password,
            }
            resp = requests.post(
                url,
                data=data,
                headers=self._request_headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 400 and attempt == 0:
                # Likely stale client creds.  Force-refresh on next
                # attempt.
                log.info(
                    "PeerTube token mint got 400; refreshing client creds"
                )
                continue
            # Any other status, or 400 on the second attempt, is fatal
            # for this request.  Don't include the response body in the
            # log: PeerTube echoes the username back in error
            # messages and our log destination is shared.
            raise RuntimeError(
                f"PeerTube token mint failed: HTTP {resp.status_code}"
            )
        raise RuntimeError("PeerTube token mint failed: out of attempts")


# ---------------------------------------------------------------------------
# Streaming proxy core
# ---------------------------------------------------------------------------
class _CappedReader:
    """Wraps a file-like .read(n) that caps at a known total length."""

    def __init__(self, src, length: int) -> None:
        self._src = src
        self._remaining = int(length)

    def read(self, n: int = -1) -> bytes:
        if self._remaining <= 0:
            return b""
        if n is None or n < 0 or n > self._remaining:
            n = self._remaining
        chunk = self._src.read(n)
        if not chunk:
            self._remaining = 0
            return b""
        self._remaining -= len(chunk)
        return chunk

    @property
    def remaining(self) -> int:
        return self._remaining


def _copy_stream(src, dst, max_bytes: int | None = None) -> int:
    copied = 0
    while True:
        if max_bytes is not None and copied >= max_bytes:
            return copied
        want = STREAM_CHUNK_BYTES
        if max_bytes is not None:
            want = min(want, max_bytes - copied)
        chunk = src.read(want)
        if not chunk:
            return copied
        dst.write(chunk)
        copied += len(chunk)


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[list[str]]:
    drop_lower = {h.lower() for h in drop}
    return [[k, v] for k, v in headers if k.lower() not in drop_lower]


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------
class AuthProxyHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 for chunked transfer encoding support.
    protocol_version = "HTTP/1.1"
    # Close the client connection after every response so request-body
    # framing across requests can never get out of sync.  The OpenHost
    # router doesn't pipeline, so this costs us nothing.
    close_connection = True

    # Class-level config set by main() before serve_forever().
    jwks: JwksCache | None = None
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 9090
    oauth_bridge: PeerTubeOauthBridge | None = None

    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        path = getattr(self, "path", "")
        # PeerTube + the OpenHost router both probe /api/v1/ping for
        # liveness; suppress those so the log isn't drowned.
        if path.startswith("/api/v1/ping"):
            return
        log.info("%s - " + format, self.address_string(), *args)

    # Standard HTTP verbs.
    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch()

    def _safe_send_error(self, code: int, message: str) -> None:
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    # ----------------------------------------------------------------
    # Routing entry point
    # ----------------------------------------------------------------
    def _dispatch(self) -> None:
        try:
            self.connection.settimeout(STREAM_TIMEOUT_SECONDS)
        except OSError as exc:
            log.debug("settimeout on client socket failed: %s", exc)

        # SSO trampoline routes — handled wholly in-sidecar.
        path_only = self.path.split("?", 1)[0].split("#", 1)[0]
        if path_only == SSO_LOGIN_PATH:
            self._handle_sso_login()
            return
        if path_only == SSO_TOKEN_PATH:
            self._handle_sso_mint_token()
            return
        if path_only == SSO_LOGOUT_PATH:
            self._handle_sso_logout()
            return

        # Federation surface OR no zone_auth — pass straight through.
        # Owner-status-check happens only if the request looks like
        # an owner browser visit that needs trampolining.
        cookies = _parse_cookie_header(self.headers.get("Cookie"))
        zone_token = cookies.get(ZONE_COOKIE, "")
        marker_until = cookies.get(SSO_MARKER_COOKIE, "")

        is_owner = False
        if zone_token and self.jwks is not None:
            is_owner = _verify_owner(zone_token, self.jwks)

        # Should we trampoline THIS request?  Only if all of:
        #   * the request looks like a top-level navigation (HTML
        #     accept), so we don't trampoline an XHR or asset
        #     fetch (which would corrupt the SPA's view of itself);
        #   * the visitor is the owner;
        #   * the request isn't already part of the federation/
        #     anonymous surface;
        #   * the marker cookie isn't already present + unexpired.
        accept = self.headers.get("Accept", "")
        is_html_navigation = (
            self.command == "GET"
            and "text/html" in accept.lower()
            and not _is_federation_path(self.path)
        )
        marker_valid = self._marker_cookie_valid(marker_until)

        if is_owner and is_html_navigation and not marker_valid:
            self._redirect_to_trampoline()
            return

        # Pass through.
        self._proxy()

    @staticmethod
    def _marker_cookie_valid(marker: str) -> bool:
        if not marker:
            return False
        try:
            until = int(marker)
        except ValueError:
            return False
        return until > time.time()

    # ----------------------------------------------------------------
    # SSO trampoline handlers
    # ----------------------------------------------------------------
    def _redirect_to_trampoline(self) -> None:
        """Redirect an owner navigation to the SSO trampoline page."""
        # Encode the original path so the trampoline can bounce us
        # back after writing localStorage.  ``Location`` is sent in
        # latin-1 over the wire; Python urlencode handles non-ASCII
        # by percent-encoding.
        next_url = self.path
        # Avoid an open-redirect: only allow same-origin paths.  An
        # owner clicking a maliciously-crafted link with
        # ?next=https://evil.example/ wouldn't escape because we
        # only echo back the request-target as-received and that's
        # always origin-form when serving a path under our hostname,
        # but enforce it here anyway as defence in depth.
        if not next_url.startswith("/"):
            next_url = "/"
        target = SSO_LOGIN_PATH + "?" + urllib.parse.urlencode({"next": next_url})
        try:
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        except OSError as exc:
            log.debug("client disconnected during trampoline redirect: %s", exc)

    def _handle_sso_login(self) -> None:
        """Serve the trampoline HTML page.

        The page itself is served regardless of whether the visitor
        appears to be the owner — we will deny the actual token-mint
        endpoint if their JWT doesn't verify, and the page just
        shows an error in that case.  Serving the static HTML to
        non-owners simplifies caching and lets a stale tab recover
        gracefully without needing zone_auth at the page-load time.
        """
        # Parse ?next= to validate it's an origin-form path; never
        # echo a foreign URL back (open-redirect risk).
        try:
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            next_path = qs.get("next", ["/"])[0]
        except Exception:  # noqa: BLE001
            next_path = "/"
        if not isinstance(next_path, str) or not next_path.startswith("/"):
            next_path = "/"
        # Basic XSS hardening — echo back into JS string literal and
        # HTML attribute.  ``json.dumps`` produces a safe JS string
        # literal even for adversarial inputs (it escapes ``</`` →
        # ``<\/`` etc.).  ``html.escape`` covers the textual
        # fallback link.
        next_path_js = json.dumps(next_path)
        next_path_attr = html.escape(next_path, quote=True)

        body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Signing you in…</title>
<style>
  body {{ font-family: system-ui, sans-serif; padding: 2rem; max-width: 40rem; margin: 0 auto; }}
  .spinner {{ display: inline-block; width: 1.2em; height: 1.2em; border: 2px solid #999; border-top-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; vertical-align: middle; margin-right: 0.5em; }}
  @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
  .err {{ color: #b00; }}
  code {{ background: #f4f4f4; padding: 0.1em 0.3em; border-radius: 3px; }}
</style>
</head>
<body>
<p><span class="spinner"></span><span id="msg">Signing you in…</span></p>
<noscript>
  <p class="err">JavaScript is required to sign in to PeerTube via OpenHost SSO.
     <a href={next_path_attr}>Continue without signing in.</a></p>
</noscript>
<script>
(function () {{
  var nextUrl = {next_path_js};
  var msg = document.getElementById('msg');
  function showError(text) {{
    msg.textContent = text;
    msg.classList.add('err');
  }}
  function bounce() {{
    // Use replace() so the browser back-button doesn't loop us
    // through the trampoline a second time.
    window.location.replace(nextUrl);
  }}
  // Mint a fresh PeerTube OAuth token by asking the sidecar.
  fetch({json.dumps(SSO_TOKEN_PATH)}, {{
    credentials: 'include',
    cache: 'no-store',
    headers: {{ 'Accept': 'application/json' }}
  }}).then(function (resp) {{
    if (!resp.ok) {{
      // 401 → not the owner.  Fall through anonymously.
      // 5xx → sidecar/PeerTube hiccup; show error but still let
      //       the user click through.
      if (resp.status === 401) {{
        showError('Not signed into the OpenHost zone.');
      }} else {{
        showError('Sign-in failed (HTTP ' + resp.status + '). Continuing anonymously…');
      }}
      setTimeout(bounce, 1500);
      throw new Error('mint-token failed: ' + resp.status);
    }}
    return resp.json();
  }}).then(function (tokens) {{
    try {{
      // Match the exact localStorage keys PeerTube's SPA reads —
      // see /app/client/src/root-helpers/users/oauth-user-tokens.ts
      // and user-local-storage-keys.ts in the upstream tree.
      window.localStorage.setItem('access_token', tokens.access_token);
      window.localStorage.setItem('refresh_token', tokens.refresh_token);
      window.localStorage.setItem('token_type', tokens.token_type || 'Bearer');
    }} catch (e) {{
      showError('Could not write OAuth token to localStorage. ' +
                'Private-mode browsing? Continuing anonymously…');
      setTimeout(bounce, 2000);
      return;
    }}
    bounce();
  }}).catch(function (err) {{
    // Any other error (network down, JSON parse failure):
    // log and bounce anonymously.  The bounce-target is the
    // standard PeerTube login page on /login from the SPA's
    // perspective, which still works as a fallback.
    if (msg && !msg.classList.contains('err')) {{
      showError('Sign-in failed: ' + err);
      setTimeout(bounce, 2000);
    }}
  }});
}})();
</script>
</body>
</html>
"""
        body_bytes = body.encode("utf-8")
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body_bytes)))
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("X-Content-Type-Options", "nosniff")
            # Don't let the trampoline page be embedded.
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body_bytes)
        except OSError as exc:
            log.debug("client disconnected mid-SSO page: %s", exc)

    def _handle_sso_mint_token(self) -> None:
        """Internal endpoint that mints a PeerTube token for the owner.

        Returns JSON {access_token, refresh_token, token_type, expires_in}
        on success.  Returns 401 if the request doesn't carry a valid
        owner zone_auth.  Returns 5xx if PeerTube is unreachable or
        rejects our credentials.

        Critically, this endpoint must reject requests on a federation
        path or that lack zone_auth — otherwise an attacker could
        request a token from a public surface.  We rely on the JWT
        being signed by the router; without zone_auth and a valid
        owner claim we always return 401.
        """
        # Strip request body — POST etc. has no business here, this
        # is GET-only.
        if self.command not in ("GET", "HEAD"):
            self._safe_send_error(405, "Method Not Allowed")
            return

        if self.jwks is None or self.oauth_bridge is None:
            log.error("SSO mint-token reached without configured handlers")
            self._safe_send_error(503, "SSO not initialised")
            return

        cookies = _parse_cookie_header(self.headers.get("Cookie"))
        zone_token = cookies.get(ZONE_COOKIE, "")
        if not _verify_owner(zone_token, self.jwks):
            # Not the owner (or zone_auth absent).  401 is what the
            # trampoline JS expects.
            self._sso_json_response(401, {"error": "not_owner"})
            return

        try:
            tokens = self.oauth_bridge.mint_token()
        except Exception as exc:  # noqa: BLE001
            log.warning("PeerTube token mint failed: %s", exc)
            self._sso_json_response(502, {"error": "mint_failed"})
            return

        # Minimal sanity-check.  PeerTube always returns these keys
        # on success; if they're missing something is severely wrong.
        for k in ("access_token", "refresh_token", "token_type"):
            if k not in tokens:
                log.warning("PeerTube token response missing %s", k)
                self._sso_json_response(502, {"error": "mint_malformed"})
                return

        # Compute the marker-cookie expiry.  We mint a fresh marker
        # at half the token's life so the next visit re-mints when
        # the token has half its life left — far before the SPA
        # gets a 401 from a stale token.
        expires_in = int(tokens.get("expires_in") or 86400)
        marker_until = int(time.time() + max(SSO_MIN_TOKEN_REMAINING_SEC,
                                             expires_in // 2))

        # ``HttpOnly`` is intentionally OMITTED from the marker
        # cookie: the trampoline JS doesn't read it (the server
        # does), but a client-side script could legitimately want
        # to know whether SSO is active (e.g. to decide whether to
        # auto-redirect on 401).  The cookie is only a "skip the
        # trampoline next time" marker; it grants no privilege on
        # its own.  ``Secure`` + ``SameSite=Lax`` cover the usual
        # cross-site bases.
        scheme = "https" if "https" in self.headers.get("X-Forwarded-Proto", "").lower() else "https"
        # Lax is fine: the trampoline only fires on top-level
        # navigations, never on cross-site iframes/forms.
        cookie_attrs = [
            f"{SSO_MARKER_COOKIE}={marker_until}",
            f"Max-Age={max(0, marker_until - int(time.time()))}",
            "Path=/",
            "SameSite=Lax",
        ]
        if scheme == "https":
            cookie_attrs.append("Secure")
        cookie_value = "; ".join(cookie_attrs)

        body_bytes = json.dumps({
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "token_type": tokens["token_type"],
            "expires_in": expires_in,
        }).encode("utf-8")
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body_bytes)))
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("Set-Cookie", cookie_value)
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body_bytes)
        except OSError as exc:
            log.debug("client disconnected mid-SSO mint: %s", exc)

    def _handle_sso_logout(self) -> None:
        """Clears the marker cookie so the next visit re-trampolines.

        Doesn't actually revoke the PeerTube OAuth token (PeerTube
        has its own /api/v1/users/revoke-token for that, which the
        SPA already calls during its logout flow).  All we need to
        do here is wipe the marker so the sidecar will re-trigger
        the trampoline on the next owner visit, which in turn will
        replace the stale localStorage tokens.
        """
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", "0")
            self.send_header(
                "Set-Cookie",
                f"{SSO_MARKER_COOKIE}=; Max-Age=0; Path=/; SameSite=Lax",
            )
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
        except OSError as exc:
            log.debug("client disconnected mid-SSO logout: %s", exc)

    def _sso_json_response(self, code: int, body: dict) -> None:
        body_bytes = json.dumps(body).encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body_bytes)))
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body_bytes)
        except OSError as exc:
            log.debug("client disconnected mid-SSO error response: %s", exc)

    # ----------------------------------------------------------------
    # Pass-through proxy
    # ----------------------------------------------------------------
    def _proxy(self) -> None:
        # Always strip trust headers, even on federation paths.
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | ALWAYS_STRIP_HEADERS,
        )

        # Determine body framing.
        transfer_encoding = (
            self.headers.get("Transfer-Encoding", "").lower().strip()
        )
        content_length_header = self.headers.get("Content-Length")
        body_mode: str
        body_length: int = 0
        if transfer_encoding and transfer_encoding != "identity":
            if transfer_encoding != "chunked":
                self._safe_send_error(501, "Transfer-Encoding not supported")
                return
            body_mode = "chunked"
        elif content_length_header is not None:
            try:
                body_length = int(content_length_header)
            except ValueError:
                self._safe_send_error(400, "invalid Content-Length")
                return
            if body_length < 0:
                self._safe_send_error(400, "negative Content-Length")
                return
            body_mode = "fixed"
        else:
            body_mode = "none"

        try:
            upstream_sock = socket.create_connection(
                (self.upstream_host, self.upstream_port),
                timeout=STREAM_TIMEOUT_SECONDS,
            )
        except OSError as exc:
            log.warning("upstream connect failed: %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return

        try:
            self._stream(
                upstream_sock,
                cleaned_headers,
                body_mode,
                body_length,
            )
        finally:
            try:
                upstream_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                upstream_sock.close()
            except OSError:
                pass

    @staticmethod
    def _encode_header_bytes(value: str) -> bytes:
        try:
            return value.encode("latin-1")
        except UnicodeEncodeError:
            log.warning("non-latin-1 header value, replacing offending bytes")
            return value.encode("latin-1", errors="replace")

    def _stream(
        self,
        upstream_sock: socket.socket,
        cleaned_headers: list[list[str]],
        body_mode: str,
        body_length: int,
    ) -> None:
        upstream_sock.settimeout(STREAM_TIMEOUT_SECONDS)
        upstream_writer = None
        upstream_reader = None
        try:
            upstream_writer = upstream_sock.makefile("wb")
            upstream_reader = upstream_sock.makefile(
                "rb", buffering=STREAM_CHUNK_BYTES
            )
            self._stream_inner(
                upstream_sock,
                upstream_writer,
                upstream_reader,
                cleaned_headers,
                body_mode,
                body_length,
            )
        finally:
            for f in (upstream_writer, upstream_reader):
                if f is None:
                    continue
                try:
                    f.close()
                except OSError:
                    pass

    def _stream_inner(
        self,
        upstream_sock: socket.socket,
        upstream_writer,
        upstream_reader,
        cleaned_headers: list[list[str]],
        body_mode: str,
        body_length: int,
    ) -> None:
        # ---- write request line + headers ----
        try:
            request_line = f"{self.command} {self.path} HTTP/1.1\r\n"
            upstream_writer.write(self._encode_header_bytes(request_line))
            upstream_writer.write(
                self._encode_header_bytes(
                    f"Host: {self.upstream_host}:{self.upstream_port}\r\n"
                )
            )
            for k, v in cleaned_headers:
                upstream_writer.write(
                    self._encode_header_bytes(f"{k}: {v}\r\n")
                )
        except OSError as exc:
            log.warning("upstream write failed during request headers: %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return

        # ---- write framing headers + final CRLF ----
        try:
            if body_mode == "chunked":
                upstream_writer.write(b"Transfer-Encoding: chunked\r\n")
            elif body_mode == "fixed":
                upstream_writer.write(
                    f"Content-Length: {body_length}\r\n".encode("latin-1")
                )
            elif body_mode == "none":
                upstream_writer.write(b"Content-Length: 0\r\n")
            upstream_writer.write(b"Connection: close\r\n")
            upstream_writer.write(b"\r\n")
        except OSError as exc:
            log.warning("upstream write failed during framing: %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return

        # ---- write request body ----
        request_truncated = False
        try:
            if body_mode == "fixed" and body_length > 0:
                reader = _CappedReader(self.rfile, body_length)
                copied = _copy_stream(reader, upstream_writer)
                if copied != body_length:
                    log.info(
                        "short request body: declared=%d actual=%d",
                        body_length, copied,
                    )
                    try:
                        upstream_writer.flush()
                    except OSError as exc:
                        log.debug("flush before half-close failed: %s", exc)
                    try:
                        upstream_sock.shutdown(socket.SHUT_WR)
                    except OSError as exc:
                        log.debug("upstream half-close failed: %s", exc)
                    request_truncated = True
            elif body_mode == "chunked":
                if not self._copy_chunked(self.rfile, upstream_writer):
                    log.warning(
                        "chunked request body forwarded with truncation"
                    )
                    try:
                        upstream_writer.flush()
                    except OSError as exc:
                        log.debug("flush before half-close failed: %s", exc)
                    try:
                        upstream_sock.shutdown(socket.SHUT_WR)
                    except OSError as exc:
                        log.debug("upstream half-close failed: %s", exc)
                    request_truncated = True
        except (OSError, TimeoutError) as exc:
            log.info("client/upstream IO error during request body: %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return

        if not request_truncated:
            try:
                upstream_writer.flush()
            except OSError as exc:
                log.warning("upstream flush failed: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

        # ---- read response status + headers (with 1xx interim loop) ----
        status_code: int = 0
        reason: str = ""
        resp_headers: list[list[str]] = []
        MAX_INTERIM = 8
        interim_seen = 0
        while True:
            try:
                status_line = upstream_reader.readline(HEADER_LINE_CAP)
            except OSError as exc:
                log.warning("upstream read status failed: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return
            if not status_line:
                log.warning("upstream closed before sending status line")
                self._safe_send_error(502, "Bad Gateway")
                return
            if not status_line.endswith((b"\n",)):
                log.warning(
                    "upstream status line exceeds %d bytes", HEADER_LINE_CAP
                )
                self._safe_send_error(502, "upstream status line too long")
                return
            try:
                parts = status_line.decode("latin-1").rstrip("\r\n").split(" ", 2)
            except UnicodeDecodeError:
                log.warning("upstream status line not latin-1")
                self._safe_send_error(502, "Bad Gateway")
                return
            if len(parts) < 2 or not parts[0].startswith("HTTP/"):
                log.warning("malformed upstream status line: %r", status_line)
                self._safe_send_error(502, "Bad Gateway")
                return
            try:
                status_code = int(parts[1])
            except ValueError:
                log.warning("non-numeric status code: %r", parts[1])
                self._safe_send_error(502, "Bad Gateway")
                return
            reason = parts[2] if len(parts) > 2 else ""

            resp_headers = []
            while True:
                try:
                    line = upstream_reader.readline(HEADER_LINE_CAP)
                except OSError as exc:
                    log.warning("upstream read header failed: %s", exc)
                    self._safe_send_error(502, "Bad Gateway")
                    return
                if not line or line in (b"\r\n", b"\n"):
                    break
                if not line.endswith((b"\n",)):
                    log.warning(
                        "upstream header line exceeds %d bytes", HEADER_LINE_CAP
                    )
                    self._safe_send_error(502, "upstream header too long")
                    return
                try:
                    decoded = line.decode("latin-1").rstrip("\r\n")
                except UnicodeDecodeError:
                    log.warning("upstream header not latin-1")
                    self._safe_send_error(502, "Bad Gateway")
                    return
                if line[:1] in (b" ", b"\t") and resp_headers:
                    resp_headers[-1][1] = (
                        resp_headers[-1][1] + " " + decoded.strip()
                    )
                    continue
                if ":" not in decoded:
                    log.warning(
                        "dropping malformed response header line: %r", decoded
                    )
                    continue
                name, _, value = decoded.partition(":")
                resp_headers.append([name.strip(), value.strip()])

            if 100 <= status_code < 200 and status_code != 101:
                interim_seen += 1
                if interim_seen >= MAX_INTERIM:
                    log.warning(
                        "upstream sent %d or more interim responses; aborting",
                        MAX_INTERIM,
                    )
                    self._safe_send_error(502, "too many interim responses")
                    return
                log.debug(
                    "skipping interim response %d %s", status_code, reason
                )
                continue
            break

        # Detect framing.
        resp_te = ""
        resp_te_parts: list[str] = []
        resp_cl: int | None = None
        for k, v in resp_headers:
            kl = k.lower()
            if kl == "transfer-encoding":
                for tok in v.split(","):
                    tok = tok.strip().lower()
                    if tok:
                        resp_te_parts.append(tok)
            elif kl == "content-length":
                try:
                    parsed_cl = int(v.strip())
                except ValueError:
                    log.warning(
                        "upstream sent non-integer Content-Length %r", v
                    )
                    continue
                if parsed_cl < 0:
                    log.warning(
                        "upstream sent negative Content-Length %d", parsed_cl
                    )
                    continue
                if resp_cl is not None and resp_cl != parsed_cl:
                    log.warning(
                        "upstream sent conflicting Content-Length values "
                        "%d and %d; using first", resp_cl, parsed_cl,
                    )
                elif resp_cl is None:
                    resp_cl = parsed_cl
        if "chunked" in resp_te_parts:
            resp_te = "chunked"

        # ---- write status + headers to client ----
        try:
            self.send_response_only(status_code, reason)
            for k, v in resp_headers:
                if k.lower() in HOP_BY_HOP_HEADERS:
                    continue
                # Strip CR/LF defence in depth (response header
                # splitting / CRLF injection if a compromised
                # PeerTube ever wrote them).
                if "\r" in v or "\n" in v:
                    log.warning(
                        "stripping CR/LF from upstream header %r value", k
                    )
                    v = v.replace("\r", "").replace("\n", "")
                self.send_header(k, v)
            if status_code in (204, 304):
                pass
            elif self.command == "HEAD":
                if resp_cl is not None:
                    self.send_header("Content-Length", str(resp_cl))
            elif resp_te == "chunked":
                self.send_header("Transfer-Encoding", "chunked")
            elif resp_cl is not None:
                self.send_header("Content-Length", str(resp_cl))
            self.send_header("Connection", "close")
            self.end_headers()
        except OSError as exc:
            log.debug("client disconnected before response headers: %s", exc)
            return

        # ---- stream response body ----
        if status_code in (204, 304) or self.command == "HEAD":
            return

        try:
            if resp_te == "chunked":
                if not self._copy_chunked(upstream_reader, self.wfile):
                    log.warning(
                        "chunked response body delivered with truncation"
                    )
            elif resp_cl is not None:
                reader = _CappedReader(upstream_reader, resp_cl)
                copied = _copy_stream(reader, self.wfile)
                if copied != resp_cl:
                    log.warning(
                        "Content-Length mismatch: declared=%d delivered=%d",
                        resp_cl, copied,
                    )
            else:
                _copy_stream(upstream_reader, self.wfile)
        except OSError as exc:
            log.info("IO error streaming response body: %s", exc)
            return

    # Limits used by ``_copy_chunked``.
    _CHUNKED_MAX_BLANK_LINES = 8
    _CHUNKED_MAX_TRAILER_LINES = 64
    _CHUNKED_LINE_CAP = 8192
    _CHUNKED_MAX_CHUNK_BYTES = 16 * 1024 * 1024 * 1024

    def _copy_chunked(self, src, dst) -> bool:
        blank_lines_seen = 0
        while True:
            size_line = src.readline(self._CHUNKED_LINE_CAP)
            if not size_line:
                log.info("chunked stream truncated: EOF before chunk-size line")
                return False
            if not size_line.endswith((b"\n",)):
                log.warning(
                    "chunk-size line exceeds %d bytes; aborting stream",
                    self._CHUNKED_LINE_CAP,
                )
                return False
            decoded = size_line.split(b";", 1)[0].strip()
            if not decoded:
                blank_lines_seen += 1
                if blank_lines_seen > self._CHUNKED_MAX_BLANK_LINES:
                    log.warning(
                        "too many blank chunk-size lines (%d); aborting",
                        blank_lines_seen,
                    )
                    return False
                continue
            try:
                size = int(decoded, 16)
            except ValueError:
                log.warning("malformed chunk size: %r", size_line)
                return False
            if size < 0 or size > self._CHUNKED_MAX_CHUNK_BYTES:
                log.warning(
                    "chunk size %d outside acceptable range; aborting",
                    size,
                )
                return False
            blank_lines_seen = 0
            dst.write(size_line)
            if size == 0:
                trailers_seen = 0
                while True:
                    trailer = src.readline(self._CHUNKED_LINE_CAP)
                    if not trailer:
                        log.info("chunked stream truncated: EOF in trailers")
                        return False
                    if not trailer.endswith((b"\n",)):
                        log.warning(
                            "trailer line exceeds %d bytes; aborting",
                            self._CHUNKED_LINE_CAP,
                        )
                        return False
                    dst.write(trailer)
                    if trailer in (b"\r\n", b"\n"):
                        return True
                    trailers_seen += 1
                    if trailers_seen > self._CHUNKED_MAX_TRAILER_LINES:
                        log.warning(
                            "too many trailer lines (%d); aborting",
                            trailers_seen,
                        )
                        return False
                # unreachable
            remaining = size
            while remaining > 0:
                chunk = src.read(min(STREAM_CHUNK_BYTES, remaining))
                if not chunk:
                    log.info(
                        "chunked stream truncated mid-chunk (declared %d, %d remaining)",
                        size, remaining,
                    )
                    return False
                dst.write(chunk)
                remaining -= len(chunk)
            crlf = b""
            while len(crlf) < 2:
                more = src.read(2 - len(crlf))
                if not more:
                    log.info("chunked stream truncated in inter-chunk CRLF")
                    return False
                crlf += more
            if crlf != b"\r\n":
                log.warning(
                    "chunked framing error: post-chunk delimiter %r != CRLF",
                    crlf,
                )
                return False
            dst.write(crlf)


# ---------------------------------------------------------------------------
# Server bootstrap
# ---------------------------------------------------------------------------
class IPv4ThreadingServer(ThreadingHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def _port_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer: {exc}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}={raw!r} is out of range (1-65535)")
    return port


def _read_admin_password(path: str) -> str:
    """Read the trimmed root admin password from ``admin-password.txt``.

    Same recipe as start.sh's gen_secret reader: read the first line,
    strip surrounding whitespace, fail loud if it ends up empty.
    Without this credential we have no way to mint OAuth tokens for
    the owner — that's a hard fail rather than a runtime degraded
    state.
    """
    try:
        with open(path, "rb") as f:
            first_line = f.readline()
    except OSError as exc:
        raise RuntimeError(
            f"cannot read admin password from {path}: {exc}"
        ) from exc
    pw = first_line.decode("utf-8", errors="replace").strip()
    if not pw:
        raise RuntimeError(
            f"admin password file {path} is empty/whitespace-only"
        )
    return pw


def main() -> int:
    router_url = os.environ.get("OPENHOST_ROUTER_URL", "").strip()
    if not router_url:
        log.error("OPENHOST_ROUTER_URL is not set; refusing to start")
        return 1

    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 9000)
        # AUTH_PROXY_UPSTREAM_PORT is the port Caddy listens on (Caddy
        # is the Host-rewriter that fronts PeerTube).  Pass-through
        # proxy traffic flows AUTH_PROXY → Caddy → PeerTube.
        upstream_port = _port_from_env("AUTH_PROXY_UPSTREAM_PORT", 9090)
        # AUTH_PROXY_PEERTUBE_PORT is where PeerTube itself listens
        # on the loopback.  The OAuth bridge bypasses Caddy and
        # speaks to PeerTube directly because PeerTube's
        # /api/v1/oauth-clients/local handler enforces a strict
        # Host-header equality check that's awkward to satisfy
        # through the Caddy mid-tier when there's no inbound
        # X-Forwarded-Host to rewrite from (loopback callers don't
        # have one).
        peertube_port = _port_from_env("AUTH_PROXY_PEERTUBE_PORT", 9001)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    upstream_host = os.environ.get(
        "AUTH_PROXY_UPSTREAM_HOST", "127.0.0.1"
    ).strip() or "127.0.0.1"
    peertube_host = os.environ.get(
        "AUTH_PROXY_PEERTUBE_HOST", "127.0.0.1"
    ).strip() or "127.0.0.1"

    # The canonical PeerTube hostname (and explicit :port if the
    # public URL has a non-standard one) — what PeerTube expects on
    # the Host header when it's checking ``oauth-clients/local``.
    # start.sh derives this from PEERTUBE_WEBSERVER_HOSTNAME +
    # PEERTUBE_WEBSERVER_PORT and passes it via env.
    canonical_host = os.environ.get(
        "AUTH_PROXY_CANONICAL_HOST", ""
    ).strip()
    if not canonical_host:
        log.error(
            "AUTH_PROXY_CANONICAL_HOST is not set; refusing to start "
            "(should be PEERTUBE_WEBSERVER_HOSTNAME[:port])"
        )
        return 1

    admin_user = os.environ.get(
        "AUTH_PROXY_ADMIN_USER", "root"
    ).strip() or "root"

    admin_pw_file = os.environ.get(
        "AUTH_PROXY_ADMIN_PW_FILE", ""
    ).strip()
    if not admin_pw_file:
        log.error(
            "AUTH_PROXY_ADMIN_PW_FILE is not set; refusing to start "
            "(point this at your admin-password.txt)"
        )
        return 1
    try:
        admin_pw = _read_admin_password(admin_pw_file)
    except RuntimeError as exc:
        log.error("admin password load failed: %s", exc)
        return 1

    jwks = JwksCache(router_url)
    jwks.prefetch()

    bridge = PeerTubeOauthBridge(
        peertube_host=peertube_host,
        peertube_port=peertube_port,
        canonical_host=canonical_host,
        username=admin_user,
        password=admin_pw,
    )

    AuthProxyHandler.jwks = jwks
    AuthProxyHandler.upstream_host = upstream_host
    AuthProxyHandler.upstream_port = upstream_port
    AuthProxyHandler.oauth_bridge = bridge

    try:
        server = IPv4ThreadingServer(("0.0.0.0", listen_port), AuthProxyHandler)
    except OSError as exc:
        log.error(
            "failed to bind auth-proxy listener on 0.0.0.0:%d: %s",
            listen_port, exc,
        )
        return 1

    log.info(
        "listening on 0.0.0.0:%d -> %s:%d (router=%s, admin_user=%s, "
        "canonical_host=%s, peertube=%s:%d)",
        listen_port, upstream_host, upstream_port, router_url, admin_user,
        canonical_host, peertube_host, peertube_port,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
