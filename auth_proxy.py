"""OpenHost auth-sidecar for PeerTube — owner SSO without breaking federation.

Two rails for traffic flow, plus three sidecar-served endpoints
under ``/__openhost-sso/*`` (``login``, ``mint-token``, ``logout``)
that drive the SSO bridge.  The two traffic rails mirror the
openhost-nextcloud pattern but the SSO endpoints are
PeerTube-specific because PeerTube's SPA reads its OAuth2 token
from ``localStorage`` rather than a cookie.

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
       * writes seven items to localStorage:
              - the OAuth token triple (``access_token``,
                ``refresh_token``, ``token_type``); and
              - the four user-identity fields (``id``, ``username``,
                ``email``, ``role``) — without these the SPA
                bootstrap (``loadUser`` in ``main.js``) treats the
                visitor as anonymous EVEN with valid tokens.
          These are the exact keys the PeerTube SPA reads on
          bootstrap (see
          /app/client/src/root-helpers/users/oauth-user-tokens.ts
          for the token triple and the SPA's
          user-local-storage-keys helpers for the identity quartet).
          The sidecar fetches the identity fields via
          ``/api/v1/users/me`` with the freshly-minted token before
          handing them to the trampoline.
   The mint-token response from the sidecar additionally carries
   a ``Set-Cookie: openhost_pt_sso_until=<unix-ts>; Path=/; ...``
   header so subsequent visits skip the trampoline until the
   marker expires.  (The cookie is set server-side; the trampoline
   JS itself only touches localStorage.)  Once both write paths
   complete, the JS redirects to the original URL.
   On subsequent visits, the marker cookie is present and unexpired,
   so the sidecar passes the request through untouched and the SPA
   reads the still-valid token from localStorage on its own.

   ``/__openhost-sso/logout`` (POST-only — see the handler) clears
   the marker cookie so the next owner visit re-trampolines and
   replaces stale localStorage tokens.  Useful after the operator
   resets the admin password (the sidecar caches the password at
   startup, so a reset requires a container restart anyway, but
   the logout endpoint at least stops the browser from holding
   onto the stale OAuth tokens after the marker invalidates).

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
``X-OpenHost-Is-Owner`` headers are stripped on every request
that the sidecar PROXIES UPSTREAM — i.e., everything that
reaches ``_proxy()`` or ``_proxy_websocket()``, which covers
both federation paths and the owner pass-through after the
trampoline.  These are the headers the OpenHost router uses to
assert owner identity to the app; forging them must never
grant privilege downstream.

The three sidecar-served SSO endpoints (``/__openhost-sso/login``,
``/.../mint-token``, ``/.../logout``) do NOT proxy upstream and
therefore don't run the strip step — but they also never use
the trust headers for any decision.  Owner authentication on
those paths is exclusively the JWT signature check.

We do NOT strip ``Authorization``: the SPA, mobile app, and any
third-party PeerTube client carries its OAuth2 access token in
that header, and forwarding it untouched is precisely how the
mobile app + third-party clients keep working.  ``Authorization``
is application-level auth that PeerTube validates against its own
token store — the auth-proxy has no business stripping or
inspecting it.
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

# When we mint a PeerTube token, PeerTube returns ``expires_in`` in
# seconds (typically ~86400).  We want the marker cookie to expire
# BEFORE the access token so the next owner navigation re-trampolines
# while there's still time left on the token (this avoids the SPA
# ever seeing a 401 for a stale token).  The marker's lifetime is
# computed as ``expires_in - SSO_MARKER_SAFETY_MARGIN_SEC``, capped
# below by 60s (so a tiny TTL doesn't produce a negative or near-zero
# marker that re-fires on every navigation).
#
# 1 hour of headroom means: with the typical 24h PeerTube token, the
# marker lasts 23h and we re-mint shortly before expiry.  With a
# hypothetical 30-minute token, headroom shrinks to 60s — still
# correct, just less efficient.
SSO_MARKER_SAFETY_MARGIN_SEC = 60 * 60

# Short-lived marker we set on mint-failure paths so the browser
# doesn't loop the trampoline if PeerTube is briefly unavailable.
# After this many seconds the next owner navigation will retry.
SSO_FAILURE_MARKER_SEC = 5 * 60

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


def _safe_next_path(raw: str) -> str:
    """Normalise an attacker-controlled ?next= value to a safe local path.

    Defends against open-redirect:
      * Anything that isn't a string is rejected → ``/``.
      * Anything that doesn't start with ``/`` is rejected → ``/``
        (catches ``http://evil.example/``).
      * A protocol-relative URL ``//evil.example/...`` IS a path that
        starts with ``/``, but ``urlparse`` of it produces a
        ``netloc`` and would resolve to a different origin in the
        browser.  We reject it explicitly.
      * ``\\evil.example`` is rejected too (some browsers treat
        backslashes as path separators after the leading ``/``).
    The resulting path is always a single-leading-slash, no-netloc
    same-origin reference, safe to put after ``Location: `` or to
    drop into ``window.location.replace()``.
    """
    if not isinstance(raw, str) or not raw:
        return "/"
    # Reject protocol-relative URLs and backslash-prefixed paths.
    # A path that starts with ``//`` (or ``/\\``) becomes a netloc
    # reference per RFC 3986 §4.2.  ``"/\\"`` and ``"/" + chr(0x5C)``
    # are the SAME 2-character string in Python — keep one.
    if raw.startswith("//") or raw.startswith("/\\"):
        return "/"
    if not raw.startswith("/"):
        return "/"
    # Final sanity-check: parse and confirm there's no netloc and
    # no scheme.  ``urlparse`` is permissive and the prefix checks
    # above already covered the common cases, but a defence in
    # depth is cheap and protects against future browser quirks.
    try:
        parsed = urllib.parse.urlparse(raw)
    except Exception as exc:  # noqa: BLE001
        log.debug("urlparse failed for next path %r: %s", raw, exc)
        return "/"
    if parsed.scheme or parsed.netloc:
        return "/"
    return raw


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
        # Defence in depth: a misbehaving router that returned a
        # JSON array (or null) instead of an object would otherwise
        # throw AttributeError on the .get() below.  Validate the
        # shape and produce a clear error.
        if not isinstance(jwks, dict):
            raise RuntimeError(
                f"router JWKS response is not a JSON object "
                f"(got {type(jwks).__name__})"
            )
        keys_list = jwks.get("keys", [])
        if not isinstance(keys_list, list):
            raise RuntimeError(
                f"router JWKS 'keys' field is not a list "
                f"(got {type(keys_list).__name__})"
            )
        keys = []
        skipped = 0
        for jwk in keys_list:
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
    last_error: Exception | None = None
    # Sentinel ``False`` distinguishes "we never managed to decode the
    # JWT against any key" from "we decoded successfully, but the sub
    # was not 'owner'".  Without the sentinel, ``sub=None`` (a valid
    # JWT with no sub claim) would log nothing at any level.
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
        except Exception as exc:  # noqa: BLE001
            # Catch broader than ``jwt.PyJWTError`` because PyJWT
            # CAN raise plain ``ValueError``/``TypeError``/
            # ``UnicodeDecodeError`` for certain malformed token
            # byte sequences before the JWT-specific validation
            # logic runs.  Letting those propagate would tear down
            # the request thread with no HTTP response.
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
    via the ``canonical_host`` constructor argument (start.sh
    derives it from ``PT_HTTPS`` + ``PT_PORT`` and passes the value
    as ``$AUTH_PROXY_CANONICAL_HOST``), so we just send it directly.

    We DO NOT cache the access token globally; we mint a fresh one
    each time the trampoline fires for an owner visit, and let the
    SPA's localStorage be the per-browser cache.  PeerTube tokens
    are short enough (~24h) and minting is cheap (~50ms loopback),
    so the simplicity is worth it.

    Client_id / client_secret are cached because they don't change
    until PeerTube restarts.  Specifically: on a token-endpoint
    HTTP 400 (which PeerTube returns when the cached creds are
    stale because PeerTube restarted between mints), we
    force-refresh the creds and retry the mint exactly once.
    Other failures (network errors, 5xx, 400 on the second
    attempt) raise immediately — no further retry.
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
        # Fast path: cache hit.  Take the lock just for the
        # snapshot read so concurrent readers don't tear the
        # tuple.  Mirrors the JwksCache.get pattern.
        with self._client_lock:
            cached = (self._client_id, self._client_secret)
        if not force and cached[0] and cached[1]:
            return cached  # type: ignore[return-value]

        # Slow path: fetch from PeerTube.  Don't hold the cache
        # lock across the network I/O — that would serialize
        # every concurrent owner mint behind a 10-second worst-
        # case timeout.  Multiple concurrent fetches are wasteful
        # but not unsafe: PeerTube's client creds rotate only on
        # PeerTube restart, so any racing fetches will all return
        # the same value.
        url = self._peertube_url("/api/v1/oauth-clients/local")
        try:
            with requests.get(
                url, headers=self._request_headers(), timeout=10
            ) as resp:
                resp.raise_for_status()
                data = resp.json()
        except (json.JSONDecodeError, ValueError) as exc:
            # Distinct error for the JSON-parse failure case so the
            # log surfaces it as a parse error rather than a
            # generic exception (a foreseeable failure when the
            # upstream responds with HTML — e.g. a
            # misconfiguration that exposes Caddy's default error
            # page in place of PeerTube).
            raise RuntimeError(
                "PeerTube /oauth-clients/local returned non-JSON response"
            ) from exc
        cid = data.get("client_id") if isinstance(data, dict) else None
        csec = data.get("client_secret") if isinstance(data, dict) else None
        if not cid or not csec:
            raise RuntimeError(
                "PeerTube /oauth-clients/local returned no client_id"
            )
        # Publish the new creds atomically.
        with self._client_lock:
            self._client_id = cid
            self._client_secret = csec
        return cid, csec

    def fetch_user_info(self, access_token: str, token_type: str) -> dict:
        """Fetch /api/v1/users/me with the freshly-minted token.

        Returns the parsed JSON response (a dict containing at least
        ``id``, ``username``, ``email``, ``role.id``).  Raises on any
        error; caller logs.

        The SPA's bootstrap (``loadUser`` in main.js) refuses to
        rebuild an authenticated user state from localStorage unless
        BOTH the OAuth tokens AND four user-identity fields
        (``id``, ``username``, ``email``, ``role``) are present.
        Without the user-identity fields the visitor sees the
        anonymous UI even though tokens are valid — so we must
        prime them via /users/me as part of the trampoline mint.
        """
        url = self._peertube_url("/api/v1/users/me")
        headers = self._request_headers()
        # PeerTube's auth uses the standard ``Authorization: Bearer
        # <access_token>`` scheme; ``token_type`` is "Bearer" in
        # practice but we honour what the upstream returned in case
        # a future PeerTube version uses a different scheme name.
        headers["Authorization"] = f"{token_type} {access_token}"
        try:
            with requests.get(url, headers=headers, timeout=10) as resp:
                resp.raise_for_status()
                data = resp.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError(
                "PeerTube /users/me returned non-JSON response"
            ) from exc
        if not isinstance(data, dict):
            raise RuntimeError(
                f"PeerTube /users/me response is not a JSON object "
                f"(got {type(data).__name__})"
            )
        return data

    def mint_token(self) -> dict:
        """Mint a new OAuth2 access token for the configured user.

        Returns the parsed JSON response — the SPA expects keys
        ``access_token``, ``refresh_token``, ``token_type``, and
        ``expires_in``.  Raises on any error; caller logs.

        On a 400 from the token endpoint (which PeerTube returns when
        the client_id/secret are stale because PeerTube restarted),
        we transparently re-fetch the client creds and retry once.
        """
        # Initialised to 0 so that even if the loop short-circuits in
        # ways the type checker can't see, the post-loop ``raise`` has
        # a defined value.  In practice, every code path through the
        # ``with`` either ``return``s on 200, sets ``status_was_400``
        # explicitly, or assigns ``failed_status`` — but a future
        # refactor that adds a path could otherwise hit a NameError.
        failed_status: int = 0
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
            with requests.post(
                url,
                data=data,
                headers=self._request_headers(),
                timeout=10,
            ) as resp:
                if resp.status_code == 200:
                    return resp.json()
                if resp.status_code == 400 and attempt == 0:
                    # Likely stale client creds.  Force-refresh on
                    # the next attempt.  ``continue`` exits the
                    # ``with`` block first, so the response is
                    # closed and the urllib3 connection released
                    # back to the pool before we retry.
                    log.info(
                        "PeerTube token mint got 400; refreshing client creds"
                    )
                    status_was_400 = True
                else:
                    status_was_400 = False
                    failed_status = resp.status_code
            if status_was_400:
                continue
            # Any other status, or 400 on the second attempt, is fatal
            # for this request.  Don't include the response body in
            # the log: PeerTube echoes the username back in error
            # messages and our log destination is shared.
            raise RuntimeError(
                f"PeerTube token mint failed: HTTP {failed_status}"
            )
        # Unreachable: every iteration of the for loop above either
        # returns on success, raises on terminal failure, or
        # ``continue``s after the first 400.  Defensive raise so a
        # future refactor that adds an unguarded path doesn't fall
        # off the end of the function and return None to the
        # caller (which would attempt to ``tokens["access_token"]``
        # and crash with a less obvious traceback).
        raise RuntimeError("PeerTube token mint loop exhausted unexpectedly")


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
        next_url = _safe_next_path(self.path)
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
        # echo a foreign URL back (open-redirect risk).  If the
        # parse fails for any reason we log at DEBUG and fall back
        # to the safe default ``/`` — silent fallback would mask a
        # systematic parser failure.
        try:
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            raw_next = qs.get("next", ["/"])[0]
        except Exception as exc:  # noqa: BLE001
            log.debug("trampoline ?next= parse failed: %s", exc)
            raw_next = "/"
        next_path = _safe_next_path(raw_next)
        # XSS hardening — echo back into a JS string literal AND an
        # HTML attribute.
        #
        # ``json.dumps`` alone is NOT sufficient for embedding into
        # an inline ``<script>`` block: it does not escape ``<`` or
        # ``/``, so an input like ``</script><script>alert(1)`` would
        # close our script tag and execute attacker JS.  The standard
        # mitigation is to additionally escape ``<`` to its JS-string
        # unicode form ``\u003c`` (and ``>`` to ``\u003e`` for good
        # measure, in case a future browser parser uses it as a
        # script-tag delimiter).  ``\u`` escapes are inert inside JS
        # string literals — they decode at parse time but do not
        # break out of the surrounding quote.
        next_path_js = (
            json.dumps(next_path)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
        )
        # ``html.escape(..., quote=True)`` escapes ``"`` and ``'``
        # within the value, which is what we need given the
        # surrounding ``href="..."`` quotes.
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
     <a href="{next_path_attr}">Continue without signing in.</a></p>
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
      // Match the exact localStorage keys PeerTube's SPA reads.
      // The SPA's bootstrap (``loadUser`` in main.js) needs BOTH
      // the OAuth token triple AND the four user-identity fields
      // (id, username, email, role) — if any are missing the
      // visitor is treated as anonymous on next render.  See
      // /app/client/src/root-helpers/users/oauth-user-tokens.ts
      // and user-local-storage-keys.ts in the upstream tree.
      window.localStorage.setItem('access_token', tokens.access_token);
      window.localStorage.setItem('refresh_token', tokens.refresh_token);
      window.localStorage.setItem('token_type', tokens.token_type || 'Bearer');
      // ``role`` is stored as the role-ID integer, stringified —
      // the SPA's getLoggedInUser does parseInt(stored, 10).
      // ``id`` is stored the same way.  Mismatching the stringify
      // (e.g. storing the role *label* rather than the integer ID)
      // makes the SPA think the user has the "Unknown" role and
      // hides admin UI.
      window.localStorage.setItem('id', String(tokens.user.id));
      window.localStorage.setItem('username', tokens.user.username);
      window.localStorage.setItem('email', tokens.user.email);
      window.localStorage.setItem('role', String(tokens.user.role_id));
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

        Returns JSON
        ``{access_token, refresh_token, token_type, expires_in,
           user: {id, username, email, role_id}}`` on success.  The
        ``user`` block is what the trampoline JS writes to
        localStorage so the SPA's bootstrap recognises the visitor
        as logged in (without it the SPA boots anonymous even with
        valid tokens).  The identity fields come from
        ``/api/v1/users/me`` called with the freshly-minted token.

        Returns 401 if the request doesn't carry a valid owner
        zone_auth.  Returns 5xx if PeerTube is unreachable, rejects
        our credentials, or returns a malformed /users/me response.

        Authorisation here is the zone_auth JWT verified inside
        this method via ``_verify_owner``.  ``_dispatch`` routes
        the path here directly (it dispatches by URL prefix BEFORE
        the cookie inspection logic that drives the owner
        trampoline redirect), so this method's own JWT check is
        the SOLE enforcement — not a defence in depth.  Any change
        that loosens it must be paired with a stronger check at
        the dispatch layer.
        """
        # GET (page-load) and HEAD (occasional probe) are the only
        # methods that make sense on this endpoint.  Anything else
        # is a misuse and gets a clean 405 instead of being passed
        # through.
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

        # ``failure_until`` is the short-lived marker timestamp we
        # apply on every error path so the browser doesn't loop the
        # trampoline through a brief PeerTube outage.  Recomputed
        # at use time in case mint_token blocks for a while.
        def _failure_marker() -> int:
            return int(time.time() + SSO_FAILURE_MARKER_SEC)

        try:
            tokens = self.oauth_bridge.mint_token()
        except Exception as exc:  # noqa: BLE001
            log.warning("PeerTube token mint failed: %s", exc)
            self._sso_json_response(
                502,
                {"error": "mint_failed"},
                marker_until=_failure_marker(),
            )
            return

        # PeerTube always returns a JSON object on 200, but a buggy
        # or compromised upstream COULD return a list / null /
        # string.  Guard so the token-shape check below doesn't
        # raise TypeError.
        if not isinstance(tokens, dict):
            log.warning(
                "PeerTube token response is not a JSON object (got %s)",
                type(tokens).__name__,
            )
            self._sso_json_response(
                502,
                {"error": "mint_malformed"},
                marker_until=_failure_marker(),
            )
            return

        # Minimal sanity-check.  PeerTube always returns these keys
        # on success; if they're missing something is severely
        # wrong.  Set the failure marker on this path too so the
        # browser doesn't loop through the trampoline (the
        # malformed-response case is one PeerTube doesn't recover
        # from on its own — operator intervention needed).
        for k in ("access_token", "refresh_token", "token_type"):
            if k not in tokens:
                log.warning("PeerTube token response missing %s", k)
                self._sso_json_response(
                    502,
                    {"error": "mint_malformed"},
                    marker_until=_failure_marker(),
                )
                return

        # Compute the marker-cookie expiry.  The marker MUST expire
        # before the access token does — otherwise an owner whose
        # marker is still valid when their token has expired will
        # skip the trampoline and the SPA's localStorage tokens are
        # stale.  We bake in SSO_MARKER_SAFETY_MARGIN_SEC of
        # headroom: marker_until = now + expires_in - margin.  For
        # the typical 24h PeerTube token, the marker lasts 23h.
        #
        # Use an explicit ``is None`` check so a legitimate
        # ``expires_in: 0`` (which would be a degenerate but valid
        # PeerTube response) is detected and handled — the
        # falsy-or idiom would silently substitute the 86400
        # default for any zero/empty value, masking the issue.
        raw_expires = tokens.get("expires_in")
        try:
            expires_in = int(raw_expires) if raw_expires is not None else 86400
        except (TypeError, ValueError):
            log.warning(
                "PeerTube returned non-numeric expires_in=%r; using default 24h",
                raw_expires,
            )
            expires_in = 86400
        if expires_in <= 0:
            log.warning(
                "PeerTube returned non-positive expires_in=%d; "
                "marker cookie will use a 60s floor",
                expires_in,
            )
        marker_lifetime = max(60, expires_in - SSO_MARKER_SAFETY_MARGIN_SEC)
        marker_until = int(time.time() + marker_lifetime)

        # Fetch user-identity fields (id/username/email/role) from
        # /users/me so the trampoline can prime the SPA's
        # localStorage with everything its bootstrap needs.  Without
        # these the SPA boots as anonymous even with valid tokens:
        # the bootstrap calls ``loadUser`` in the upstream
        # ``main.ts``, which calls ``getLoggedInUser`` in
        # ``client/src/root-helpers/users/user-local-storage-keys.ts``,
        # which returns null (and skips ``buildAuthUser``) whenever
        # the ``username`` localStorage key is absent.
        try:
            me = self.oauth_bridge.fetch_user_info(
                access_token=tokens["access_token"],
                token_type=tokens["token_type"],
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("PeerTube /users/me fetch failed: %s", exc)
            self._sso_json_response(
                502,
                {"error": "userinfo_failed"},
                marker_until=_failure_marker(),
            )
            return

        # Extract the four required identity fields with defensive
        # guards so a buggy/compromised upstream doesn't take down
        # the trampoline with a TypeError.  All four are required
        # by the SPA's ``getLoggedInUser`` reader; if any is missing
        # we fail closed.
        try:
            user_id = int(me["id"])
            username = str(me["username"])
            email = str(me["email"])
            role_obj = me.get("role")
            if not isinstance(role_obj, dict) or "id" not in role_obj:
                raise KeyError("role.id")
            role_id = int(role_obj["id"])
        except (KeyError, TypeError, ValueError) as exc:
            log.warning(
                "PeerTube /users/me missing/malformed identity fields: %s",
                exc,
            )
            self._sso_json_response(
                502,
                {"error": "userinfo_malformed"},
                marker_until=_failure_marker(),
            )
            return

        # Send the success response through ``_sso_json_response``
        # so HEAD handling, Content-Length, CRLF-injection-proof
        # marker-cookie construction, and OSError robustness all
        # share one code path with the failure responses above.
        self._sso_json_response(
            200,
            {
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "token_type": tokens["token_type"],
                "expires_in": expires_in,
                "user": {
                    "id": user_id,
                    "username": username,
                    "email": email,
                    "role_id": role_id,
                },
            },
            marker_until=marker_until,
        )

    def _handle_sso_logout(self) -> None:
        """Clears the marker cookie so the next visit re-trampolines.

        Doesn't actually revoke the PeerTube OAuth token (PeerTube
        has its own /api/v1/users/revoke-token for that, which the
        SPA already calls during its logout flow).  All we need to
        do here is wipe the marker so the sidecar will re-trigger
        the trampoline on the next owner visit, which in turn will
        replace the stale localStorage tokens.

        Anti-CSRF: we require POST AND a custom header
        ``X-Requested-With: XMLHttpRequest``.  POST alone isn't
        enough — a cross-site ``<form method="POST">`` submission
        IS allowed by SameSite=Lax (Lax blocks cross-site requests
        that aren't top-level navigations, but a top-level form
        POST IS a top-level navigation).  Requiring a custom
        header IS sufficient: HTML forms cannot set arbitrary
        request headers, only the same Content-Type values a form
        already supports.  ``XMLHttpRequest`` / ``fetch()`` from
        same-origin JS can set the custom header without
        triggering a CORS preflight (because the header value
        ``XMLHttpRequest`` is on the CORS-safelisted-request-header
        list under "X-Requested-With").
        """
        if self.command not in ("POST",):
            self._safe_send_error(405, "Method Not Allowed")
            return
        xrw = self.headers.get("X-Requested-With", "").strip().lower()
        if xrw != "xmlhttprequest":
            log.info(
                "rejecting /__openhost-sso/logout without X-Requested-With"
            )
            self._safe_send_error(403, "X-Requested-With header required")
            return
        # ``_build_marker_cookie`` already gates ``Secure`` on
        # ``X-Forwarded-Proto`` so the unset Set-Cookie addresses
        # the same cookie scope as the original.  A mismatched
        # attribute set can leave the browser holding onto the
        # original cookie because it treats the unset as a
        # different cookie.  Pass marker_until=0 so the value and
        # Max-Age both expire immediately.
        unset_cookie = self._build_marker_cookie(0)
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", "0")
            self.send_header("Set-Cookie", unset_cookie)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
        except OSError as exc:
            log.debug("client disconnected mid-SSO logout: %s", exc)

    def _sso_json_response(
        self,
        code: int,
        body: dict,
        marker_until: int | None = None,
    ) -> None:
        """Send a JSON response from a sidecar SSO endpoint.

        Honours HEAD per RFC 9110 §9.3.2 by skipping the body write
        but keeping the Content-Length so the client knows the size
        a GET would have returned.

        ``marker_until`` optionally sets the SSO marker cookie to
        the given unix timestamp.  Used by the mint-failure path to
        prevent a redirect loop when PeerTube is briefly unavailable.
        """
        body_bytes = json.dumps(body).encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body_bytes)))
            self.send_header("Cache-Control", "no-store, max-age=0")
            if marker_until is not None:
                self.send_header(
                    "Set-Cookie",
                    self._build_marker_cookie(marker_until),
                )
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body_bytes)
        except OSError as exc:
            log.debug("client disconnected mid-SSO error response: %s", exc)

    def _build_marker_cookie(self, marker_until: int) -> str:
        """Build the marker-cookie ``Set-Cookie`` header value.

        Centralises the cookie-attribute construction so the mint,
        logout, and failure paths all stay in sync.  ``Secure`` is
        added only on HTTPS — see the inline comment in
        ``_handle_sso_mint_token`` for why.

        ``X-Forwarded-Proto`` parsing is strict: we split on commas
        (multi-hop proxies prepend additional values) and check
        whether ANY token is exactly ``https``.  A naive substring
        check would mis-classify a value like ``nothttps`` or
        ``https-variant`` as HTTPS.
        """
        xfp = self.headers.get("X-Forwarded-Proto", "").lower()
        # Tokens are comma-separated per RFC 7239; whitespace-tolerant.
        is_https = any(
            tok.strip() == "https" for tok in xfp.split(",")
        )
        max_age = max(0, marker_until - int(time.time()))
        attrs = [
            f"{SSO_MARKER_COOKIE}={marker_until}",
            f"Max-Age={max_age}",
            "Path=/",
            "SameSite=Lax",
        ]
        if is_https:
            attrs.append("Secure")
        return "; ".join(attrs)

    # ----------------------------------------------------------------
    # Pass-through proxy
    # ----------------------------------------------------------------
    def _proxy(self) -> None:
        # WebSocket upgrade: PeerTube uses /socket.io for live
        # transcoding job updates and the embed player.  These
        # requests carry ``Upgrade: websocket`` and ``Connection:
        # Upgrade``.  Our normal HTTP proxy path strips Upgrade
        # and Connection (hop-by-hop) and forces ``Connection:
        # close``, which would break the handshake.  Detect the
        # upgrade and switch to a raw bidirectional TCP forwarding
        # mode that doesn't touch any headers.  This still strips
        # the SSO trust headers ahead of the upgrade, so an
        # attacker can't forge owner identity over a WebSocket.
        if self._is_websocket_upgrade():
            self._proxy_websocket()
            return

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

    def _is_websocket_upgrade(self) -> bool:
        """True if the request is a WebSocket upgrade per RFC 6455 §4.1."""
        upgrade = self.headers.get("Upgrade", "").lower().strip()
        connection = self.headers.get("Connection", "").lower()
        # ``Connection`` is comma-separated; check for ``upgrade``
        # as one of the tokens.
        connection_tokens = {t.strip() for t in connection.split(",")}
        return upgrade == "websocket" and "upgrade" in connection_tokens

    def _proxy_websocket(self) -> None:
        """Forward a WebSocket upgrade request bidirectionally.

        We open a TCP connection to upstream, send the entire
        request (including the Upgrade + Connection: Upgrade
        headers, and the WebSocket-specific Sec-WebSocket-* trio),
        read the 101 Switching Protocols response, write it back to
        the client, and then shuffle bytes in both directions until
        either side closes.  The auth-proxy's normal hop-by-hop
        stripping and Connection:close forcing are deliberately
        bypassed for this path because they would break the
        handshake.

        We DO strip the SSO trust headers
        (X-OpenHost-User / X-OpenHost-Is-Owner) before forwarding,
        same as the HTTP path, so a hostile client can't forge
        owner identity through a WebSocket request.
        """
        # Headers to forward to upstream: drop only the trust
        # headers and Host (we'll re-write Host below).  Keep
        # Upgrade, Connection, and the Sec-WebSocket-* headers
        # intact — those are part of the handshake.
        ws_drop = ALWAYS_STRIP_HEADERS | frozenset({"host"})
        cleaned = _strip_headers(self.headers.items(), ws_drop)

        try:
            upstream_sock = socket.create_connection(
                (self.upstream_host, self.upstream_port),
                timeout=STREAM_TIMEOUT_SECONDS,
            )
        except OSError as exc:
            log.warning("upstream connect failed (websocket): %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return

        try:
            upstream_sock.settimeout(STREAM_TIMEOUT_SECONDS)
            # Build the request.  We send raw bytes so we don't
            # have to navigate http.client's framing code path
            # (which doesn't expose a clean way to defer the
            # connection's close after the response has been
            # parsed).
            request_bytes = bytearray()
            request_bytes.extend(
                self._encode_header_bytes(
                    f"{self.command} {self.path} HTTP/1.1\r\n"
                )
            )
            request_bytes.extend(
                self._encode_header_bytes(
                    f"Host: {self.upstream_host}:{self.upstream_port}\r\n"
                )
            )
            for k, v in cleaned:
                request_bytes.extend(
                    self._encode_header_bytes(f"{k}: {v}\r\n")
                )
            request_bytes.extend(b"\r\n")
            try:
                upstream_sock.sendall(bytes(request_bytes))
            except OSError as exc:
                log.warning("websocket request send failed: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            # Read the 101 response (or rejection) and any small
            # remainder bytes that the upstream might have
            # pipelined into the same packet.  Use the socket
            # directly (not makefile) so leftover bytes go straight
            # into the bidirectional copy.
            response_buf = self._read_until_double_crlf(
                upstream_sock, max_bytes=HEADER_LINE_CAP
            )
            if response_buf is None:
                self._safe_send_error(502, "Bad Gateway")
                return
            head_bytes, tail_bytes = response_buf

            # Forward the response head verbatim to the client.
            # We do NOT use BaseHTTPRequestHandler.send_response_*
            # here because we want to preserve every header as-is
            # (including Upgrade + Connection + Sec-WebSocket-Accept).
            try:
                self.wfile.write(head_bytes)
                if tail_bytes:
                    self.wfile.write(tail_bytes)
                self.wfile.flush()
            except OSError as exc:
                log.debug("client disconnected during ws handshake: %s", exc)
                return

            # Bail if upstream rejected the upgrade — no bidirectional
            # phase needed.  We do a lazy parse just to log; the
            # client already has whatever upstream said.
            if not head_bytes.startswith(b"HTTP/1.1 101"):
                log.info("upstream rejected websocket upgrade")
                return

            # Bidirectional byte shuffling until either side
            # closes.  Use a poll loop in two threads (or
            # selectors) — selectors is simpler and works in a
            # single thread.
            self._websocket_pump(self.connection, upstream_sock)
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
    def _read_until_double_crlf(
        sock: socket.socket, max_bytes: int
    ) -> tuple[bytes, bytes] | None:
        """Read bytes from ``sock`` until ``\\r\\n\\r\\n``.

        Returns ``(head_including_terminator, leftover_bytes)`` or
        ``None`` on EOF / overflow / socket error.  ``leftover_bytes``
        is whatever bytes were read past the header terminator in
        the same recv() — typically empty for a WebSocket handshake
        but a misbehaving upstream COULD pipe data immediately after
        the headers.

        OSError (incl. socket.timeout) is caught and treated as a
        failure, since the call site can't drive a different
        response when this returns.
        """
        buf = bytearray()
        while True:
            try:
                chunk = sock.recv(4096)
            except OSError as exc:
                log.info("websocket handshake recv failed: %s", exc)
                return None
            if not chunk:
                return None
            buf.extend(chunk)
            idx = buf.find(b"\r\n\r\n")
            if idx >= 0:
                head = bytes(buf[: idx + 4])
                tail = bytes(buf[idx + 4 :])
                return head, tail
            if len(buf) >= max_bytes:
                log.warning(
                    "websocket response head exceeds %d bytes; aborting",
                    max_bytes,
                )
                return None

    @staticmethod
    def _websocket_pump(
        client_sock: socket.socket, upstream_sock: socket.socket
    ) -> None:
        """Bidirectionally forward bytes between two sockets.

        Returns when either socket closes.  Uses ``selectors`` so a
        single thread can wait on both directions; this matches the
        pattern Caddy / nginx use for WebSocket reverse-proxying.
        """
        import selectors

        # Reset both sockets to a much shorter timeout for the
        # bidirectional phase: the original 30-minute end-to-end
        # cap is fine, but a per-recv timeout helps detect dead
        # sockets faster.  We use blocking mode + selectors-based
        # readiness rather than non-blocking + EAGAIN, which is
        # simpler.
        for s in (client_sock, upstream_sock):
            try:
                s.settimeout(None)
            except OSError:
                pass

        # Construct + register inside the try so a register failure
        # (already-closed socket) still hits the finally and closes
        # the selector — otherwise the selector's epoll/kqueue FD
        # would leak.
        sel = selectors.DefaultSelector()
        try:
            sel.register(client_sock, selectors.EVENT_READ, "client")
            sel.register(upstream_sock, selectors.EVENT_READ, "upstream")
            while True:
                events = sel.select(timeout=STREAM_TIMEOUT_SECONDS)
                if not events:
                    log.info("websocket idle timeout; closing")
                    return
                for key, _ in events:
                    if key.data == "client":
                        src, dst = client_sock, upstream_sock
                        direction = "client→upstream"
                    else:
                        src, dst = upstream_sock, client_sock
                        direction = "upstream→client"
                    try:
                        chunk = src.recv(STREAM_CHUNK_BYTES)
                    except OSError as exc:
                        # Match _stream_inner's IO-error log level
                        # (INFO) so a network drop mid-WebSocket is
                        # visible at the default log level.
                        log.info(
                            "websocket %s recv failed: %s",
                            direction, exc,
                        )
                        return
                    if not chunk:
                        # Clean half-close from the source.  Common
                        # at the end of a normal WebSocket session
                        # (Close frame sent then peer closes its
                        # send-side); log at DEBUG.
                        log.debug("websocket %s EOF; closing", direction)
                        return
                    try:
                        dst.sendall(chunk)
                    except OSError as exc:
                        log.info(
                            "websocket %s sendall failed: %s",
                            direction, exc,
                        )
                        return
        finally:
            try:
                sel.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("websocket selector close failed: %s", exc)

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

    Decoding uses ``errors="strict"`` so a non-UTF-8 byte in the
    file (corrupted save / wrong file pointed at) fails immediately
    with a clear UnicodeDecodeError instead of silently substituting
    U+FFFD into the password and producing every PeerTube auth as
    a 401 with no obvious cause.
    """
    try:
        with open(path, "rb") as f:
            first_line = f.readline()
    except OSError as exc:
        raise RuntimeError(
            f"cannot read admin password from {path}: {exc}"
        ) from exc
    try:
        pw = first_line.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise RuntimeError(
            f"admin password file {path} is not valid UTF-8: {exc}"
        ) from exc
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
