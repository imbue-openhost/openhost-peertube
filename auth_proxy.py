"""OpenHost auth-sidecar for PeerTube — owner SSO without breaking federation.

A thin reverse proxy that sits between the OpenHost router and the
Caddy → PeerTube backend.  Two responsibilities:

1. Anonymous + federation pass-through.  Almost every URL on a
   PeerTube instance is reachable without login: a remote Mastodon
   server fetches an actor object, an anonymous browser watches a
   public video, the federated player downloads HLS chunks, the
   bittorrent tracker accepts WebTorrent peers.  All of these paths
   pass through this sidecar untouched — same body, same headers,
   no SSO header injected, no Authorization header rewritten.

2. Owner SSO bounce.  When the zone owner (someone holding a
   router-issued ``zone_auth`` JWT cookie, ``sub == "owner"``)
   visits the SPA root or any non-federation HTML page WITHOUT a
   ``openhost_pt_sso_marker`` cookie, the sidecar redirects them
   to ``/plugins/auth-openhost-sso/router/auto-login`` — a route
   exposed by the bundled
   ``peertube-plugin-auth-openhost-sso`` plugin.  The plugin
   verifies the same JWT against the same JWKS and calls
   PeerTube's standard ``userAuthenticated`` external-auth
   helper, which generates a one-time ``externalAuthToken``
   and redirects the browser to ``/login?externalAuthToken=…``.
   The SPA's ordinary login page exchanges that token for OAuth
   credentials via the standard ``/api/v1/users/token`` endpoint
   and runs its full native login flow — which primes
   ``localStorage`` exactly the way a real password login does.

   The sidecar sets ``openhost_pt_sso_marker`` on the bounce
   redirect so the SPA's post-login navigations don't trigger
   another bounce while the SPA is in the middle of exchanging
   the token.  The marker has a short TTL (5 minutes) — long
   enough to cover the redirect chain plus normal navigation,
   short enough that an owner who explicitly logs out of
   PeerTube gets a fresh SSO bounce on their next page load
   instead of being stuck anonymous.

Routing the actual sign-in through PeerTube's plugin API
(rather than priming ``localStorage`` from this sidecar) keeps
the SPA's auth bootstrap entirely inside PeerTube.  The SPA
reads several localStorage keys on boot to reconstruct an
authenticated user (the OAuth token triple plus four user-
identity fields); the externalAuthToken round-trip writes all
of them via PeerTube's native code paths so the sidecar never
has to track the SPA's internal storage contract.

Federation is wholly unaffected: remote ActivityPub servers
don't carry ``zone_auth``, don't reach the bounce, and see
verbatim pass-through.

Anonymous web visitors are also unaffected: no ``zone_auth``,
no bounce.

Header sanitation: client-supplied ``X-OpenHost-User`` and
``X-OpenHost-Is-Owner`` headers are stripped on every request
that this sidecar PROXIES UPSTREAM.  These are the headers the
OpenHost router uses to assert owner identity to apps; forging
them must never grant privilege downstream.

We do NOT strip ``Authorization``: the SPA, mobile app, and any
third-party PeerTube client carries its OAuth2 access token in
that header, and forwarding it untouched is precisely how the
mobile app + third-party clients keep working.  ``Authorization``
is application-level auth that PeerTube validates against its own
token store — the auth-proxy has no business stripping or
inspecting it.
"""

from __future__ import annotations

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

# Plugin route the sidecar redirects owner navigations to.  The
# matching plugin source lives in ``peertube-plugin-auth-openhost-sso/``
# and is installed onto the running PeerTube instance by
# ``start.sh`` on first boot via ``POST /api/v1/plugins/install``.
# We use the un-versioned form of the plugin custom-router URL
# (``/plugins/<name>/router/<route>``) so a plugin version bump
# doesn't require also updating this constant.
SSO_BOUNCE_PATH = "/plugins/auth-openhost-sso/router/auto-login"

# Marker cookie the sidecar sets when it bounces an owner to the
# plugin auto-login route.  Presence (regardless of value) means
# "skip the bounce" — the owner is in the middle of, or has
# recently completed, the SSO flow.  The cookie has a short TTL
# (see SSO_MARKER_TTL_SEC); when it expires, the next owner
# navigation re-bounces through the plugin.  A re-bounce on an
# already-logged-in SPA is harmless: the plugin redirects to
# /login with a fresh externalAuthToken, the SPA's login page
# exchanges it (silently, since the SPA is already in a logged-in
# state), and updates localStorage with the refreshed tokens.
SSO_MARKER_COOKIE = "openhost_pt_sso_marker"

# How long the marker cookie lives.  Five minutes is plenty for
# the redirect chain (auto-login -> login?externalAuthToken=… ->
# /api/v1/users/token -> /) to complete with margin for slow
# networks, but short enough that a logged-out owner gets
# re-bounced the next time they visit the page after their
# explicit logout.
SSO_MARKER_TTL_SEC = 5 * 60

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
# Federation surface — paths that NEVER trigger the SSO bounce.
#
# These are the URL families a remote ActivityPub server, a federated
# video player on another instance, or an anonymous web viewer needs
# to reach.  They are wholly orthogonal to owner-SSO; we still strip
# trust headers and do not stamp Authorization on these paths.
#
# We don't NEED to enumerate every public path here — for an anonymous
# visitor with no zone_auth cookie, the bounce isn't triggered anyway,
# so the bypass list is only relevant to OWNER traffic.  But being
# explicit about which paths skip the bounce avoids surprising a
# Mastodon-server-behind-its-own-zone or an owner who happens to be
# following another zone account into accidentally bouncing through
# the SSO flow when they request remote content.
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
    # the SSO bounce; including them under a wildcard would skip
    # the bounce incorrectly.
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
    # own login flow (including the post-SSO externalAuthToken
    # exchange) and by any third-party app needing to authenticate.
    re.compile(r"^/api/v1/oauth-clients(/|$)"),
    re.compile(r"^/api/v1/users/token$"),
    re.compile(r"^/api/v1/users/revoke-token$"),
    # The login page itself — we just bounced the owner here from
    # the plugin's auto-login route.  Bouncing them BACK would
    # produce a redirect loop.  (The /plugins/* prefix below also
    # protects the plugin's own routes from being bounced.)
    re.compile(r"^/login(/|$|\?)"),
    # SPA assets — anonymous viewers need these to load the
    # client.  Asset paths are loaded with Accept: */* anyway so
    # the bounce filter wouldn't fire on them, but listing them
    # explicitly is documentation-as-code.
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

        # Owner-bounce check: do we redirect this navigation to
        # the plugin's auto-login route?  Only if all of:
        #   * the request looks like a top-level navigation (HTML
        #     accept), so we don't bounce an XHR or asset fetch
        #     (which would corrupt the SPA's view of itself);
        #   * the visitor IS the zone owner — verified by the
        #     RS256 JWT signature on the zone_auth cookie;
        #   * the request isn't already part of the federation/
        #     anonymous surface (federation must never be
        #     bounced — remote ActivityPub servers never carry
        #     zone_auth anyway, but the explicit allow-list is
        #     also our defense against misconfigured paths);
        #   * the marker cookie isn't already present.  The
        #     marker is the "I just bounced you, don't re-bounce"
        #     flag we set on the bounce response and that the
        #     browser sends back on every subsequent navigation
        #     until it expires.
        cookies = _parse_cookie_header(self.headers.get("Cookie"))
        zone_token = cookies.get(ZONE_COOKIE, "")
        # Presence-only check (any value, including empty string)
        # matches the documented contract on SSO_MARKER_COOKIE: the
        # marker says "I just bounced you, don't re-bounce" and the
        # value is irrelevant.  ``in`` on the parsed cookie dict is
        # the cleanest way to express that.
        has_marker = SSO_MARKER_COOKIE in cookies

        is_owner = False
        if zone_token and self.jwks is not None:
            is_owner = _verify_owner(zone_token, self.jwks)

        accept = self.headers.get("Accept", "")
        is_html_navigation = (
            self.command == "GET"
            and "text/html" in accept.lower()
            and not _is_federation_path(self.path)
        )

        if is_owner and is_html_navigation and not has_marker:
            self._redirect_to_plugin_auto_login()
            return

        # Pass through.
        self._proxy()

    # ----------------------------------------------------------------
    # Owner-SSO bounce
    # ----------------------------------------------------------------
    def _redirect_to_plugin_auto_login(self) -> None:
        """Redirect the owner to the plugin's auto-login route.

        Sets the marker cookie at the same time so the redirect
        chain (``/auto-login`` -> ``/login?externalAuthToken=…``
        -> ``/api/v1/users/token`` -> SPA bootstrap) doesn't
        re-bounce on the way back.

        The ``next=`` query param is the original path the visitor
        was trying to reach.  ``_safe_next_path`` validates and
        sanitises it (rejects absolute URLs, scheme-relative
        URLs, and other open-redirect shapes) so we never echo
        an attacker-controlled location back as the bounce
        target.  ``urllib.parse.urlencode`` then percent-encodes
        the (already-validated) value into the query string.
        The plugin currently ignores ``next`` (it always lands
        on ``/login`` after the externalAuthToken round-trip and
        then the SPA decides where to navigate), but we pass it
        through for forward compatibility with a future plugin
        version that honours it.
        """
        next_url = _safe_next_path(self.path)
        target = SSO_BOUNCE_PATH + "?" + urllib.parse.urlencode({"next": next_url})
        # The marker's expiry timestamp is used by
        # ``_build_marker_cookie`` to compute the ``Max-Age``
        # attribute, and is also written verbatim as the cookie
        # value for human debuggability — an operator inspecting
        # the cookie in their browser dev tools can read off when
        # the marker will expire instead of having to compute it
        # from Max-Age.  The dispatch-layer presence check
        # (``SSO_MARKER_COOKIE in cookies``) ignores the value
        # entirely; only Max-Age governs when the browser stops
        # sending it.
        marker_expires_at = int(time.time() + SSO_MARKER_TTL_SEC)
        try:
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header(
                "Set-Cookie", self._build_marker_cookie(marker_expires_at)
            )
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        except OSError as exc:
            log.debug("client disconnected during SSO bounce: %s", exc)

    def _build_marker_cookie(self, marker_expires_at: int) -> str:
        """Build the marker-cookie ``Set-Cookie`` header value.

        ``Secure`` is added only on HTTPS — set based on the
        ``X-Forwarded-Proto`` header the OpenHost router stamps.
        We can't unconditionally set ``Secure`` because the
        development OpenHost router serves zones over plain HTTP
        on lvh.me / localhost, and the browser would silently
        drop a ``Secure`` cookie on a plain-HTTP page.

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
        max_age = max(0, marker_expires_at - int(time.time()))
        attrs = [
            f"{SSO_MARKER_COOKIE}={marker_expires_at}",
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


def main() -> int:
    router_url = os.environ.get("OPENHOST_ROUTER_URL", "").strip()
    if not router_url:
        log.error("OPENHOST_ROUTER_URL is not set; refusing to start")
        return 1

    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 9000)
        # AUTH_PROXY_UPSTREAM_PORT is the port Caddy listens on (Caddy
        # is the Host-rewriter that fronts PeerTube).  All
        # pass-through traffic flows AUTH_PROXY → Caddy → PeerTube.
        upstream_port = _port_from_env("AUTH_PROXY_UPSTREAM_PORT", 9090)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    upstream_host = os.environ.get(
        "AUTH_PROXY_UPSTREAM_HOST", "127.0.0.1"
    ).strip() or "127.0.0.1"

    jwks = JwksCache(router_url)
    jwks.prefetch()

    AuthProxyHandler.jwks = jwks
    AuthProxyHandler.upstream_host = upstream_host
    AuthProxyHandler.upstream_port = upstream_port

    try:
        server = IPv4ThreadingServer(("0.0.0.0", listen_port), AuthProxyHandler)
    except OSError as exc:
        log.error(
            "failed to bind auth-proxy listener on 0.0.0.0:%d: %s",
            listen_port, exc,
        )
        return 1

    log.info(
        "listening on 0.0.0.0:%d -> %s:%d (router=%s, sso_bounce=%s)",
        listen_port, upstream_host, upstream_port, router_url, SSO_BOUNCE_PATH,
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
