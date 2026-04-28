// PeerTube plugin: OpenHost owner SSO via the external-auth API.
//
// Mirrors the openhost-miniflux / openhost-plane.so pattern: the
// OpenHost router signs a `zone_auth` cookie (RS256, JWKS published
// at <router>/.well-known/jwks.json) and, when `sub == "owner"`, we
// log that visitor in as the root PeerTube admin.
//
// Why a plugin instead of a sidecar trampoline?
// PeerTube's SPA stores its OAuth token in localStorage and bootstraps
// auth state by reading several keys (id, username, email, role,
// access_token, refresh_token, token_type) — a sidecar that primes
// these fields is fragile because the SPA keeps shipping bundle-format
// tweaks.  Instead, we use PeerTube's own `registerExternalAuth`
// API: we redirect the owner to a plugin route, that route verifies
// the zone_auth JWT, then calls `userAuthenticated(...)` which makes
// PeerTube generate a one-time `externalAuthToken`, store the user
// payload in a server-side memo, and redirect the browser to
// /login?externalAuthToken=…&username=root.  The SPA's standard
// login page picks the token up, exchanges it via /api/v1/users/token
// (grant_type=password, externalAuthToken=…), and the SPA's own
// native login flow primes localStorage exactly the way a normal
// password login would.  All identity-bootstrap responsibility stays
// inside PeerTube — we only need to vouch for "this visitor is the
// zone owner".
//
// Two entry points are exposed:
//
//   1. /plugins/auth-openhost-sso/router/auto-login
//        Hit by the auth-proxy sidecar via 302 on every owner-HTML
//        navigation that the sidecar hasn't already bounced (i.e.
//        the bounce-marker cookie isn't yet set in the request).
//        The bounce fires regardless of the SPA's own auth state
//        — if the SPA already has valid OAuth tokens in
//        localStorage, redeeming a fresh externalAuthToken just
//        refreshes them, which is harmless.
//
//   2. /plugins/auth-openhost-sso/<version>/auth/openhost-sso
//        PeerTube's standard external-auth URL — the URL that's
//        wired up to the "Login with OpenHost" button on the
//        login form.  Same JWT-verification logic, same
//        userAuthenticated call.  Provides a manual fallback if
//        auto-login hits an edge case.
//
// Both routes share `handleAuthRequest`.  If the cookie is missing
// or fails verification we redirect to /login?externalAuthError=true
// — the SPA renders a generic "couldn't sign you in" message there,
// which is the same surface PeerTube shows for any external-auth
// failure.

'use strict'

const jwt = require('jsonwebtoken')
const jwksClient = require('jwks-rsa')

// Cookie the OpenHost router sets on every authenticated owner
// browser session.  The router signs it RS256; the matching
// public key is at <router>/.well-known/jwks.json.
const ZONE_COOKIE = 'zone_auth'
const OWNER_SUB = 'owner'
const AUTH_NAME = 'openhost-sso'
const AUTH_DISPLAY_NAME = 'OpenHost'
// JWKS cache freshness: we re-fetch keys at most once per this
// interval, but the underlying jwks-rsa client falls back to its
// last successful fetch on transient errors so a router blip
// during refresh doesn't lock the owner out.
const JWKS_CACHE_TTL_MS = 10 * 60 * 1000 // 10 minutes
// Allow a tiny bit of clock skew between the router and the
// PeerTube container.  Matches what the openhost-miniflux and
// openhost-nextcloud sidecars use for the equivalent check.
const JWT_CLOCK_TOLERANCE_SEC = 30

const store = {
  // Set during register().  Read by handleAuthRequest on every
  // request so a config reload (settings change) is visible
  // without a process restart.
  jwks: null,
  routerUrl: null,
  // Captured from the registerExternalAuth() return value.  This
  // is the entry point that makes PeerTube generate the
  // externalAuthToken and redirect the browser to /login.
  userAuthenticated: null,
  // peertubeHelpers.logger snapshot — we hand this to log lines
  // inside route handlers so error traces from the plugin show
  // up alongside upstream PeerTube logs.
  logger: null,
  // Captured admin-email default.  PeerTube validates that
  // userAuthenticated.email is non-empty, so we fall back to a
  // synthesised admin@<webserver-hostname> when the JWT doesn't
  // carry one (the OpenHost router doesn't currently put an
  // email in zone_auth).
  fallbackEmail: null
}

async function register ({
  registerExternalAuth,
  unregisterExternalAuth,
  registerSetting,
  settingsManager,
  peertubeHelpers,
  getRouter
}) {
  const { logger } = peertubeHelpers
  store.logger = logger

  // The router URL is supplied by start.sh as a plugin setting
  // rather than an env var because PeerTube doesn't expose
  // process.env to plugins.  We persist it the same way every
  // upstream auth plugin does: as a registered setting, written
  // by start.sh on first boot via the in-app settings DB.
  registerSetting({
    name: 'openhost-router-url',
    label: 'OpenHost router URL',
    type: 'input',
    private: true,
    descriptionHTML:
      'Internal URL of the OpenHost router used to fetch the JWKS for ' +
      "owner JWT verification (e.g. <code>http://host.containers.internal:8080</code>). " +
      'Set automatically by start.sh on every container boot — ' +
      'operators should not normally touch this.',
    default: ''
  })

  // Build the synthesised admin-email default from the configured
  // webserver hostname.  This is used only when the JWT carries no
  // email claim (the current OpenHost router doesn't include one);
  // PeerTube's external-auth validator rejects an empty email so we
  // need *something* — and "admin@<your-zone>" is the value the
  // sidecar's openhost.toml-time setup already wrote into the root
  // user's profile.
  const webserverUrl = peertubeHelpers.config.getWebserverUrl()
  try {
    const u = new URL(webserverUrl)
    store.fallbackEmail = `admin@${u.hostname}`
  } catch (err) {
    // Fall back to a literal that PeerTube's email validator
    // still accepts.  An invalid webserverUrl is a misconfigured
    // PeerTube instance, not something the plugin should fail
    // closed on — the operator already has a broken instance.
    logger.warn(
      'auth-openhost-sso: cannot parse webserver URL %s; using fallback email',
      webserverUrl
    )
    store.fallbackEmail = 'admin@localhost'
  }

  // Resolve and cache the router URL setting.  Wired up to
  // settingsManager.onSettingsChange so a runtime edit (eg. when
  // the operator manually fixes a broken value) takes effect
  // without a PeerTube restart.
  //
  // Both call sites — the initial load here and the re-load on
  // settings changes — wrap the await in a try/catch.  An
  // unhandled rejection escaping ``register()`` would prevent
  // the plugin from completing registration, leaving PeerTube
  // with a half-installed plugin entry that can't be cleanly
  // removed without a restart.  Logging the error and
  // continuing means the plugin is registered but
  // owner-detection is disabled until the operator fixes the
  // setting — handleAuthRequest already redirects to /login
  // when ``store.jwks`` is null, so this degrades gracefully.
  try {
    await loadRouterSetting(settingsManager)
  } catch (err) {
    logger.error('auth-openhost-sso: initial settings load failed', { err })
  }
  settingsManager.onSettingsChange(async () => {
    try {
      await loadRouterSetting(settingsManager)
    } catch (err) {
      logger.error('auth-openhost-sso: settings reload failed', { err })
    }
  })

  // PeerTube's plugin custom-router mounts at
  // /plugins/<name>/router/<route> AND
  // /plugins/<name>/<version>/router/<route>.  The auth-proxy
  // sidecar uses the un-versioned form so it doesn't have to
  // track plugin version bumps.
  //
  // Express 4 (used by PeerTube 7.x) does NOT auto-await async
  // route handlers — a Promise rejection escaping the handler
  // becomes an UnhandledPromiseRejectionWarning and the client
  // hangs with no response.  Wrap each entry point in
  // ``runHandler`` which awaits and routes any unanticipated
  // rejection through the same login-failure redirect the
  // handler would have returned itself.
  // COUPLING: ``/auto-login`` is the path the auth-proxy
  // sidecar's ``SSO_BOUNCE_PATH`` constant in auth_proxy.py
  // points at.  The two strings must agree; if you rename one,
  // rename the other in the same change.
  const router = getRouter()
  router.get('/auto-login', (req, res) => runHandler(req, res))

  // Standard external-auth registration: shows up as a "Login with
  // OpenHost" button on /login.  Visitors who somehow end up on
  // the login form (eg. clicked a sign-out and then refreshed)
  // can click it to take the same code path the auto-login URL
  // exercises.
  const result = registerExternalAuth({
    authName: AUTH_NAME,
    authDisplayName: () => AUTH_DISPLAY_NAME,
    onAuthRequest: (req, res) => runHandler(req, res)
  })
  store.userAuthenticated = result.userAuthenticated
  // Capture the unregister hook so unregister() can fully tear
  // down the external-auth registration on plugin uninstall /
  // reload, instead of leaving a stale entry pointing at the
  // now-nulled callback.
  store.unregisterExternalAuth = unregisterExternalAuth

  logger.info(
    'auth-openhost-sso: registered (router=%s, auth=%s, fallback_email=%s)',
    store.routerUrl || '(unset)',
    AUTH_NAME,
    store.fallbackEmail
  )
}

async function unregister () {
  // Pull the external-auth registration out of PeerTube's
  // in-memory map so an uninstall / reinstall via the admin UI
  // doesn't leave a stale entry pointing at the now-nulled
  // ``store.userAuthenticated`` callback.  (Settings changes
  // don't flow through here — they call loadRouterSetting()
  // directly via onSettingsChange.)
  if (typeof store.unregisterExternalAuth === 'function') {
    try {
      store.unregisterExternalAuth(AUTH_NAME)
    } catch (err) {
      if (store.logger) {
        store.logger.warn(
          'auth-openhost-sso: unregisterExternalAuth threw',
          { err }
        )
      }
    }
  }
  // The jwks-rsa client we currently use exposes no documented
  // ``.close()``; on the versions PeerTube ships this means the
  // background TTL refresh interval keeps the Node event loop
  // alive until process exit.  Plugin unregister already runs
  // at shutdown / reload so the cost is bounded; we just drop
  // our reference.  If a future jwks-rsa adds an explicit
  // close, ``releaseJwks`` is the central place to call it.
  releaseJwks(store.jwks)
  store.jwks = null
  store.userAuthenticated = null
  store.unregisterExternalAuth = null
}

// Internal helper: synchronous-best-effort cleanup for a
// jwks-rsa client.  Centralised so both ``unregister()`` and
// ``loadRouterSetting()`` (which replaces the client on a
// settings change) handle teardown the same way.
function releaseJwks (client) {
  if (!client) return
  // Some forks / future jwks-rsa releases expose a ``close``
  // method.  We probe and call defensively.
  if (typeof client.close === 'function') {
    try {
      client.close()
    } catch (err) {
      if (store.logger) {
        store.logger.debug('auth-openhost-sso: jwks close failed', { err })
      }
    }
  }
}

// Express-4 wrapper: route handlers must not leak async
// rejections.  Awaits the inner promise and, on any escape,
// emits a generic external-auth-error redirect (idempotent
// even if a previous handler call already wrote headers — we
// guard with res.headersSent).
async function runHandler (req, res) {
  try {
    await handleAuthRequest(req, res)
  } catch (err) {
    if (store.logger) {
      store.logger.error('auth-openhost-sso: handler threw', { err })
    }
    if (!res.headersSent) {
      try {
        res.redirect('/login?externalAuthError=true')
      } catch (redirectErr) {
        // Response already half-sent or socket is closed.
        // Nothing useful to do; swallow so we don't crash the
        // Node process with an UnhandledPromiseRejection.
        if (store.logger) {
          store.logger.debug(
            'auth-openhost-sso: error-path redirect failed',
            { err: redirectErr }
          )
        }
      }
    }
  }
}

module.exports = { register, unregister }

// ----------------------------------------------------------------
// Settings handling
// ----------------------------------------------------------------

// Serialise concurrent loadRouterSetting calls.  PeerTube's
// settings-change subscription can fire in rapid succession (e.g.
// when the admin saves multiple settings in one PUT), and two
// in-flight calls suspended at ``await getSetting`` would both
// resume past the guard, both call ``releaseJwks`` on each
// other's freshly-built clients, and end up with a non-deterministic
// last-writer-wins.  We chain each invocation behind the
// previous one's promise so the URL-comparison guard sees a
// stable view of ``store.routerUrl`` / ``store.jwks``.
let pendingSettingsLoad = Promise.resolve()
function loadRouterSetting (settingsManager) {
  const next = pendingSettingsLoad
    .catch(() => undefined)
    .then(() => loadRouterSettingInner(settingsManager))
  pendingSettingsLoad = next
  return next
}

async function loadRouterSettingInner (settingsManager) {
  const value = (await settingsManager.getSetting('openhost-router-url')) || ''
  const trimmed = value.trim()
  if (!trimmed) {
    // No URL — we can't verify anything.  Drop any old client so
    // a stale URL doesn't continue to be used.  handleAuthRequest
    // checks for null and returns a clean external-auth-error
    // redirect.
    releaseJwks(store.jwks)
    store.routerUrl = null
    store.jwks = null
    if (store.logger) {
      store.logger.warn(
        'auth-openhost-sso: openhost-router-url setting is empty; ' +
        'owner SSO is disabled until it is set'
      )
    }
    return
  }
  // Validate URL up front so we don't rebuild the JWKS client on
  // every settings-change event with a bad value.
  try {
    // eslint-disable-next-line no-new
    new URL(trimmed)
  } catch (err) {
    releaseJwks(store.jwks)
    store.routerUrl = null
    store.jwks = null
    if (store.logger) {
      store.logger.error(
        'auth-openhost-sso: openhost-router-url is not a valid URL: %s',
        trimmed
      )
    }
    return
  }
  if (store.routerUrl === trimmed && store.jwks) return

  // URL changed — release the previous client's resources before
  // dropping our reference to it.  releaseJwks no-ops on null
  // and on clients that don't expose a close method, so this is
  // safe regardless of the current jwks-rsa shape.
  releaseJwks(store.jwks)
  store.routerUrl = trimmed
  store.jwks = jwksClient({
    jwksUri: trimmed.replace(/\/$/, '') + '/.well-known/jwks.json',
    // Cache successful fetches for the configured TTL.  jwks-rsa
    // returns the cached key on every request inside the TTL
    // window without going to network.
    cache: true,
    cacheMaxAge: JWKS_CACHE_TTL_MS,
    cacheMaxEntries: 16,
    // Rate-limit: at most 10 outbound JWKS fetches / minute even
    // under a key-rotation event.  A misbehaving caller cannot
    // turn the router into a JWKS-DDoS target through us.
    rateLimit: true,
    jwksRequestsPerMinute: 10,
    // Fast bail on a hung router.  The TTL above gives us a
    // valid stale-cache fallback if a fetch fails.
    timeout: 5000
  })
}

// ----------------------------------------------------------------
// Auth request handler — shared by /auto-login and
// /<version>/auth/openhost-sso
// ----------------------------------------------------------------

async function handleAuthRequest (req, res) {
  const logger = store.logger
  // ``req.query.next`` is set by the auth-proxy sidecar's
  // bounce as the originally-requested path.  We currently
  // ignore it: PeerTube's ``userAuthenticated`` redirects to
  // /login?externalAuthToken=…, and the SPA's login page picks
  // its own post-login destination from the
  // SESSION_STORAGE_REDIRECT_URL_KEY entry it writes when an
  // anonymous request was deflected to /login.  Honouring
  // ``next`` here would require either passing it as
  // ``externalRedirectUri`` (which PeerTube validates against
  // an allowed-list of URIs and is the wrong layer for an
  // origin-relative path), or adding a custom client-side
  // hook that reads it from the URL and stuffs it into the
  // SPA's redirect storage.  Both add complexity for an edge
  // case (the dashboard tile points at the SPA root anyway),
  // so we accept the parameter for forward compatibility but
  // don't act on it.

  // Misconfiguration: the plugin is registered but settings
  // weren't seeded.  Fail closed — there's no safe default that
  // would still verify the owner.
  if (!store.jwks || !store.userAuthenticated) {
    logger.error(
      'auth-openhost-sso: handler invoked but plugin is not fully configured ' +
      '(jwks=%s, userAuthenticated=%s)',
      Boolean(store.jwks),
      Boolean(store.userAuthenticated)
    )
    return res.redirect('/login?externalAuthError=true')
  }

  const cookie = req.cookies && req.cookies[ZONE_COOKIE]
  if (!cookie) {
    // The visitor isn't signed in to the OpenHost zone (or
    // their cookie has been cleared) — let them log in
    // through the regular form instead of confusing them
    // with a "sign-in failed" page.
    logger.debug('auth-openhost-sso: no zone_auth cookie; redirecting to /login')
    return res.redirect('/login')
  }

  let claims
  try {
    claims = await verifyOwnerJwt(cookie, store.jwks)
  } catch (err) {
    logger.warn('auth-openhost-sso: zone_auth verification failed: %s', err.message)
    return res.redirect('/login?externalAuthError=true')
  }

  if (claims.sub !== OWNER_SUB) {
    logger.warn(
      'auth-openhost-sso: zone_auth verified but sub=%j is not %j; refusing',
      claims.sub,
      OWNER_SUB
    )
    return res.redirect('/login?externalAuthError=true')
  }

  // PeerTube's `userAuthenticated` validator requires a
  // non-empty email.  The router doesn't currently put one in
  // zone_auth (it carries `sub` and `username` only), so we
  // fall back to the synthesised admin email computed at
  // registration time.  Honour an explicit email claim if a
  // future router version starts emitting one.
  const email = (typeof claims.email === 'string' && claims.email.length > 0)
    ? claims.email
    : store.fallbackEmail

  // The PeerTube root admin is always username=root, role=0
  // (Administrator — see UserRole enum in
  // @peertube/peertube-models).  We never let the JWT claim
  // override these because they're the security boundary: the
  // OpenHost zone owner gets the PeerTube admin role, period.
  // Any other visitor is anonymous (zone_auth is owner-only —
  // the OpenHost router does not issue zone_auth cookies to
  // non-owners).
  //
  // ``userAuthenticated`` is declared by PeerTube as returning
  // ``void``: its real work (looking up / creating the user,
  // generating the externalAuthToken, writing the redirect to
  // ``res``) is dispatched async with the failure path wired
  // up internally via ``.catch(err => logger.error(...))``.
  // We don't await it.
  logger.info('auth-openhost-sso: owner verified, calling userAuthenticated')
  try {
    store.userAuthenticated({
      req,
      res,
      username: 'root',
      email,
      role: 0,
      displayName: 'root'
    })
  } catch (err) {
    logger.error('auth-openhost-sso: userAuthenticated call failed', { err })
    return res.redirect('/login?externalAuthError=true')
  }
}

// ----------------------------------------------------------------
// JWT verification helper
// ----------------------------------------------------------------

function verifyOwnerJwt (token, jwks) {
  return new Promise((resolve, reject) => {
    let header
    try {
      const decoded = jwt.decode(token, { complete: true })
      if (!decoded || !decoded.header) {
        return reject(new Error('malformed JWT (no header)'))
      }
      header = decoded.header
    } catch (err) {
      return reject(new Error('JWT decode failed: ' + err.message))
    }

    // We only accept RS256 because the OpenHost router only
    // signs RS256.  Pinning the algorithm at verify-time is the
    // standard mitigation for the "alg=none" / "alg=HS256 with
    // public key as secret" classes of JWT attacks.
    if (header.alg !== 'RS256') {
      return reject(new Error('unexpected JWT alg: ' + header.alg))
    }
    if (!header.kid) {
      return reject(new Error('JWT missing kid header'))
    }

    jwks.getSigningKey(header.kid, (err, key) => {
      if (err) {
        return reject(new Error('JWKS lookup failed: ' + err.message))
      }
      const publicKey = key.getPublicKey()
      jwt.verify(
        token,
        publicKey,
        {
          algorithms: ['RS256'],
          clockTolerance: JWT_CLOCK_TOLERANCE_SEC
        },
        (verr, payload) => {
          if (verr) return reject(new Error('JWT verify failed: ' + verr.message))
          if (typeof payload !== 'object' || !payload) {
            return reject(new Error('JWT payload is not an object'))
          }
          // Reject tokens with no ``exp`` claim.  jsonwebtoken
          // only enforces expiry when ``exp`` is present in the
          // payload — a token that omits the claim entirely is
          // accepted forever.  We require ``exp`` explicitly
          // here so a router-issued token without an expiry
          // can't grant indefinite admin access.  Matches what
          // auth_proxy.py does (PyJWT's ``options={"require":
          // ["exp"]}``) on the same JWT.
          if (typeof payload.exp !== 'number') {
            return reject(new Error('JWT has no exp claim'))
          }
          resolve(payload)
        }
      )
    })
  })
}
