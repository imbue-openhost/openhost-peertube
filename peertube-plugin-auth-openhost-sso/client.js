// Client-side hook for the OpenHost SSO plugin.
//
// PeerTube's SPA shows a "Your authentication has expired, you need
// to reconnect" toast when its OAuth refresh-token POST fails for
// any reason (refresh-token TTL exceeded, oauth-clients/local
// rotated across a PeerTube restart, etc.).  For an OpenHost zone
// owner, the right UX is to silently re-trampoline through the SSO
// plugin's auto-login route — if their zone_auth cookie is still
// valid the SPA picks up where it left off, and if it isn't they
// land on /login the same way the toast's "reconnect" link would
// have taken them.
//
// We hook ``action:auth-user.logged-out`` (which fires both for
// explicit user-initiated logout AND for the failed-refresh
// logout the SPA does internally — both call the same logout()
// path inside the AuthService) and redirect the browser to the
// plugin's auto-login route.  The SSO plugin handler verifies the
// zone_auth JWT against the cached JWKS:
//   * valid owner → ``userAuthenticated`` → /login?externalAuthToken=…
//                    → SPA's standard login flow takes over
//   * no/invalid cookie → /login?externalAuthError=true (same place
//                    the toast's "reconnect" would lead).
//
// Explicit-logout caveat: this hook can't tell user-initiated
// logout apart from refresh-failure logout — the SPA exposes the
// same ``action:auth-user.logged-out`` event for both.  For a
// single-owner zone this is acceptable: clicking Log Out and
// immediately landing back logged in is mildly surprising but
// not broken (if the owner truly wants to leave their PeerTube
// account, they can clear their OpenHost zone_auth cookie via
// the OpenHost dashboard, or use a private browsing window).

'use strict'

// Path the auth-proxy sidecar (auth_proxy.py) bounces owner HTML
// navigations to — see ``SSO_BOUNCE_PATH`` in auth_proxy.py and
// ``router.get('/auto-login', …)`` in this plugin's main.js.
// Changing this path requires updating both other sites in lockstep.
const AUTO_LOGIN_PATH = '/plugins/auth-openhost-sso/router/auto-login'

// Pages we never auto-redirect FROM, even if the SPA reports the
// user as logged out:
//   * /login    — the user is in the middle of an explicit re-login
//                 attempt (OR our SSO failed and bounced them here);
//                 redirecting back to /auto-login would either loop
//                 (if SSO still fails) or steal focus from a manual
//                 re-login attempt.
//   * /signup   — same reasoning.
//   * /admin/...— explicit admin views; reaching them requires
//                 admin auth, so a logout there indicates session
//                 expiry, but redirecting from inside the admin
//                 routing tree confuses the Angular router.  Better
//                 to let the SPA finish its internal logout, then
//                 trigger the bounce on the next plain navigation.
function shouldSkipAutoRelogin () {
  const path = window.location.pathname || '/'
  if (path === '/login' || path.startsWith('/login/')) return true
  if (path === '/signup' || path.startsWith('/signup/')) return true
  if (path.startsWith('/plugins/')) return true
  return false
}

function triggerAutoRelogin () {
  if (shouldSkipAutoRelogin()) return
  // Use replace() so the user's back button doesn't loop them
  // through the just-failed page.  We pass the originally-visited
  // path as ``next`` for forward-compat with a future plugin
  // version that honours it (the current plugin redirects to
  // /login regardless).
  const here = window.location.pathname + window.location.search
  const target = AUTO_LOGIN_PATH + '?next=' + encodeURIComponent(here)
  window.location.replace(target)
}

function register ({ registerHook }) {
  registerHook({
    target: 'action:auth-user.logged-out',
    handler: () => {
      // Defer to the next macrotask so any pending SPA logout-cleanup
      // work (clearing localStorage, calling /api/v1/users/revoke-token)
      // completes before we navigate.  Without the defer, an
      // in-flight revoke-token request would be torn down by the
      // navigation and PeerTube's server-side token list would
      // briefly hold a stale entry.
      setTimeout(triggerAutoRelogin, 0)
    }
  })
}

export { register }
