# Application dependencies
require "action-controller"

# Application code
require "./placeos-auth"
require "./logging"

# Server required after application controllers
require "action-controller/server"

module PlaceOS::Auth
  # Fields to redact in request logs. Matches rest-api plus the auth-specific
  # entries we never want on disk.
  #
  # `LogHandler#filter_path` matches query keys by EXACT equality, so every
  # credential-bearing parameter needs its own entry — `code` does not cover
  # `code_verifier`. That gap was live: dev's auth log held 37 PKCE verifiers
  # in plaintext, beside their (correctly redacted) `code=[FILTERED]`.
  #
  # A verifier alone is not enough to redeem a code, but it is half of a
  # credential whose other half appears in the authorize redirect — and that
  # redirect lands in nginx's log, the browser's history and any `Referer`.
  # Two logs should not combine into a working login.
  #
  # `token` matters just as much: ts-client's `revokeToken()` calls
  # `POST ${token_uri}?token=${token()}`, so every logout would otherwise
  # write a live access token to stdout.
  #
  # Exposed as a constant so `spec/config_log_filters_spec.cr` asserts against
  # the real list rather than a copy of it.
  LOG_FILTERS = [
    "bearer_token",
    "secret",
    "password",
    "api-key",
    "client_secret",
    "code",
    "code_verifier",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "assertion",
    "SAMLResponse",
  ]

  ActionController::Server.before(
    ActionController::ErrorHandler.new(Auth.production?, ["X-Request-ID"]),
    ActionController::LogHandler.new(LOG_FILTERS, ms: true),
  )

  # Session cookie. Path is locked to `/auth` so the cookie is never sent
  # to other PlaceOS services. Cookie name and path mirror the legacy
  # Rails service so nginx routing rules don't need to change.
  ActionController::Session.configure do |settings|
    settings.key = SESSION_COOKIE_NAME
    settings.secret = COOKIE_SESSION_SECRET
    settings.path = SESSION_COOKIE_PATH
    # SameSite=None (set in session_samesite_patch.cr for embedded/cross-site
    # login parity with the legacy Ruby service) is invalid without Secure, and
    # auth always runs behind HTTPS — mirror the `verified` cookie's
    # unconditional Secure rather than gating on production.
    settings.secure = true
    settings.encrypted = true
  end
end
