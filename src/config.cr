# Application dependencies
require "action-controller"

# Application code
require "./placeos-auth"
require "./logging"

# Server required after application controllers
require "action-controller/server"

module PlaceOS::Auth
  # Fields to redact in request logs. Matches rest-api plus a few auth-specific
  # entries we never want on disk.
  filters = ["bearer_token", "secret", "password", "api-key", "client_secret", "code"]

  ActionController::Server.before(
    ActionController::ErrorHandler.new(Auth.production?, ["X-Request-ID"]),
    ActionController::LogHandler.new(filters, ms: true),
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
