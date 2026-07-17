module PlaceOS::Auth
  APP_NAME    = "auth"
  API_VERSION = "v2"

  Log = ::Log.for(self)

  # Calculate version, build time, commit at compile time
  VERSION      = {{ system(%(shards version "#{__DIR__}")).chomp.stringify.downcase }}
  BUILD_TIME   = {{ system("date -u").stringify }}
  BUILD_COMMIT = {{ env("PLACE_COMMIT") || "DEV" }}

  # Runtime environment
  PROD = ENV["SG_ENV"]?.try(&.downcase) == "production"

  # PlaceOS API used for API-key inspection. Kept for compatibility with
  # the legacy `auth` service that delegated `X-API-Key` validation to
  # the core engine; nil disables that fallback path.
  PLACE_URI = ENV["PLACE_URI"]?

  # Base64-encoded RSA private key used to sign issued JWTs (RS256).
  # The Ruby service used the matching public key under the same name;
  # rotating this value is a breaking change for token consumers.
  JWT_SECRET = ENV["JWT_SECRET"]?

  # HMAC-SHA256 key for the nginx-validated `verified` asset-access cookie.
  # nginx renders this SAME env var into its access_by_lua_block
  # (`local secret = "${SECRET_KEY_BASE}"`, nginx.conf.template) and
  # recomputes the signature on every SPA asset request. It MUST equal the
  # value auth uses here (and the legacy Rails `secret_key_base`) or nginx
  # rejects every cookie we issue and bounces the browser into an
  # /auth/login redirect loop. Defaults to "" so auth still agrees with
  # nginx when neither has it set (dev boxes).
  SECRET_KEY_BASE = ENV["SECRET_KEY_BASE"]?.presence || begin
    Log.error { "SECRET_KEY_BASE unset — `verified` cookie will use an empty HMAC key; set it to the value nginx uses or the SPA hits a login redirect loop" } if PROD
    ""
  end

  # Default token + session lifetimes (per-Authority override available
  # via `authority.internals["session_timeout"]`).
  SESSION_TIMEOUT_MINUTES = (ENV["SESSION_TIMEOUT_MINUTES"]? || "1440").to_i

  # Redis channel that receives `{user_id, provider}` JSON after each
  # successful login (consumed by PlaceOS to invalidate caches etc.).
  REDIS_URL            = ENV["REDIS_URL"]?
  LOGIN_EVENTS_CHANNEL = ENV["LOGIN_EVENTS_CHANNEL"]? || "placeos/auth/login"

  # Session cookie name and path. The wire format is not compatible with
  # the legacy Rails `_coauth_session`; we keep the name for nginx route
  # familiarity but anyone holding an old cookie will be re-prompted to
  # sign in at cutover, which is fine.
  SESSION_COOKIE_NAME = "_coauth_session"
  SESSION_COOKIE_PATH = "/auth"

  # Secret used by `ActionController::Session::MessageEncryptor` to
  # encrypt + sign the session cookie. Must be at least 32 bytes for
  # AES-256. In production this MUST be set; the dev fallback generates
  # a new key per boot, which deliberately invalidates existing cookies.
  COOKIE_SESSION_SECRET = ENV["COOKIE_SESSION_SECRET"]? || begin
    Log.warn { "COOKIE_SESSION_SECRET not set — generating an ephemeral key, sessions will not survive a restart" } unless PROD
    Random::Secure.hex(32)
  end

  # OIDC issuer claim. Kept as "POS" so existing services keep validating
  # tokens issued before the cutover.
  JWT_ISSUER = ENV["JWT_ISSUER"]? || "POS"

  class_getter? production : Bool = PROD
end
