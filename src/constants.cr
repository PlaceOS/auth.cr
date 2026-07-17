require "digest/sha256"

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
  # AES-256.
  #
  # Resolution order:
  #   1. `COOKIE_SESSION_SECRET` if explicitly provided.
  #   2. Otherwise derive a stable key from `SECRET_KEY_BASE` — the secret
  #      the platform already wires for auth's session cookies. It's the
  #      same value nginx uses for the asset-access cookie and what the
  #      legacy Rails/Doorkeeper service derived its session key from, and
  #      it is present in BOTH the docker-compose (`.env.secret_key`) and
  #      k8s (`auth.secrets.SECRET_KEY_BASE`) deployments — unlike
  #      `PLACE_SERVER_SECRET`, which is NOT provided to the auth pod in
  #      k8s. It is stable across restarts and identical across replicas,
  #      so sessions survive a redeploy. SHA-256'd (not used raw) so it is
  #      namespaced away from the raw-HMAC use of the same secret and is
  #      always the right length.
  #   3. Only if neither is set (a bare dev box) do we fall back to an
  #      ephemeral per-boot key, which deliberately invalidates cookies.
  COOKIE_SESSION_SECRET = ENV["COOKIE_SESSION_SECRET"]?.presence || begin
    if secret_key_base = ENV["SECRET_KEY_BASE"]?.presence
      Digest::SHA256.hexdigest("auth.cr/cookie-session/#{secret_key_base}")
    else
      Log.warn { "neither COOKIE_SESSION_SECRET nor SECRET_KEY_BASE set — generating an ephemeral key, sessions will not survive a restart" } unless PROD
      Random::Secure.hex(32)
    end
  end

  # OIDC issuer claim. Kept as "POS" so existing services keep validating
  # tokens issued before the cutover.
  JWT_ISSUER = ENV["JWT_ISSUER"]? || "POS"

  class_getter? production : Bool = PROD
end
