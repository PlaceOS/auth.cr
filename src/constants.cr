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

  # Session cookie name and path.
  #
  # This MUST NOT reuse the legacy Rails name `_coauth_session`. The wire
  # format is incompatible (Rails MessageEncryptor vs action-controller), so a
  # Rails-issued `_coauth_session` is `InvalidSignature` to us. Sharing the
  # name looked harmless ("old cookie → re-prompt") but is not: (1) the failing
  # parse strips the in-session OAuth `state`, so the very re-prompt (SSO)
  # 401s with "oauth state mismatch"; and (2) Rails set the cookie at the
  # default `Path=/` while ours is `Path=/auth`, so the two SAME-NAMED cookies
  # coexist — the browser sends both, we read the stale Rails one, and we can
  # never overwrite a `Path=/` cookie by writing `Path=/auth`. The result was a
  # PERMANENT lockout for anyone with a Ruby-era session (PPT-2536, reported on
  # dev). Using a distinct name sidesteps the collision in both cutover
  # directions; the orphaned `_coauth_session` is simply ignored.
  SESSION_COOKIE_NAME = "_placeos_auth_session"
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
      # This diagnostic used to carry `unless PROD`, which inverted it: it
      # spoke up in development, where an ephemeral key is harmless and the
      # box gets restarted constantly anyway, and went SILENT in production,
      # where an ephemeral key is the whole B.2 incident — every restart
      # invalidates every session, and under k8s each replica derives a
      # DIFFERENT key, so logins fail depending on which pod answers. The one
      # signal a misconfigured production deployment would ever get was
      # switched off precisely there.
      #
      # Escalated rather than merely un-suppressed: in production this is a
      # deployment fault, not a note. Not fatal — Rails refuses to boot
      # without `secret_key_base` and that is arguably right here too, but
      # auth.cr is the login path and CFG-02 (whether helm actually delivers
      # SECRET_KEY_BASE) is still open, so failing closed today could take a
      # rollout down over a gap we have not finished measuring. Revisit once
      # CFG-02 is settled.
      if PROD
        Log.error { "neither COOKIE_SESSION_SECRET nor SECRET_KEY_BASE is set in production — using an ephemeral session key: every restart will log all users out, and multiple replicas will not share sessions" }
      else
        Log.warn { "neither COOKIE_SESSION_SECRET nor SECRET_KEY_BASE set — generating an ephemeral key, sessions will not survive a restart" }
      end
      Random::Secure.hex(32)
    end
  end

  # OIDC issuer claim. Kept as "POS" so existing services keep validating
  # tokens issued before the cutover.
  JWT_ISSUER = ENV["JWT_ISSUER"]? || "POS"

  class_getter? production : Bool = PROD
end
