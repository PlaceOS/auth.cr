require "authly"
require "base64"
require "openssl"

require "./authly_adapter/client"
require "./authly_adapter/claims_provider"
require "./authly_adapter/code_store"
require "./authly_adapter/legacy_refresh"
require "./authly_adapter/owner"
require "./authly_adapter/token_store"

module PlaceOS::Auth::AuthlyAdapter
  Log = ::PlaceOS::Auth::Log.for(self)

  # Hardcoded dev RSA keypair, used only when `JWT_SECRET` is unset.
  # Matches the placeos-models default so tokens encoded by this
  # service round-trip cleanly through `Model::UserJWT.decode` in
  # development. NEVER use in production — `configure!` logs a loud
  # warning when this branch fires.
  DEV_PRIVATE_KEY = <<-KEY
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEAt01C9NBQrA6Y7wyIZtsyur191SwSL3MjR58RIjZ5SEbSyzMG
    3r9v12qka4UtpB2FmON2vwn0fl/7i3Jgh1Xth/s+TqgYXMebdd123wodrbex5pi3
    Q7PbQFT6hhNpnsjBh9SubTf+IeTIFeXUyqtqcDBmEoT5GxU6O+Wuch2GtbfEAmaD
    roy+uyB7P5DxpKLEx8nlVYgpx5g2mx2LufHvykVnx4bFzLezU93SIEW6yjPwUmv9
    R+wDM/AOg60dIf3hCh1DO+h22aKT8D8ysuFodpLTKCToI/AbK4IYOOgyGHZ7xizX
    HYXZdsqX5/zBFXu/NOVrSd/QBYYuCxbqe6tz4wIDAQABAoIBAQCEIRxXrmXIcMlK
    36TfR7h8paUz6Y2+SGew8/d8yvmH4Q2HzeNw41vyUvvsSVbKC0HHIIfzU3C7O+Lt
    9OeiBo2vTKrwNflBv9zPDHHoerlEBLsnNwQ7uEUeTWM9DHdBLwNaLzQApLD6q5iT
    OFW4NfIGpsydIt8R565PiNPDjIcTKwhbVdlsSbI87cLkQ9UuYIMRkvXSD1Q2cg3I
    VsC0SpE4zmfTe7YTZQ5yTxtsoLKPBXrSxhhGuhdayeN7A4YHFYVD39RuQ6/T2w2a
    W/0UaGOk8XWgydDpD5w9wiBdH2I4i6D35IynCcodc5JvmTajzJT+xj6aGjjvMSyq
    q5ZdwJ4JAoGBAOPdZgjbOCf3ONUoiZ5Qw/a4b4xJgMokgqZ5QGBF5GqV1Xsphmk1
    apYmgC7fmab/EOdycrQMS0am2FmtwX1f7gYgJoyWtK4TVkUc5rf+aoWi0ieIsegv
    rjhuiIAc12+vVIbegRgnq8mOI5icrwm6OkwdqHkwTt6VRYdJGEmu67n/AoGBAM3v
    RAd5uIjVwVDLXqaOpvF3pxWfl+cf6PJtAE5y+nbabeTmrw//fJMank3o7qCXkFZR
    F0OJ2tmENwV+LPM8Gy3So8YP2nkOz4bryaGrxQ4eMA+K9+RiACVaKv+tNx/NbyMS
    e9gg504u0cwa60XjM5KUKrmT3RXpY4YIfUPZ1J4dAoGAB6jalDOiSJ2j2G57acn3
    PGTowwN5g9IEXko3IsVWr0qIGZLExOaZxaBXsLutc5KhY9ZSCsFbCm3zWdhgZ7GA
    083i3dj3C970iHA3RToVJJbbj56ltFNd/OGiTwQpLcTsB3iVSFWVDbpsceXacG5F
    JWfd0O0RyaOk6a5IVbm+jMsCgYBglxAOfY4LSE8y6SCM+K3e5iNNZhymgHYPdwbE
    xPMrWgpfab/Evi2dBcgofM+oLU663bAOspMeoP/5qJPGxnNtC7ZbSMZNL6AxBVj+
    ZoW3uHsMXz8kNL8ixecTIxiO5xlwltPVrKExL46hsCKYFhfzcWGUx4DULTLMBCFU
    +M/cFQKBgQC+Ite962yJOnE+bjtSReOrvR9+I+YNGqt7vyRa2nGFxL7ZNIqHss5T
    VjaMgjzVJqqYozNT/74pE/b9UjYyMzO/EhrjUmcwriMMan/vTbYoBMYWvGoy536r
    4n455vizig2c4/sxU5yu9AF9Dv+qNsGCx2e9uUOTDUlHM9NXwxU9rQ==
    -----END RSA PRIVATE KEY-----
    KEY

  # Configures the `authly` shard with our four interface
  # implementations and our JWT signing material.
  #
  # Called once at boot, after PgORM has been configured (we need the
  # DB up before the first request lands).
  def self.configure!
    private_pem, public_pem = load_keys

    ::Authly.configure do |config|
      config.issuer = JWT_ISSUER
      config.algorithm = JWT::Algorithm::RS256
      config.secret_key = private_pem
      config.public_key = public_pem
      config.token_strategy = :jwt
      config.access_ttl = 2.hours
      config.refresh_ttl = 30.days
      config.code_ttl = 10.minutes
      config.owners = Owner.new
      config.clients = Client.new
      config.claims_provider = ClaimsProvider.new
      config.token_store = TokenStore.new
      config.persist_jwt_tokens = true
      config.enforce_pkce = false
      config.allow_dynamic_registration = false
    end
  end

  # Loads the RSA private/public key pair used by both authly and the
  # placeos-models `UserJWT`. Reads `JWT_SECRET` (base64-encoded PEM)
  # and derives the public key from it. Falls back to a known dev key
  # — same one placeos-models ships — when the env var is unset, so
  # tokens still round-trip between auth.cr and other services in dev.
  private def self.load_keys : Tuple(String, String)
    if (encoded = ENV["JWT_SECRET"]?) && encoded.presence
      private_pem = String.new(Base64.decode(encoded))
    else
      Log.warn { "JWT_SECRET not set — using insecure default RSA keypair (DO NOT use in production)" }
      private_pem = DEV_PRIVATE_KEY
    end

    rsa = OpenSSL::PKey::RSA.new(private_pem)
    public_pem = rsa.public_key.to_pem
    {private_pem, public_pem}
  end
end

module Authly
  # Patch: `Authly::Code` captures `ISSUER` (and `CODE_TTL`) into
  # struct-level constants at *class load time*, which happens before
  # any application-level `Authly.configure` call. Codes minted after
  # our `configure!` therefore carry the upstream default issuer
  # ("The Authority Server Provider") while `Authly.jwt_decode` (used
  # by the token endpoint to redeem the code) validates against the
  # currently-configured issuer ("POS") — and the mismatch raises
  # `JWT::InvalidIssuerError`.
  #
  # We override the JWT body to read the live config instead. Same fix
  # applies to the code TTL.
  struct Code
    def jwt
      Authly.jwt_encode({
        "jti"          => Random::Secure.hex(32),
        "code"         => code,
        "challenge"    => challenge,
        "method"       => method,
        "scope"        => scope,
        "user_id"      => user_id,
        "redirect_uri" => redirect_uri,
        "iat"          => Time.utc.to_unix,
        "iss"          => Authly.config.issuer,
        "exp"          => Authly.config.code_ttl.from_now.to_unix,
      })
    end
  end

  # Patch: `Grant#access_token` derives the token's `sub` from
  # `grant_strategy.user_id`, but upstream `AuthorizationCode` never
  # overrides `user_id` (it returns the module default, `nil`), so the
  # authorization-code grant mints a token with a *random* `sub`. The
  # legacy Ruby service (Doorkeeper::JWT) sets `sub` to the resource
  # owner's id — and our `ClaimsProvider` relies on `sub` being a real
  # user id to attach the `aud` + `u{n,e,p,r}` claims. We recover the
  # `user_id` that was captured into the authorization code when it was
  # minted (see the `Code#jwt` patch above).
  class AuthorizationCode
    def user_id : String?
      return nil if @code.empty?
      Authly.jwt_decode(@code).first["user_id"]?.try(&.as_s.presence)
    rescue
      nil
    end

    # SECURITY patch: enforce PKCE at *redemption* (RFC 7636 §4.6).
    #
    # Upstream `verify_challenge!` opens with `return if verifier.empty?`, so
    # a code minted WITH a `code_challenge` can be redeemed by simply omitting
    # `code_verifier` — the challenge baked into the code is never compared.
    # `Authly.config.enforce_pkce` does not close this: it is read only by the
    # *authorize* handler, deciding whether a challenge must be supplied when
    # the code is minted, and is `false` for us anyway.
    #
    # PlaceOS SPAs are PUBLIC clients — ts-client's `createRefreshURL` sends no
    # `client_secret` on the code exchange — so PKCE is the only control
    # between an intercepted code and an access token. Anyone who obtained a
    # code (browser history, a `Referer` header, a proxy log) could drop the
    # verifier and exchange it. Verified against the pre-fix build: code +
    # public client_id + redirect_uri, no secret and no verifier, returned 200
    # and a full token pair.
    #
    # This is a REGRESSION against the Ruby service, not a shared gap.
    # Doorkeeper 5.9.2 guards it twice: `validate_params` errors when
    # `grant.uses_pkce? && code_verifier.blank?`, and `validate_code_verifier`
    # accepts a blank verifier only via `return grant.code_challenge.blank?`.
    #
    # Raises `unauthorized_client` (401) to match the adjacent wrong-verifier
    # path — RFC 7636 §4.6 nominally prescribes `invalid_grant`, but the two
    # are the same event and clients benefit from one consistent answer.
    private def verify_challenge!
      # No challenge was issued with this code, so there is nothing to verify.
      # (Confidential clients doing the plain authorization-code flow.)
      return if challenge.empty?

      # A challenge WAS issued: the verifier is mandatory from here on.
      raise Error.unauthorized_client if verifier.empty?

      raise Error.unauthorized_client unless resolved_code_challenge.valid?(verifier)
    end

    # `/auth/authorize` stores `code_challenge_method || ""`, so a client that
    # sends `code_challenge` without a method mints a code carrying `""`.
    # Upstream `CodeChallengeBuilder.build` raises `ArgumentError` on that —
    # which is not an `Authly::Error`, so it escapes the token controller's
    # typed rescues and 500s the endpoint (SEC-01: never 5xx). RFC 7636 §4.3
    # specifies "plain" as the default when the method is omitted, so this
    # input is legal rather than hostile; honour the default, and downgrade
    # any genuinely unrecognised method to a 401 instead of a crash.
    private def resolved_code_challenge
      CodeChallengeBuilder.build(challenge, method.presence || "plain")
    rescue ArgumentError
      raise Error.unauthorized_client
    end
  end

  # Patch: authly's refresh token (`token_generator.cr#generate_refresh_token`)
  # carries `sub => client_id` and *no* resource-owner identity, and
  # `RefreshToken` never overrides `user_id`. So refreshing an access token
  # mints one with a *random* `sub`, losing the user — and, via our
  # `ClaimsProvider` (which does `User.find?(sub)`), also dropping the
  # `u{n,e,p,r}` block and the `aud` claim. This is the exact upstream gap
  # the `AuthorizationCode#user_id` patch fixes for the code grant; we extend
  # the same compensation to refresh.
  #
  # `@sub` is already the resource-owner id at this point (set from `user_id`
  # before the refresh token is generated in `AccessToken#initialize`), so we
  # re-mint the refresh token to embed it. Only user grants pass a real
  # `user_id`; client_credentials (which has no resource owner) is left as-is.
  struct AccessToken
    def initialize(@client_id : String, @scope : String, @id_token : String? = nil, cert_thumbprint : String? = nil, user_id : String? = nil)
      previous_def
      if (uid = user_id) && !uid.empty?
        @refresh_token = Authly.jwt_encode({
          "jti"     => Random::Secure.hex(32),
          "sub"     => @client_id,
          "user_id" => uid,
          # Embed the granted scope so it survives refresh. authly's refresh
          # grant otherwise derives scope only from the request (absent on a
          # standard refresh) or the auth code (absent on a refresh), leaving
          # the refreshed token with an empty scope — which fails rest-api's
          # `can_read` (needs `public`) and 403s every API call (PPT-2536).
          # Recovered in `Grant#scope` below. Mirrors Ruby Doorkeeper, which
          # reapplies the original grant's scope on refresh.
          "scope" => @scope,
          "name"  => "refresh token",
          "iat"   => Time.utc.to_unix,
          "iss"   => Authly.config.issuer,
          "exp"   => Authly.config.refresh_ttl.from_now.to_unix,
        })
      end
    end
  end

  # Patch: recover the resource-owner id embedded above so the refreshed
  # access token gets a real `sub` (direct analog of the
  # `AuthorizationCode#user_id` patch). The identity chains across
  # refresh-of-refresh because each new refresh token re-embeds it.
  #
  # Falls back to the legacy Doorkeeper bridge for refresh tokens issued by
  # the Ruby service (opaque strings, not JWTs) so a client mid-session at
  # cutover keeps its user identity.
  class RefreshToken
    def user_id : String?
      Authly.jwt_decode(refresh_token).first["user_id"]?.try(&.as_s.presence)
    rescue
      PlaceOS::Auth::AuthlyAdapter::LegacyRefresh
        .lookup(refresh_token)
        .try(&.resource_owner_id)
        .try(&.presence)
    end

    # Upstream `validate_code!` only accepts refresh tokens we minted
    # (`Authly.jwt_decode` must succeed), which rejects every token issued by
    # the legacy Ruby service — forcing an interactive re-login at cutover.
    # Accept a Doorkeeper token when an unrevoked row exists AND the redeeming
    # client owns it (Doorkeeper validated the same pairing).
    private def validate_code!
      payload, _ = Authly.jwt_decode(refresh_token)
      enforce_not_revoked!(payload)
    rescue ex : Error
      # revocation (and any other Authly error) is a decision, not a signal to
      # try the legacy path — re-raise before the catch-all below
      raise ex
    rescue e
      legacy = PlaceOS::Auth::AuthlyAdapter::LegacyRefresh.lookup(refresh_token)
      raise Error.invalid_grant if legacy.nil?
      unless PlaceOS::Auth::AuthlyAdapter::LegacyRefresh.client_matches?(legacy, client_id)
        raise Error.invalid_grant
      end
    end

    # Refuse a refresh token that has been revoked.
    #
    # Upstream `validate_code!` only checks that the JWT decodes — it never
    # consults the token store. The refresh token's `jti` is also never written
    # by `store_token_metadata` (refresh tokens are stateless JWTs even with
    # `persist_jwt_tokens` on). So `POST /auth/revoke` wrote `revoked_at` and
    # the token carried on minting access tokens for its full 30-day TTL:
    # revocation and logout did not end a session. Doorkeeper had no such gap —
    # the access and refresh tokens were columns of a single row.
    #
    # The complication is that ROTATION also revokes: `revoke_old_refresh_token`
    # marks the presented token revoked before returning its replacement. So a
    # naive "revoked => reject" breaks the ts-client boot race (RF-05, P0),
    # where the SPA legitimately submits the SAME refresh token twice within
    # milliseconds — the second submission would arrive after the first had
    # rotated and revoked it, logging every SPA out on startup.
    #
    # A short grace window separates the two: a double-submit lands inside it,
    # a logged-out session or a stolen token does not. This is no weaker than
    # what it replaces — Doorkeeper's `previous_refresh_token` kept the old
    # token usable until the *successor* was used, which is typically a longer
    # window than this.
    #
    # Tune with REFRESH_REVOCATION_GRACE_SECONDS; 0 disables the window
    # entirely (strict single-use, which will break SPA boot).
    private def enforce_not_revoked!(payload) : Nil
      jti = payload["jti"]?.try(&.as_s?)
      return if jti.nil? || jti.empty?

      record = ::PlaceOS::Model::OAuthToken.where(jti: jti).first?
      return if record.nil?

      revoked_at = record.revoked_at
      return if revoked_at.nil?

      elapsed = Time.utc.to_unix - revoked_at # revoked_at is a unix Int64

      # Grace applies ONLY to a rotation. A token revoked via /auth/revoke or
      # /auth/logout is refused immediately — otherwise logout would not end
      # the session, which is the entire point of closing this gap.
      if record.token_type == PlaceOS::Auth::AuthlyAdapter::TokenStore::ROTATED_MARKER
        grace = ENV["REFRESH_REVOCATION_GRACE_SECONDS"]?.try(&.to_i?) || 30
        return if elapsed >= 0 && elapsed < grace
      end

      Log.info { {action: "refresh", message: "refused a revoked refresh token", jti: jti, seconds_since_revocation: elapsed} }
      raise Error.invalid_grant
    end
  end

  # Patch: carry the granted scope across a refresh. Upstream `Grant#scope`
  # returns the request scope (absent on a standard refresh), else the auth
  # code's scope (absent on a refresh), else "". So a refreshed access token
  # lost its scope entirely — emitting `scope: [] ` — and every downstream
  # API call 403'd on rest-api's `can_read` (which requires the `public`
  # scope). We recover the scope embedded in the refresh token by the
  # `AccessToken#initialize` patch above. An explicit (narrowing) request
  # scope still wins, per RFC 6749 §6.
  class Grant
    private def scope : String
      if (scp = @scope) && !scp.empty?
        return scp
      end
      unless @code.empty?
        return auth_code["scope"].as_s
      end
      # Refresh grant: no request scope, no auth code. Recover the scope the
      # `AccessToken#initialize` patch embedded in the refresh token. Guard
      # only this decode so the code-grant path keeps its original semantics.
      unless @refresh_token.empty?
        recovered = begin
          Authly.jwt_decode(@refresh_token).first["scope"]?.try(&.as_s?.presence)
        rescue
          nil
        end
        return recovered if recovered

        # Legacy Doorkeeper refresh token: scope lives on the DB row.
        if legacy = PlaceOS::Auth::AuthlyAdapter::LegacyRefresh.lookup(@refresh_token)
          if scp = legacy.scopes.try(&.presence)
            return scp
          end
        end

        # Self-heal for refresh tokens that carry a user but no recoverable
        # scope — i.e. auth.cr tokens minted BEFORE the scope-embedding fix
        # (they embed `user_id` only) and scope-less Doorkeeper rows. Without
        # this the refreshed access token gets `scope: []`, every API call
        # 403s on rest-api's `can_read`, and — because each refresh re-embeds
        # the empty scope — the client is stuck until a full re-login (the
        # 2026-07-25 dev revert). Ruby parity: Doorkeeper `default_scopes` is
        # `:public`, and refresh reapplied the original grant's scopes, which
        # for every PlaceOS client is `public`. The re-minted refresh token
        # then embeds the healed scope, permanently repairing the chain.
        # Client-only grants (no resource owner) keep "" — no privilege is
        # invented for machine tokens.
        if @grant_strategy.user_id.try(&.presence)
          return "public"
        end
      end
      ""
    end

    # Spend the authorization code exactly once (RFC 6749 §4.1.2, AU-11).
    #
    # `access_token` is the right seam: `Grant#token` calls it only after
    # `validate_scope!` and `authorized?` have passed, and immediately before
    # any token is minted. Claiming earlier — in `authorized?`, say — would let
    # anyone holding a stolen code burn it before the legitimate client
    # redeemed it, turning a confidentiality bug into a denial-of-service one.
    # Claiming later would leave the mint itself racing.
    #
    # A DB failure here propagates rather than being swallowed: no token is
    # issued either way, and a 5xx correctly reports an outage instead of
    # telling the client its perfectly good code was invalid.
    private def access_token
      spend_authorization_code!
      previous_def
    end

    private def spend_authorization_code! : Nil
      return if @code.empty?

      jti = begin
        auth_code["jti"]?.try(&.as_s?)
      rescue
        nil
      end
      # A code with no jti predates this field; there is nothing to key single
      # use on, so preserve the old behaviour rather than reject it outright.
      return if jti.nil? || jti.empty?

      claimed = PlaceOS::Auth::AuthlyAdapter::CodeStore.claim(
        code_jti: jti,
        client_id: @client_id.presence,
        sub: @grant_strategy.user_id.try(&.presence),
        scope: scope.presence,
        expires_at: begin
          auth_code["exp"]?.try(&.as_i64?)
        rescue
          nil
        end,
      )
      return if claimed

      Log.info { {action: "token", message: "refused a replayed authorization code", code_jti: jti, client_id: @client_id} }
      raise Error.invalid_grant
    end

    # Upstream revokes the old refresh token via the JWT token manager, which
    # `Authly.jwt_decode`s it — raising on a legacy Doorkeeper (opaque) token
    # AFTER we successfully redeemed it. Revoke legacy tokens on their
    # Doorkeeper row instead (same rotation semantics).
    private def revoke_old_refresh_token(token : String)
      return unless @grant_strategy.is_a?(RefreshToken)
      if legacy = PlaceOS::Auth::AuthlyAdapter::LegacyRefresh.lookup(@refresh_token)
        PlaceOS::Auth::AuthlyAdapter::LegacyRefresh.revoke!(legacy)
      else
        # Record this as a ROTATION rather than a plain revocation, so the
        # refresh path can tell "just replaced" from "deliberately revoked"
        # and grant a grace window to the former only.
        store = Authly.config.token_store
        jti = begin
          Authly.jwt_decode(@refresh_token).first["jti"]?.try(&.as_s?)
        rescue
          nil
        end
        if jti && (rotatable = store.as?(PlaceOS::Auth::AuthlyAdapter::TokenStore))
          rotatable.revoke_rotated(jti)
        else
          @token_manager.revoke(@refresh_token)
        end
      end
    end

    # ID tokens live 120 seconds, matching the Ruby service: PlaceOS left
    # doorkeeper-openid_connect's `expiration` commented out in
    # `config/initializers/doorkeeper_openid_connect.rb`, so its default of
    # 120 applied. The ID token is a one-shot assertion consumed immediately
    # at sign-in, not a credential to hold — the access token carries the
    # session.
    ID_TOKEN_TTL = 120

    # Patch: two fixes to id_token generation.
    #
    # 1. Upstream unconditionally reads `auth_code["user_id"]` when the scope
    #    includes `openid` — but a refresh grant has no auth code, so a legacy
    #    Doorkeeper row whose scopes include `openid` would 500 the token
    #    endpoint. An id_token is only derivable from a fresh authorization.
    #
    # 2. Upstream builds the payload from `Authly.owners.id_token(user_id)`
    #    plus `iss` and `aud` only, and `Authly.jwt_encode` is a bare
    #    `JWT.encode` that adds nothing — so the ID token carried NO `exp` and
    #    NO `iat`. OIDC Core §2 lists both as REQUIRED, and RFC 7519 §4.1.4
    #    means an assertion without `exp` never expires: a strict relying
    #    party rejects it, a lax one accepts it forever. doorkeeper-openid_
    #    connect emitted `iss, sub, aud, exp, iat` (+ nonce/auth_time), so
    #    this is a parity gap too.
    #
    # Nothing inside PlaceOS consumes the ID token today — rest-api and the
    # SPAs authenticate with the access token — so this is an interop defect
    # rather than a live vulnerability. It had to be closed before any
    # external OIDC relying party is onboarded.
    #
    # `nonce` and `auth_time` remain unemitted: neither is REQUIRED, and
    # `nonce` would first need `/auth/authorize` to capture it into the code.
    private def generate_id_token
      return if @code.empty?
      return unless scope.includes?("openid")

      payload = Authly.owners.id_token(auth_code["user_id"].as_s)
      payload["iss"] = Authly.config.issuer
      payload["aud"] = @client_id

      issued = Time.utc.to_unix
      payload["iat"] = issued
      payload["exp"] = issued + ID_TOKEN_TTL

      Authly.jwt_encode(payload)
    end
  end
end

# Configure at require time so both the production binary (`src/app.cr`)
# and the spec runner (`spec/helper.cr` → `src/config.cr`) share the
# same Authly setup. The configure step only sets fields on Authly's
# in-memory config object — no IO, no DB queries — so it's safe to
# do here.
PlaceOS::Auth::AuthlyAdapter.configure!
