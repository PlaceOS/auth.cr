require "authly"
require "base64"
require "openssl"

require "./authly_adapter/client"
require "./authly_adapter/claims_provider"
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
  end
end

# Configure at require time so both the production binary (`src/app.cr`)
# and the spec runner (`spec/helper.cr` → `src/config.cr`) share the
# same Authly setup. The configure step only sets fields on Authly's
# in-memory config object — no IO, no DB queries — so it's safe to
# do here.
PlaceOS::Auth::AuthlyAdapter.configure!
