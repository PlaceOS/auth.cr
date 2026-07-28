require "../helper"
require "jwt"

module PlaceOS::Auth
  # Refresh-token hardening (PPT-2536, the 2026-07-25 dev revert).
  #
  # Steve's weekend testing hit 403s on refreshed tokens DESPITE the
  # scope-across-refresh fix. Forensics (dev `oauth_tokens` table) showed
  # empty-scope access tokens still being minted by refresh grants on Jul
  # 24/25 for the Workplace + Backoffice clients. Two uncovered classes:
  #
  #   A. auth.cr refresh tokens minted BEFORE the scope-embedding fix carry
  #      `user_id` but no `scope` claim. Recovery found nothing -> "" ->
  #      403s; and each refresh re-embedded "" — the client was stuck until
  #      a full re-login.
  #   B. Refresh tokens issued by the legacy RUBY service are opaque
  #      Doorkeeper strings (SHA256-hashed in `oauth_access_tokens`), not
  #      JWTs — `validate_code!` rejected them outright, forcing every
  #      mid-session client through an interactive re-login at cutover.
  #
  # These specs pin the heal for A, the Doorkeeper bridge for B, and the
  # public-client (SPA) refresh path.
  describe OAuth, tags: "refresh-hardening" do
    decode = ->(token : String) {
      payload, _ = JWT.decode(token, ::Authly.config.public_key.as(String), JWT::Algorithm::RS256)
      payload
    }
    scopes_of = ->(claims : JSON::Any) { claims["scope"].as_a.map(&.as_s) }

    make_user = ->(support : Bool, admin : Bool) {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      ::PlaceOS::Model::Generator.user(authority).tap do |u|
        u.name = "Refresh Hardening User"
        u.support = support
        u.sys_admin = admin
        u.save!
      end
    }

    make_app = ->(confidential : Bool) {
      ::PlaceOS::Model::DoorkeeperApplication.new.tap do |app|
        app.name = "refresh-hardening-#{Random.rand(999_999)}"
        # unique per app: redirect_uri is ensure_unique scoped to owner_id
        app.redirect_uri = "https://app.example/cb-#{Random.rand(999_999)}"
        app.scopes = "public"
        app.confidential = confidential
        app.owner_id = "authority-owner"
        app.save!
      end
    }

    refresh = ->(app : ::PlaceOS::Model::DoorkeeperApplication, refresh_token : String, secret : String) {
      client.post("/auth/token", headers: HTTP::Headers{
        "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
      }, body: URI::Params.build { |fp|
        fp.add("grant_type", "refresh_token")
        fp.add("client_id", app.uid.as(String))
        fp.add("client_secret", secret)
        fp.add("refresh_token", refresh_token)
      })
    }

    # An auth.cr refresh token in the PRE-scope-fix wire format: embeds the
    # user but NOT the granted scope.
    prefix_refresh_token = ->(app : ::PlaceOS::Model::DoorkeeperApplication, user_id : String) {
      ::Authly.jwt_encode({
        "jti"     => Random::Secure.hex(32),
        "sub"     => app.uid.as(String),
        "user_id" => user_id,
        "name"    => "refresh token",
        "iat"     => Time.utc.to_unix,
        "iss"     => ::Authly.config.issuer,
        "exp"     => 30.days.from_now.to_unix,
      })
    }

    # Seeds a Doorkeeper (Ruby-era) access-token row. Returns the PLAIN
    # refresh token a browser would present; the row stores its SHA256 hex
    # digest, per the Ruby `hash_token_secrets` config.
    seed_doorkeeper_row = ->(app_id : Int64, owner : String?, scopes : String?, revoked : Bool) {
      plain = Random::Secure.hex(32)
      ::PgORM::Database.connection do |db|
        db.exec(<<-SQL, AuthlyAdapter::LegacyRefresh.digest(plain), Digest::SHA256.hexdigest(Random::Secure.hex(32)), app_id, owner, scopes, revoked)
          INSERT INTO oauth_access_tokens
            (id, refresh_token, token, application_id, resource_owner_id, scopes, revoked_at, created_at, previous_refresh_token)
          VALUES
            ((SELECT COALESCE(MAX(id), 0) + 1 FROM oauth_access_tokens),
             $1, $2, $3, $4, $5,
             CASE WHEN $6 THEN now() ELSE NULL END, now(), '')
          SQL
      end
      plain
    }

    row_revoked = ->(plain : String) {
      ::PgORM::Database.connection do |db|
        db.query_one?(
          "SELECT revoked_at IS NOT NULL FROM oauth_access_tokens WHERE refresh_token = $1",
          AuthlyAdapter::LegacyRefresh.digest(plain), as: Bool)
      end
    }

    # ---- Class A: pre-scope-fix auth.cr refresh tokens ------------------

    it "heals a pre-scope-fix refresh token (user, no scope claim) to the public scope" do
      user = make_user.call(true, true)
      app = make_app.call(true)
      stale = prefix_refresh_token.call(app, user.id.as(String))

      result = refresh.call(app, stale, app.secret)
      result.status_code.should eq 200
      claims = decode.call(JSON.parse(result.body)["access_token"].as_s)

      scopes_of.call(claims).should eq ["public"] # was [] -> 403s
      claims["sub"].as_s.should eq user.id.as(String)
      claims["u"]["p"].as_i.should eq 3
    ensure
      app.try &.destroy
      user.try &.destroy
    end

    it "permanently repairs the chain: the re-minted refresh token embeds the healed scope" do
      user = make_user.call(false, false)
      app = make_app.call(true)
      stale = prefix_refresh_token.call(app, user.id.as(String))

      first = JSON.parse(refresh.call(app, stale, app.secret).body)
      second = refresh.call(app, first["refresh_token"].as_s, app.secret)
      second.status_code.should eq 200
      scopes_of.call(decode.call(JSON.parse(second.body)["access_token"].as_s)).should eq ["public"]
    ensure
      app.try &.destroy
      user.try &.destroy
    end

    it "does not invent a scope for client-only grants (no resource owner)" do
      app = make_app.call(true)
      # a scope-less refresh token with NO user_id: recovery must yield ""
      ownerless = ::Authly.jwt_encode({
        "jti" => Random::Secure.hex(32),
        "sub" => app.uid.as(String),
        "iat" => Time.utc.to_unix,
        "iss" => ::Authly.config.issuer,
        "exp" => 30.days.from_now.to_unix,
      })
      result = refresh.call(app, ownerless, app.secret)
      if result.status_code == 200
        scopes_of.call(decode.call(JSON.parse(result.body)["access_token"].as_s)).should eq [] of String
      end
    ensure
      app.try &.destroy
    end

    # ---- Class B: legacy Ruby (Doorkeeper) refresh tokens ---------------

    it "redeems a Doorkeeper refresh token: correct user, row scopes, row revoked, chain migrates to JWT" do
      user = make_user.call(true, true)
      app = make_app.call(true)
      plain = seed_doorkeeper_row.call(app.id.as(Int64), user.id.as(String), "public", false)

      result = refresh.call(app, plain, app.secret)
      result.status_code.should eq 200
      body = JSON.parse(result.body)
      claims = decode.call(body["access_token"].as_s)

      claims["sub"].as_s.should eq user.id.as(String)
      scopes_of.call(claims).should eq ["public"]
      claims["u"]["e"].as_s.should eq user.email.to_s.downcase
      claims["aud"].as_s.should eq "localhost"

      # Doorkeeper rotation semantics: the redeemed row is revoked...
      row_revoked.call(plain).should be_true
      # ...and the replacement refresh token is a native auth.cr JWT that
      # carries user + scope, so the chain never touches Doorkeeper again.
      neu = body["refresh_token"].as_s
      neu.includes?('.').should be_true
      again = refresh.call(app, neu, app.secret)
      again.status_code.should eq 200
      scopes_of.call(decode.call(JSON.parse(again.body)["access_token"].as_s)).should eq ["public"]
    ensure
      app.try &.destroy
      user.try &.destroy
    end

    it "heals a scope-less Doorkeeper row to public (resource-owner grant)" do
      user = make_user.call(false, false)
      app = make_app.call(true)
      plain = seed_doorkeeper_row.call(app.id.as(Int64), user.id.as(String), nil, false)

      result = refresh.call(app, plain, app.secret)
      result.status_code.should eq 200
      scopes_of.call(decode.call(JSON.parse(result.body)["access_token"].as_s)).should eq ["public"]
    ensure
      app.try &.destroy
      user.try &.destroy
    end

    it "rejects a REVOKED Doorkeeper refresh token" do
      user = make_user.call(false, false)
      app = make_app.call(true)
      plain = seed_doorkeeper_row.call(app.id.as(Int64), user.id.as(String), "public", true)

      refresh.call(app, plain, app.secret).status_code.should_not eq 200
    ensure
      app.try &.destroy
      user.try &.destroy
    end

    it "rejects a Doorkeeper token presented by a DIFFERENT client, leaving the row unrevoked" do
      user = make_user.call(false, false)
      owner_app = make_app.call(true)
      thief_app = make_app.call(true)
      plain = seed_doorkeeper_row.call(owner_app.id.as(Int64), user.id.as(String), "public", false)

      refresh.call(thief_app, plain, thief_app.secret).status_code.should_not eq 200
      row_revoked.call(plain).should be_false
    ensure
      owner_app.try &.destroy
      thief_app.try &.destroy
      user.try &.destroy
    end

    it "rejects an unknown opaque refresh token" do
      app = make_app.call(true)
      refresh.call(app, Random::Secure.hex(32), app.secret).status_code.should_not eq 200
    ensure
      app.try &.destroy
    end

    # ---- SPA (public client) refresh ------------------------------------

    it "allows a PUBLIC client (SPA) to refresh without a client secret" do
      user = make_user.call(false, false)
      app = make_app.call(false) # confidential: false — Backoffice/Workplace style
      # a current-format auth.cr refresh token (user + scope embedded)
      current = ::Authly.jwt_encode({
        "jti"     => Random::Secure.hex(32),
        "sub"     => app.uid.as(String),
        "user_id" => user.id.as(String),
        "scope"   => "public",
        "name"    => "refresh token",
        "iat"     => Time.utc.to_unix,
        "iss"     => ::Authly.config.issuer,
        "exp"     => 30.days.from_now.to_unix,
      })
      result = refresh.call(app, current, "")
      result.status_code.should eq 200
      claims = decode.call(JSON.parse(result.body)["access_token"].as_s)
      scopes_of.call(claims).should eq ["public"]
      claims["sub"].as_s.should eq user.id.as(String)
    ensure
      app.try &.destroy
      user.try &.destroy
    end
  end
end
