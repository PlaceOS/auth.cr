require "../helper"
require "jwt"

module PlaceOS::Auth
  # Parity coverage for the *shape* of the access-token JWT issued by the
  # `authorization_code` grant. The legacy Ruby service (Doorkeeper::JWT,
  # see `auth/config/initializers/doorkeeper.rb`) emits exactly:
  #
  #   { iss: "POS", iat, exp, jti, aud: authority.domain,
  #     scope: Array(scopes), sub: user.id, u: { n, e, p, r } }
  #
  # Downstream PlaceOS services decode these tokens with
  # `PlaceOS::Model::UserJWT`, so `auth.cr` must issue the same claim set
  # for the drop-in to hold.
  describe OAuth, tags: "jwt-claims" do
    # Runs the full code flow and returns {user, raw access_token JWT}.
    issue_access_token = ->(scopes : String) {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      user = ::PlaceOS::Model::Generator.user(authority).tap do |u|
        u.name = "Parity Claims User"
        u.groups = ["parity-role-a", "parity-role-b"]
        u.support = true
        u.sys_admin = true
        u.save!
      end
      password = "bcrypt-please-#{Random.rand(99999)}"
      user.password = password
      user.save!

      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "claims-test-#{Random.rand(99999)}"
      app.redirect_uri = "https://app.example/cb"
      app.scopes = scopes
      app.owner_id = user.id.as(String)
      app.confidential = true
      app.save!

      cookie = Spec.signin!(client, user, password)

      authorize_path = String.build do |io|
        io << "/auth/authorize?response_type=code"
        io << "&client_id=" << URI.encode_www_form(app.uid.as(String))
        io << "&redirect_uri=" << URI.encode_www_form("https://app.example/cb")
        io << "&scope=" << URI.encode_www_form(scopes)
        io << "&state=xyz"
      end
      authorize_result = client.get(authorize_path, headers: HTTP::Headers{
        "Host"   => "localhost",
        "Cookie" => cookie,
      })
      authorize_result.status_code.should eq 302
      location = authorize_result.headers["Location"]
      code = URI::Params.parse(location.split('?', 2).last)["code"]

      headers = HTTP::Headers{
        "Host"         => "localhost",
        "Content-Type" => "application/x-www-form-urlencoded",
      }
      body = URI::Params.build do |fp|
        fp.add("grant_type", "authorization_code")
        fp.add("client_id", app.uid.as(String))
        fp.add("client_secret", app.secret)
        fp.add("code", code)
        fp.add("redirect_uri", "https://app.example/cb")
      end
      token_result = client.post("/auth/token", headers: headers, body: body)
      token_result.status_code.should eq 200
      access_token = JSON.parse(token_result.body)["access_token"].as_s

      {user, app, access_token}
    }

    decode_claims = ->(token : String) {
      payload, _ = JWT.decode(token, ::Authly.config.public_key.as(String), JWT::Algorithm::RS256)
      payload
    }

    describe "access-token claims (authorization_code grant)" do
      it "sets sub to the authenticated user id" do
        user, app, token = issue_access_token.call("public")
        claims = decode_claims.call(token)
        claims["sub"].as_s.should eq user.id.as(String)
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "sets aud to the authority domain" do
        user, app, token = issue_access_token.call("public")
        claims = decode_claims.call(token)
        claims["aud"].as_s.should eq "localhost"
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "embeds the legacy u{n,e,p,r} metadata block" do
        user, app, token = issue_access_token.call("public")
        claims = decode_claims.call(token)
        u = claims["u"]
        u["n"].as_s.should eq user.name
        u["e"].as_s.should eq user.email.to_s.downcase
        # support + sys_admin => AdminSupport (3)
        u["p"].as_i.should eq 3
        u["r"].as_a.map(&.as_s).should eq ["parity-role-a", "parity-role-b"]
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    describe "scope claim" do
      # Ruby emits `scope: Array(opts[:scopes])`, and downstream services
      # decode with `UserJWT` whose `scope` field is `Array(Scope)`. A
      # space-separated string breaks `UserJWT.decode`.
      it "emits scope as a JSON array of the granted scopes" do
        user, app, token = issue_access_token.call("public openid")
        claims = decode_claims.call(token)
        claims["scope"].as_a.map(&.as_s).should eq ["public", "openid"]
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "issues a token that PlaceOS::Model::UserJWT can decode" do
        user, app, token = issue_access_token.call("public")
        jwt = ::PlaceOS::Model::UserJWT.decode(token)
        jwt.id.should eq user.id.as(String)
        jwt.domain.should eq "localhost"
        jwt.public_scope?.should be_true
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    describe "token lifetime" do
      # The legacy Ruby service issues 2-hour (7200s) access tokens.
      # authly's AccessToken#expires_in captures the default 1-hour TTL at
      # class-load time (before configure! runs), so the response under-
      # reported the lifetime while the JWT exp claim was a full 2 hours.
      it "reports expires_in consistent with the JWT exp (~7200s)" do
        authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
        user = ::PlaceOS::Model::Generator.user(authority).tap do |u|
          u.password = "ignored-#{Random.rand(99999)}"
          u.save!
        end
        app = ::PlaceOS::Model::DoorkeeperApplication.new
        app.name = "ttl-test-#{Random.rand(99999)}"
        app.redirect_uri = "https://app.example/cb"
        app.scopes = "public"
        app.owner_id = user.id.as(String)
        app.confidential = true
        app.save!

        headers = HTTP::Headers{
          "Host"         => "localhost",
          "Content-Type" => "application/x-www-form-urlencoded",
        }
        body = URI::Params.build do |fp|
          fp.add("grant_type", "client_credentials")
          fp.add("client_id", app.uid.as(String))
          fp.add("client_secret", app.secret)
          fp.add("scope", "public")
        end
        result = client.post("/auth/token", headers: headers, body: body)
        result.status_code.should eq 200
        parsed = JSON.parse(result.body)

        parsed["expires_in"].as_i64.should be >= 7100
        parsed["expires_in"].as_i64.should be <= 7200

        claims = decode_claims.call(parsed["access_token"].as_s)
        (claims["exp"].as_i - claims["iat"].as_i).should be_close(7200, 5)
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    describe "claim set" do
      # The legacy Ruby token carries no `cid` claim; authly adds one by
      # default. Drop it so the emitted claim set matches Doorkeeper's.
      it "does not include a cid claim" do
        user, app, token = issue_access_token.call("public")
        claims = decode_claims.call(token)
        claims.as_h.has_key?("cid").should be_false
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end
  end
end
