require "../helper"

module PlaceOS::Auth
  # The legacy Ruby service mounts its OAuth server endpoints under the
  # Doorkeeper prefix `/auth/oauth/*` (token, authorize, revoke,
  # userinfo). `auth.cr` serves them at `/auth/*`. To stay a drop-in for
  # server-to-server and native clients that hardcode the documented
  # Doorkeeper paths (see auth/README.md, auth/docs/sample_auth.md), we
  # also serve the `/auth/oauth/*` aliases.
  describe OAuth, tags: "oauth-alias" do
    new_application = ->(redirect : String, scopes : String) {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      user = ::PlaceOS::Model::Generator.user(authority).tap do |u|
        u.password = "ignored-#{Random.rand(99999)}"
        u.save!
      end
      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "oauth-alias-#{Random.rand(99999)}"
      app.redirect_uri = redirect
      app.scopes = scopes
      app.owner_id = user.id.as(String)
      app.confidential = true
      app.save!
      {user, app}
    }

    form_post = ->(path : String, params : Hash(String, String)) {
      headers = HTTP::Headers{
        "Host"         => "localhost",
        "Content-Type" => "application/x-www-form-urlencoded",
      }
      body = URI::Params.build do |fp|
        params.each { |k, v| fp.add(k, v) }
      end
      client.post(path, headers: headers, body: body)
    }

    it "serves POST /auth/oauth/token (client_credentials)" do
      user, app = new_application.call("https://app.example/cb", "public")
      result = form_post.call("/auth/oauth/token", {
        "grant_type"    => "client_credentials",
        "client_id"     => app.uid.as(String),
        "client_secret" => app.secret,
        "scope"         => "public",
      })
      result.status_code.should eq 200
      JSON.parse(result.body)["access_token"].as_s.should_not be_empty
    ensure
      app.try &.destroy
      user.try &.destroy
    end

    it "serves POST /auth/oauth/revoke" do
      user, app = new_application.call("https://app.example/cb", "public")
      token_result = form_post.call("/auth/oauth/token", {
        "grant_type"    => "client_credentials",
        "client_id"     => app.uid.as(String),
        "client_secret" => app.secret,
        "scope"         => "public",
      })
      access_token = JSON.parse(token_result.body)["access_token"].as_s

      revoke_result = form_post.call("/auth/oauth/revoke", {"token" => access_token})
      revoke_result.status_code.should eq 200
      ::Authly.valid?(access_token).should be_false
    ensure
      app.try &.destroy
      user.try &.destroy
    end

    it "serves GET /auth/oauth/userinfo" do
      _, headers = Spec::Authentication.authentication
      headers["Host"] = "localhost"
      result = client.get("/auth/oauth/userinfo", headers: headers)
      result.status_code.should eq 200
      JSON.parse(result.body)["sub"].as_s.should_not be_empty
    end

    it "serves GET /auth/oauth/authorize (redirects unauthenticated callers)" do
      result = client.get(
        "/auth/oauth/authorize?response_type=code&client_id=x&redirect_uri=https%3A%2F%2Fa%2Fcb",
        headers: HTTP::Headers{"Host" => "localhost"},
      )
      result.status_code.should eq 303
      result.headers["Location"].should eq "/auth/login"
    end

    # ---- TK-09: the two token mounts must not drift apart --------------

    it "answers the short and legacy token paths identically (TK-09)" do
      # `/auth/token` is what ts-client calls; `/auth/oauth/token` is the
      # Doorkeeper mount external integrators hardcoded. They are stacked
      # route annotations on ONE method today, so they cannot diverge — but
      # that is an implementation detail, and the drop-in promise is that
      # both behave the same. This is what fails if anyone ever splits them,
      # to deprecate one or to hang a filter on just one.
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      user = ::PlaceOS::Model::Generator.user(authority)
      user.save!
      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "alias-parity-#{Random.rand(999_999)}"
      app.redirect_uri = "https://alias.example/cb-#{Random.rand(999_999)}"
      app.scopes = "public"
      app.confidential = true
      app.owner_id = user.id.as(String)
      app.save!

      request = ->(path : String) {
        client.post(path,
          headers: HTTP::Headers{
            "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
          },
          body: URI::Params.build { |fp|
            fp.add("grant_type", "client_credentials")
            fp.add("client_id", app.uid.as(String))
            fp.add("client_secret", app.secret)
            fp.add("scope", "public")
          })
      }

      short = request.call("/auth/token")
      legacy = request.call("/auth/oauth/token")

      short.status_code.should eq 200
      legacy.status_code.should eq 200

      # Same envelope and the same cache headers. The tokens themselves
      # differ — each call mints a new one — so compare shape, not bytes.
      JSON.parse(short.body).as_h.keys.sort!.should eq JSON.parse(legacy.body).as_h.keys.sort!
      short.headers["Cache-Control"].should eq legacy.headers["Cache-Control"]
      short.headers["Pragma"].should eq legacy.headers["Pragma"]
      JSON.parse(short.body)["token_type"].as_s.should eq JSON.parse(legacy.body)["token_type"].as_s
      JSON.parse(short.body)["expires_in"].as_i.should eq JSON.parse(legacy.body)["expires_in"].as_i

      # Both tokens actually verify — a shape match on two broken tokens
      # would otherwise pass.
      ::Authly.valid?(JSON.parse(short.body)["access_token"].as_s).should be_true
      ::Authly.valid?(JSON.parse(legacy.body)["access_token"].as_s).should be_true

      # Identical REJECTION too, not just identical success.
      bad = ->(path : String) {
        client.post(path,
          headers: HTTP::Headers{
            "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
          },
          body: "grant_type=client_credentials&client_id=ghost-#{Random.rand(999_999)}&client_secret=x")
      }
      bad_short = bad.call("/auth/token")
      bad_legacy = bad.call("/auth/oauth/token")
      bad_short.status_code.should eq bad_legacy.status_code
      bad_short.status_code.should eq 401
      JSON.parse(bad_short.body)["error"].as_s.should eq JSON.parse(bad_legacy.body)["error"].as_s
      bad_short.headers["WWW-Authenticate"].should eq bad_legacy.headers["WWW-Authenticate"]
    ensure
      app.try &.destroy
      user.try &.destroy
    end
  end
end
