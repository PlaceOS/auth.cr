require "../helper"

module PlaceOS::Auth
  # Parity coverage for the two RFC 7662 / Doorkeeper metadata endpoints
  # (PPT-2536): POST /auth/oauth/introspect and GET /auth/oauth/token/info.
  describe OAuth, tags: "token-meta" do
    make_app = ->(scopes : String) {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      user = ::PlaceOS::Model::Generator.user(authority).tap do |u|
        u.password = "ignored-#{Random.rand(99999)}"
        u.save!
      end
      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "meta-test-#{Random.rand(99999)}"
      # uid is derived from redirect_uri (MD5) and globally unique, so
      # every app in a test needs a distinct redirect.
      app.redirect_uri = "https://app.example/cb/#{UUID.random}"
      app.scopes = scopes
      app.owner_id = user.id.as(String)
      app.save!
      {user, app}
    }

    form_post = ->(path : String, params : Hash(String, String), extra : HTTP::Headers?) {
      headers = HTTP::Headers{
        "Host"         => "localhost",
        "Content-Type" => "application/x-www-form-urlencoded",
      }
      extra.try &.each { |k, v| headers[k] = v.first }
      body = URI::Params.build { |fp| params.each { |k, v| fp.add(k, v) } }
      client.post(path, headers: headers, body: body)
    }

    issue_token = ->(app : ::PlaceOS::Model::DoorkeeperApplication) {
      result = form_post.call("/auth/oauth/token", {
        "grant_type"    => "client_credentials",
        "client_id"     => app.uid.as(String),
        "client_secret" => app.secret,
        "scope"         => "public",
      }, nil)
      result.status_code.should eq 200
      JSON.parse(result.body)["access_token"].as_s
    }

    describe "POST /auth/oauth/introspect" do
      it "reports an active token with the Doorkeeper field set" do
        user, app = make_app.call("public")
        active_token = issue_token.call(app)

        result = form_post.call("/auth/oauth/introspect", {
          "token"         => active_token,
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
        }, nil)

        result.status_code.should eq 200
        body = JSON.parse(result.body)
        body["active"].as_bool.should be_true
        body["token_type"].as_s.should eq "Bearer"
        body["client_id"].as_s.should eq app.uid.as(String)
        body["exp"].as_i64.should be > Time.utc.to_unix
        body["scope"].as_s.should contain "public"
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "reports inactive for an unknown token" do
        _, app = make_app.call("public")
        result = form_post.call("/auth/oauth/introspect", {
          "token"         => "not-a-real-token",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
        }, nil)

        result.status_code.should eq 200
        JSON.parse(result.body)["active"].as_bool.should be_false
      ensure
        app.try &.destroy
      end

      it "reports inactive once a token has been revoked" do
        user, app = make_app.call("public")
        active_token = issue_token.call(app)
        form_post.call("/auth/oauth/revoke", {"token" => active_token}, nil).status_code.should eq 200

        result = form_post.call("/auth/oauth/introspect", {
          "token"         => active_token,
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
        }, nil)
        JSON.parse(result.body)["active"].as_bool.should be_false
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "hides a token issued to a different application" do
        user_a, app_a = make_app.call("public")
        _, app_b = make_app.call("public")
        token_a = issue_token.call(app_a)

        # app_b asks about app_a's token
        result = form_post.call("/auth/oauth/introspect", {
          "token"         => token_a,
          "client_id"     => app_b.uid.as(String),
          "client_secret" => app_b.secret,
        }, nil)
        JSON.parse(result.body)["active"].as_bool.should be_false
      ensure
        app_a.try &.destroy
        app_b.try &.destroy
        user_a.try &.destroy
      end

      it "accepts caller identity via HTTP Basic" do
        user, app = make_app.call("public")
        active_token = issue_token.call(app)
        basic = Base64.strict_encode("#{app.uid}:#{app.secret}")

        result = form_post.call("/auth/oauth/introspect",
          {"token" => active_token},
          HTTP::Headers{"Authorization" => "Basic #{basic}"})
        result.status_code.should eq 200
        JSON.parse(result.body)["active"].as_bool.should be_true
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "rejects a caller that does not identify itself (400 invalid_request)" do
        _, app = make_app.call("public")
        active_token = issue_token.call(app)
        result = form_post.call("/auth/oauth/introspect", {"token" => active_token}, nil)
        result.status_code.should eq 400
        JSON.parse(result.body)["error"].as_s.should eq "invalid_request"
      ensure
        app.try &.destroy
      end

      it "lets a bearer caller introspect its own application's token" do
        user, app = make_app.call("public")
        token = issue_token.call(app)
        other = issue_token.call(app) # a second, different token of the same app

        result = form_post.call("/auth/oauth/introspect",
          {"token" => token},
          HTTP::Headers{"Authorization" => "Bearer #{other}"})
        result.status_code.should eq 200
        JSON.parse(result.body)["active"].as_bool.should be_true
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "forbids a bearer caller from introspecting another application's token (401)" do
        user_a, app_a = make_app.call("public")
        user_b, app_b = make_app.call("public")
        token_a = issue_token.call(app_a)
        bearer_b = issue_token.call(app_b)

        result = form_post.call("/auth/oauth/introspect",
          {"token" => token_a},
          HTTP::Headers{"Authorization" => "Bearer #{bearer_b}"})
        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "invalid_token"
      ensure
        app_a.try &.destroy
        app_b.try &.destroy
        user_a.try &.destroy
        user_b.try &.destroy
      end

      it "forbids a bearer caller from introspecting the token it authenticated with (401)" do
        user, app = make_app.call("public")
        token = issue_token.call(app)

        result = form_post.call("/auth/oauth/introspect",
          {"token" => token},
          HTTP::Headers{"Authorization" => "Bearer #{token}"})
        result.status_code.should eq 401
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "sets WWW-Authenticate and Cache-Control on a 401" do
        user, app = make_app.call("public")
        token = issue_token.call(app)
        result = form_post.call("/auth/oauth/introspect",
          {"token" => token},
          HTTP::Headers{"Authorization" => "Bearer bogus-token"})
        result.status_code.should eq 401
        result.headers["WWW-Authenticate"].should contain "Bearer"
        result.headers["Cache-Control"].should contain "no-store"
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    describe "GET /auth/oauth/token/info" do
      it "returns metadata for the presented token" do
        user, app = make_app.call("public")
        active_token = issue_token.call(app)

        result = client.get("/auth/oauth/token/info",
          headers: HTTP::Headers{"Host" => "localhost", "Authorization" => "Bearer #{active_token}"})
        result.status_code.should eq 200
        body = JSON.parse(result.body)
        body["scope"].as_a.map(&.as_s).should contain "public"
        body["expires_in"].as_i64.should be > 0
        body["application"]["uid"].as_s.should eq app.uid.as(String)
        body["created_at"].as_i64.should be > 0
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "returns 401 for an invalid token" do
        result = client.get("/auth/oauth/token/info",
          headers: HTTP::Headers{"Host" => "localhost", "Authorization" => "Bearer bogus"})
        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "invalid_token"
      end
    end
  end
end
