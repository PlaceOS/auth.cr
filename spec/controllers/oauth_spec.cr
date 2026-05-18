require "../helper"

module PlaceOS::Auth
  describe OAuth do
    # ---- Fixture helpers ----------------------------------------------

    # `DoorkeeperApplication` regenerates `secret` in `before_create`
    # (see `lib/placeos-models/.../doorkeeper_application.cr`) so the
    # caller-supplied secret is ignored; we read the real value back
    # via `app.secret`. The arg is kept on the lambda for call-site
    # readability — tests still pass the "intended" value for clarity.
    new_application = ->(_unused_secret : String, redirect : String, scopes : String) {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      user = ::PlaceOS::Model::Generator.user(authority).tap do |u|
        u.password = "ignored-#{Random.rand(99999)}"
        u.save!
      end
      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "oauth-test-#{Random.rand(99999)}"
      app.redirect_uri = redirect
      app.scopes = scopes
      app.owner_id = user.id.as(String)
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

    # ---- POST /auth/token --------------------------------------------

    describe "POST /auth/token" do
      it "issues an access token for the client_credentials grant" do
        user, app = new_application.call(
          "topsecret",
          "https://app.example/cb",
          "public openid",
        )

        result = form_post.call("/auth/token", {
          "grant_type"    => "client_credentials",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "scope"         => "public",
        })

        result.status_code.should eq 200
        body = JSON.parse(result.body)
        body["access_token"].as_s.should_not be_empty
        body["token_type"].as_s.should eq "Bearer"
        body["expires_in"].as_i64.should be > 0
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "rejects an unknown client_id" do
        result = form_post.call("/auth/token", {
          "grant_type"    => "client_credentials",
          "client_id"     => "ghost-#{Random.rand(99999)}",
          "client_secret" => "anything",
        })

        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "unauthorized_client"
      end

      it "rejects a bad client_secret" do
        user, app = new_application.call(
          "topsecret",
          "https://app.example/cb",
          "public",
        )

        result = form_post.call("/auth/token", {
          "grant_type"    => "client_credentials",
          "client_id"     => app.uid.as(String),
          "client_secret" => "nope",
        })

        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "unauthorized_client"
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "rejects the password grant with unsupported_grant_type" do
        user, app = new_application.call(
          "topsecret",
          "https://app.example/cb",
          "public",
        )

        result = form_post.call("/auth/token", {
          "grant_type"    => "password",
          "client_id"     => app.uid.as(String),
          "client_secret" => "topsecret",
          "username"      => "anyone@localhost",
          "password"      => "anything",
        })

        result.status_code.should eq 400
        JSON.parse(result.body)["error"].as_s.should eq "unsupported_grant_type"
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "rejects an unsupported grant_type" do
        result = form_post.call("/auth/token", {
          "grant_type"    => "magic_beans",
          "client_id"     => "anything",
          "client_secret" => "anything",
        })

        result.status_code.should eq 400
        JSON.parse(result.body)["error"].as_s.should eq "unsupported_grant_type"
      end

      it "round-trips authorization_code → access token, refresh_token → access token" do
        user, app = new_application.call(
          "topsecret",
          "https://app.example/cb",
          "public",
        )
        password = "bcrypt-please-#{Random.rand(99999)}"
        user.password = password
        user.save!

        # 1. sign in to obtain the session cookie used by /authorize
        cookie = Spec.signin!(client, user, password)

        # 2. authorize → captures the code from the Location header
        authorize_path = String.build do |io|
          io << "/auth/authorize?response_type=code"
          io << "&client_id=" << URI.encode_www_form(app.uid.as(String))
          io << "&redirect_uri=" << URI.encode_www_form("https://app.example/cb")
          io << "&scope=public"
          io << "&state=xyz"
        end

        authorize_result = client.get(authorize_path, headers: HTTP::Headers{
          "Host"   => "localhost",
          "Cookie" => cookie,
        })
        authorize_result.status_code.should eq 302
        location = authorize_result.headers["Location"]
        location.should start_with "https://app.example/cb?code="
        code_params = URI::Params.parse(location.split('?', 2).last)
        code = code_params["code"]
        code_params["state"].should eq "xyz"

        # 3. exchange code for tokens
        token_result = form_post.call("/auth/token", {
          "grant_type"    => "authorization_code",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "code"          => code,
          "redirect_uri"  => "https://app.example/cb",
        })
        token_result.status_code.should eq 200
        token_body = JSON.parse(token_result.body)
        token_body["access_token"].as_s.should_not be_empty
        refresh_token = token_body["refresh_token"].as_s
        refresh_token.should_not be_empty

        # 4. refresh_token grant produces a fresh access token
        refresh_result = form_post.call("/auth/token", {
          "grant_type"    => "refresh_token",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "refresh_token" => refresh_token,
        })
        refresh_result.status_code.should eq 200
        refresh_body = JSON.parse(refresh_result.body)
        refresh_body["access_token"].as_s.should_not be_empty
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # ---- GET /auth/authorize -----------------------------------------

    describe "GET /auth/authorize" do
      it "redirects unauthenticated callers to /auth/login" do
        result = client.get(
          "/auth/authorize?response_type=code&client_id=x&redirect_uri=https%3A%2F%2Fa%2Fcb",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        result.status_code.should eq 303
        result.headers["Location"].should eq "/auth/login"
      end

      it "rejects an unknown response_type" do
        user, _app = new_application.call(
          "topsecret",
          "https://app.example/cb",
          "public",
        )
        password = "bcrypt-please-#{Random.rand(99999)}"
        user.password = password
        user.save!
        cookie = Spec.signin!(client, user, password)

        result = client.get(
          "/auth/authorize?response_type=token&client_id=x&redirect_uri=https%3A%2F%2Fa%2Fcb",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie},
        )
        result.status_code.should eq 400
        JSON.parse(result.body)["error"].as_s.should eq "unsupported_response_type"
      ensure
        _app.try &.destroy
        user.try &.destroy
      end

      it "rejects an unregistered redirect_uri" do
        user, app = new_application.call(
          "topsecret",
          "https://app.example/cb",
          "public",
        )
        password = "bcrypt-please-#{Random.rand(99999)}"
        user.password = password
        user.save!
        cookie = Spec.signin!(client, user, password)

        result = client.get(
          "/auth/authorize?response_type=code&client_id=#{URI.encode_www_form(app.uid.as(String))}&redirect_uri=https%3A%2F%2Fevil.example%2Fcb",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie},
        )
        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "unauthorized_client"
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end
  end
end
