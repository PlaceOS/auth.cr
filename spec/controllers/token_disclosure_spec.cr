require "../helper"
require "jwt"
require "base64"

module PlaceOS::Auth
  # Credential disclosure — PPT-2536 test-matrix row SEC-04.
  #
  # `config_log_filters_spec.cr` covers the log half (CFG-06). This covers
  # the other three ways a token escapes the response it was meant for:
  # a cache holding it, an error body echoing it back, and a redirect URL
  # carrying it into the next site's `Referer`.
  describe OAuth, tags: "disclosure" do
    form_post = ->(path : String, params : Hash(String, String)) {
      client.post(path, headers: HTTP::Headers{
        "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
      }, body: URI::Params.build { |fp| params.each { |k, v| fp.add(k, v) } })
    }

    make_app = ->(slug : String) {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      password = "bcrypt-please-#{Random.rand(999_999)}"
      user = ::PlaceOS::Model::Generator.user(authority)
      user.password = password
      user.save!

      redirect = "https://disclose.example/cb-#{slug}-#{Random.rand(999_999)}"
      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "disclose-#{slug}-#{Random.rand(999_999)}"
      app.redirect_uri = redirect
      app.scopes = "public"
      app.owner_id = user.id.as(String)
      app.confidential = true
      app.save!

      {user, app, password, redirect}
    }

    # Drives a real login + `GET /auth/authorize` and returns the raw
    # `Location` header, so a spec can inspect exactly what the browser is
    # about to put in its address bar.
    authorize_location = ->(app : ::PlaceOS::Model::DoorkeeperApplication, user : ::PlaceOS::Model::User, password : String, redirect : String, state : String?) {
      cookie = Spec.signin!(client, user, password)
      path = String.build do |io|
        io << "/auth/authorize?response_type=code"
        io << "&client_id=" << URI.encode_www_form(app.uid.as(String))
        io << "&redirect_uri=" << URI.encode_www_form(redirect)
        io << "&scope=public"
        if value = state
          io << "&state=" << URI.encode_www_form(value)
        end
      end
      result = client.get(path, headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie})
      result.status_code.should eq 302
      result.headers["Location"]
    }

    # Full code exchange, returning the parsed token response.
    exchange = ->(app : ::PlaceOS::Model::DoorkeeperApplication, user : ::PlaceOS::Model::User, password : String, redirect : String) {
      location = authorize_location.call(app, user, password, redirect, nil)
      code = URI::Params.parse(location.split('?', 2).last)["code"]
      form_post.call("/auth/token", {
        "grant_type"    => "authorization_code",
        "client_id"     => app.uid.as(String),
        "client_secret" => app.secret,
        "code"          => code,
        "redirect_uri"  => redirect,
      })
    }

    # ---- Caching --------------------------------------------------------

    describe "token responses are not cacheable (SEC-04)" do
      # RFC 6749 §5.1 makes both headers a MUST on any response carrying
      # tokens, and Doorkeeper's `OAuth::TokenResponse#headers` sent exactly
      # these two values. auth.cr set them on its OAuth *error* envelopes but
      # not on the success response — the only one that contains credentials.
      assert_no_store = ->(result : HTTP::Client::Response) {
        result.headers["Cache-Control"].should contain "no-store"
        result.headers["Cache-Control"].should contain "no-cache"
        result.headers["Pragma"].should eq "no-cache"
      }

      it "marks an authorization_code response no-store" do
        user, app, password, redirect = make_app.call("code")
        result = exchange.call(app, user, password, redirect)

        result.status_code.should eq 200
        JSON.parse(result.body)["access_token"].as_s.should_not be_empty
        assert_no_store.call(result)
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "marks a refresh_token response no-store" do
        # The refresh response is the one a long-lived session hits over and
        # over, so a cache that retains it retains a currently-valid pair.
        user, app, password, redirect = make_app.call("refresh")
        refresh = JSON.parse(exchange.call(app, user, password, redirect).body)["refresh_token"].as_s

        result = form_post.call("/auth/token", {
          "grant_type"    => "refresh_token",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "refresh_token" => refresh,
        })

        result.status_code.should eq 200
        JSON.parse(result.body)["access_token"].as_s.should_not be_empty
        assert_no_store.call(result)
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "marks a client_credentials response no-store" do
        user, app, _password, _redirect = make_app.call("cc")

        result = form_post.call("/auth/token", {
          "grant_type"    => "client_credentials",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "scope"         => "public",
        })

        result.status_code.should eq 200
        assert_no_store.call(result)
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "keeps both headers on the error envelope" do
        # Existing specs assert `no-store` here; `Pragma` is new, and both
        # now come from the same helper as the success path so they cannot
        # drift apart.
        result = form_post.call("/auth/token", {
          "grant_type"    => "client_credentials",
          "client_id"     => "ghost-#{Random.rand(999_999)}",
          "client_secret" => "anything",
        })

        result.status_code.should eq 401
        assert_no_store.call(result)
      end
    end

    # ---- Error bodies ---------------------------------------------------

    describe "error bodies do not echo the credential (SEC-04)" do
      # Each of these submits a credential containing a marker the response
      # could only contain by quoting the input back. An error body is
      # rendered into logs, bug reports and browser consoles far more freely
      # than a success body.
      it "does not repeat a rejected refresh token" do
        marker = "MARKER-REFRESH-#{Random.rand(999_999)}"
        user, app, _password, _redirect = make_app.call("echo-refresh")

        result = form_post.call("/auth/token", {
          "grant_type"    => "refresh_token",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "refresh_token" => marker,
        })

        result.status_code.should_not eq 200
        # Positive invariant first: we got a real OAuth error envelope, so
        # "body doesn't contain the marker" isn't passing on an empty body.
        JSON.parse(result.body)["error"].as_s.should_not be_empty
        result.body.should_not contain marker
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "does not repeat a rejected client secret" do
        marker = "MARKER-SECRET-#{Random.rand(999_999)}"
        user, app, _password, _redirect = make_app.call("echo-secret")

        result = form_post.call("/auth/token", {
          "grant_type"    => "client_credentials",
          "client_id"     => app.uid.as(String),
          "client_secret" => marker,
        })

        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should_not be_empty
        result.body.should_not contain marker
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "does not repeat a rejected authorization code" do
        marker = "MARKER-CODE-#{Random.rand(999_999)}"
        user, app, _password, redirect = make_app.call("echo-code")

        result = form_post.call("/auth/token", {
          "grant_type"    => "authorization_code",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "code"          => marker,
          "redirect_uri"  => redirect,
        })

        result.status_code.should_not eq 200
        JSON.parse(result.body)["error"].as_s.should_not be_empty
        result.body.should_not contain marker
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # ---- Undecodable grants ---------------------------------------------

    describe "an undecodable grant is an OAuth error, not a stack trace (SEC-04)" do
      # authly decodes the submitted `code` as a JWT with nothing guarding
      # it, and `Grant#token` runs `validate_scope!` (which reaches that
      # decode) before `authorized?`. So a `code` that is not a currently
      # valid token signed by us raised `JWT::DecodeError` out of the
      # controller: `ActionController::ErrorHandler` turned it into a 500
      # with a backtrace, because `SG_ENV` is unset in the real deploy
      # (CFG-02) and backtraces are therefore on in production.
      #
      # A 500 here is both wrong (Doorkeeper and RFC 6749 §5.2 say 400
      # `invalid_grant`) and a disclosure: the body named our shard paths
      # and the internal call chain to anyone posting junk.
      assert_invalid_grant = ->(result : HTTP::Client::Response) {
        result.status_code.should eq 400
        body = JSON.parse(result.body)
        body["error"].as_s.should eq "invalid_grant"
        # No internal detail in the envelope.
        result.body.should_not contain "src/placeos-auth"
        result.body.should_not contain "JWT::"
        result.body.should_not contain "lib/authly"
      }

      it "rejects an opaque (non-JWT) code with 400 invalid_grant" do
        # This is the shape of a Doorkeeper-issued code: 16 random bytes,
        # no structure. A browser that started its login against the Ruby
        # service and completed it against auth.cr posts exactly this.
        user, app, _password, redirect = make_app.call("opaque")

        result = form_post.call("/auth/token", {
          "grant_type"    => "authorization_code",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "code"          => Random::Secure.hex(16),
          "redirect_uri"  => redirect,
        })

        assert_invalid_grant.call(result)
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "rejects an expired code with 400 invalid_grant" do
        # Codes live 10 minutes. A user who opens the login, walks away and
        # comes back is not an internal server error.
        user, app, _password, redirect = make_app.call("expired")

        expired = ::Authly.jwt_encode({
          "jti"          => Random::Secure.hex(32),
          "code"         => Random::Secure.hex(16),
          "challenge"    => "",
          "method"       => "",
          "scope"        => "public",
          "user_id"      => user.id.as(String),
          "redirect_uri" => redirect,
          "iat"          => 30.minutes.ago.to_unix,
          "iss"          => ::Authly.config.issuer,
          "exp"          => 20.minutes.ago.to_unix,
        })

        result = form_post.call("/auth/token", {
          "grant_type"    => "authorization_code",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "code"          => expired,
          "redirect_uri"  => redirect,
        })

        assert_invalid_grant.call(result)
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "rejects a structurally valid but unsigned code with 400 invalid_grant" do
        # `alg: none` / a token signed with no key at all — the first thing
        # a scanner tries after a plain string.
        user, app, _password, redirect = make_app.call("unsigned")
        payload = Base64.urlsafe_encode(%({"scope":"public","user_id":"#{user.id}"}), padding: false)
        header = Base64.urlsafe_encode(%({"alg":"none","typ":"JWT"}), padding: false)

        result = form_post.call("/auth/token", {
          "grant_type"    => "authorization_code",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "code"          => "#{header}.#{payload}.",
          "redirect_uri"  => redirect,
        })

        assert_invalid_grant.call(result)
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # ---- Referer --------------------------------------------------------

    describe "the authorize redirect carries nothing but the grant (SEC-04)" do
      it "puts only code and state on the redirect URL" do
        # Whatever lands in this URL is in the browser's history and in the
        # `Referer` the client site sends onward. A single-use, PKCE-bound
        # `code` is the protocol's accepted cost; a token there would not be.
        # This is the assertion that fails if the implicit flow is ever
        # revived — `response_type=token` is rejected today (see
        # `authorize_validation_spec.cr`), and this pins the redirect builder
        # itself.
        user, app, password, redirect = make_app.call("referer")
        location = authorize_location.call(app, user, password, redirect, "state-xyz")

        location.should start_with redirect
        query = location.split('?', 2).last

        keys = [] of String
        URI::Params.parse(query).each { |key, _| keys << key }
        keys.sort!.should eq ["code", "state"]

        params = URI::Params.parse(query)
        params["code"].should_not be_empty
        params["state"].should eq "state-xyz"
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "carries no user metadata inside the authorization code" do
        # DIVERGENCE, pinned rather than fixed. Doorkeeper's authorization
        # code was an opaque random string; authly's is a signed JWT
        # (`Authly::Code#jwt`), so its payload is *readable* — not forgeable,
        # but readable — by anyone who sees this URL. And this URL is the one
        # that reaches the client site's `Referer` header, the browser's
        # history, and nginx's access log.
        #
        # That makes the code's payload a real disclosure boundary, so pin
        # it: internal ids and the request's own parameters, and nothing
        # about the human. The `u{n,e,p,r}` block an access token carries
        # (name, email, permissions, roles) must never appear here.
        user, app, password, redirect = make_app.call("code-payload")
        location = authorize_location.call(app, user, password, redirect, nil)
        code = URI::Params.parse(location.split('?', 2).last)["code"]

        payload, _header = JWT.decode(code, ::Authly.config.public_key.as(String), JWT::Algorithm::RS256)

        payload.as_h.keys.sort!.should eq [
          "challenge", "client_id", "code", "exp", "iat", "iss", "jti",
          "method", "redirect_uri", "scope", "user_id",
        ]
        payload["user_id"].as_s.should eq user.id.as(String)
        payload["client_id"].as_s.should eq app.uid.as(String)
        payload["scope"].as_s.should eq "public"
        payload["redirect_uri"].as_s.should eq redirect

        # The bound on the leak: no identity, no permissions, no roles. The
        # exact key set above is the assertion that enforces it — searching
        # the encoded `code` string for an email would be vacuous, since
        # base64 hides plaintext whether or not it is in there.
        payload.as_h.has_key?("u").should be_false
        payload.as_h.has_key?("email").should be_false
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end
  end
end
