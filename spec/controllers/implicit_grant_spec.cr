require "../helper"
require "base64"
require "digest/sha256"
require "jwt"

module PlaceOS::Auth
  # The implicit grant (RFC 6749 §4.2): `GET /auth/authorize?response_type=token`
  # redirects straight back to the client with the access token in the URL
  # fragment. ts-client sends this unless an app opts into `auth_type:
  # 'auth_code'`, and Doorkeeper served it (`grant_flows` included `implicit`).
  #
  # Same habits as `authorize_validation_spec.cr`: every rejection is
  # non-redirectable, and every rejection table has a positive control.
  describe OAuth, tags: "implicit-grant" do
    localhost = -> { ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil! }

    make_user = -> {
      password = "bcrypt-please-#{Random.rand(999_999)}"
      user = ::PlaceOS::Model::Generator.user(localhost.call).tap do |u|
        u.name = "Implicit Grant User"
        u.groups = ["implicit-role"]
        u.password = password
        u.save!
      end
      {user, password}
    }

    # A public client, which is what every PlaceOS SPA is registered as.
    make_app = ->(redirect : String, skip : Bool) {
      ::PlaceOS::Model::DoorkeeperApplication.new.tap do |app|
        app.name = "implicit-#{Random.rand(999_999)}"
        app.skip_authorization = skip
        app.redirect_uri = redirect
        app.scopes = "public"
        app.confidential = false
        app.owner_id = "implicit-grant-owner"
        app.save!
      end
    }

    unique_redirect = ->(slug : String) { "https://#{slug}.example/cb-#{Random.rand(999_999)}" }

    authorize = ->(cookie : String, params : Hash(String, String)) {
      query = URI::Params.build do |fp|
        params.each { |k, v| fp.add(k, v) }
      end
      client.get("/auth/oauth/authorize?#{query}", headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie})
    }

    token_request = ->(app : ::PlaceOS::Model::DoorkeeperApplication, extra : Hash(String, String)) {
      {
        "response_type" => "token",
        "client_id"     => app.uid.as(String),
        "redirect_uri"  => app.redirect_uri.as(String),
      }.merge(extra)
    }

    # The fragment half of a redirect Location, parsed.
    fragment_params = ->(location : String) {
      URI::Params.parse(location.split('#', 2).last)
    }

    fragment_keys = ->(location : String) {
      keys = [] of String
      fragment_params.call(location).each { |key, _| keys << key }
      keys.sort!
    }

    decode_claims = ->(token : String) {
      payload, _ = JWT.decode(token, ::Authly.config.public_key.as(String), JWT::Algorithm::RS256)
      payload
    }

    # the hidden form fields of a consent page
    consent_fields = ->(html : String) {
      fields = {} of String => String
      html.scan(/<input type="hidden" name="([^"]*)" value="([^"]*)">/) do |match|
        fields[HTML.unescape(match[1])] = HTML.unescape(match[2])
      end
      fields
    }

    submit_consent = ->(fields : Hash(String, String), decision : String, cookie : String) {
      body = URI::Params.build do |form|
        fields.each { |key, value| form.add key, value }
        form.add "consent", decision
      end
      client.post("/auth/oauth/authorize", headers: HTTP::Headers{
        "Host" => "localhost", "Cookie" => cookie, "Content-Type" => "application/x-www-form-urlencoded",
      }, body: body)
    }

    describe "GET /auth/oauth/authorize?response_type=token" do
      it "redirects to the client with the access token in the fragment" do
        user, password = make_user.call
        app = make_app.call(unique_redirect.call("implicit"), true)
        redirect = app.redirect_uri.as(String)
        cookie = Spec.signin!(client, user, password)

        # ts-client's state is `nonce;state`, read back with `decodeURIComponent`
        result = authorize.call(cookie, token_request.call(app, {"scope" => "public", "state" => "n0nce;after login"}))
        result.status_code.should eq 302
        location = result.headers["Location"]

        # the registered URI, untouched, then the fragment: no query is added
        location.should start_with "#{redirect}#"
        location.split('#', 2).first.should eq redirect
        fragment_keys.call(location).should eq ["access_token", "expires_in", "state", "token_type"]

        fragment = fragment_params.call(location)
        fragment["access_token"].should_not be_empty
        fragment["token_type"].should eq "Bearer"
        fragment["expires_in"].should eq ::Authly.config.access_ttl.total_seconds.to_i64.to_s
        fragment["state"].should eq "n0nce;after login"
        # percent-encoded, never `+` for a space
        location.should contain "state=n0nce%3Bafter%20login"

        # a bearer token in a redirect must not be cached anywhere on the way
        result.headers["Cache-Control"].should contain "no-store"
        result.headers["Pragma"].should eq "no-cache"
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "binds the token to the signed-in user, the client and the authority" do
        user, password = make_user.call
        app = make_app.call(unique_redirect.call("claims"), true)
        cookie = Spec.signin!(client, user, password)

        result = authorize.call(cookie, token_request.call(app, {"scope" => "public"}))
        result.status_code.should eq 302
        fragment = fragment_params.call(result.headers["Location"])
        claims = decode_claims.call(fragment["access_token"])

        claims["sub"].as_s.should eq user.id.as(String)
        claims["aud"].as_s.should eq "localhost"
        claims["scope"].as_a.map(&.as_s).should eq ["public"]
        claims["u"]["e"].as_s.should eq user.email.to_s
        claims["u"]["r"].as_a.map(&.as_s).should eq ["implicit-role"]
        # the advertised lifetime is the token's own lifetime
        (claims["exp"].as_i64 - claims["iat"].as_i64).should eq fragment["expires_in"].to_i64

        record = ::PlaceOS::Model::OAuthToken.where(jti: claims["jti"].as_s).first?.not_nil!
        record.client_id.should eq app.uid.as(String)
        record.sub.should eq user.id.as(String)
        record.token_type.should eq "access_token"
        record.revoked?.should be_false
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "issues a token the bearer surfaces accept and revocation ends" do
        user, password = make_user.call
        app = make_app.call(unique_redirect.call("bearer"), true)
        cookie = Spec.signin!(client, user, password)

        result = authorize.call(cookie, token_request.call(app, {"scope" => "public"}))
        result.status_code.should eq 302
        token = fragment_params.call(result.headers["Location"])["access_token"]
        bearer = HTTP::Headers{"Host" => "localhost", "Authorization" => "Bearer #{token}"}

        info = client.get("/auth/oauth/token/info", headers: bearer)
        info.status_code.should eq 200
        body = JSON.parse(info.body)
        body["resource_owner_id"].as_s.should eq user.id.as(String)
        body["application"]["uid"].as_s.should eq app.uid.as(String)
        body["scope"].as_a.map(&.as_s).should eq ["public"]

        revoke = client.post("/auth/oauth/revoke",
          headers: HTTP::Headers{"Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded"},
          body: URI::Params.build { |fp| fp.add("token", token) })
        revoke.status_code.should eq 200

        client.get("/auth/oauth/token/info", headers: bearer).status_code.should eq 401
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "defaults an omitted scope to public and reports it in the fragment" do
        user, password = make_user.call
        app = make_app.call(unique_redirect.call("scope"), true)
        cookie = Spec.signin!(client, user, password)

        result = authorize.call(cookie, token_request.call(app, {} of String => String))
        result.status_code.should eq 302
        location = result.headers["Location"]
        fragment_keys.call(location).should eq ["access_token", "expires_in", "scope", "token_type"]
        fragment = fragment_params.call(location)
        fragment["scope"].should eq "public"
        decode_claims.call(fragment["access_token"])["scope"].as_a.map(&.as_s).should eq ["public"]
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "keeps the client's own query string ahead of the fragment" do
        user, password = make_user.call
        app = make_app.call("#{unique_redirect.call("query")}?app=studio", true)
        redirect = app.redirect_uri.as(String)
        cookie = Spec.signin!(client, user, password)

        result = authorize.call(cookie, token_request.call(app, {"scope" => "public"}))
        result.status_code.should eq 302
        result.headers["Location"].should start_with "#{redirect}#access_token="
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "is served at the short /auth/authorize path too" do
        user, password = make_user.call
        app = make_app.call(unique_redirect.call("short"), true)
        cookie = Spec.signin!(client, user, password)

        query = URI::Params.encode(token_request.call(app, {"scope" => "public"}))
        result = client.get("/auth/authorize?#{query}", headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie})
        result.status_code.should eq 302
        fragment_params.call(result.headers["Location"])["access_token"].should_not be_empty
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    describe "refusals are not redirectable" do
      it "bounces an unauthenticated caller to login with the request in continue" do
        app = make_app.call(unique_redirect.call("anon"), true)
        query = URI::Params.encode(token_request.call(app, {"scope" => "public"}))

        result = client.get("/auth/oauth/authorize?#{query}", headers: HTTP::Headers{"Host" => "localhost"})
        result.status_code.should eq 303
        result.headers["Location"].should start_with "/auth/login?continue=%2Fauth%2Foauth%2Fauthorize%3Fresponse_type%3Dtoken"
      ensure
        app.try &.destroy
      end

      it "refuses an unregistered redirect_uri, an unknown client and a fragment in the redirect_uri" do
        user, password = make_user.call
        app = make_app.call(unique_redirect.call("hostile"), true)
        fragment_app = make_app.call("#{unique_redirect.call("fragment")}#top", true)
        cookie = Spec.signin!(client, user, password)

        # Control: this session + client really does mint tokens.
        control = authorize.call(cookie, token_request.call(app, {"scope" => "public"}))
        control.status_code.should eq 302
        fragment_params.call(control.headers["Location"])["access_token"].should_not be_empty

        {
          {"https://evil.example/steal", app.uid.as(String), 401, "unauthorized_client"},
          {"https://evil.example/steal?next=#{app.redirect_uri}", app.uid.as(String), 401, "unauthorized_client"},
          {"//evil.example/steal", app.uid.as(String), 401, "unauthorized_client"},
          {app.redirect_uri.as(String), "not-a-client", 401, "unauthorized_client"},
          {"", app.uid.as(String), 400, "invalid_redirect_uri"},
          # registered exactly, but a fragment can't carry a fragment response
          {fragment_app.redirect_uri.as(String), fragment_app.uid.as(String), 400, "invalid_request"},
        }.each do |redirect, client_id, status, error|
          result = authorize.call(cookie, {
            "response_type" => "token",
            "client_id"     => client_id,
            "redirect_uri"  => redirect,
            "scope"         => "public",
          })
          result.status_code.should eq status
          JSON.parse(result.body)["error"].as_s.should eq error
          result.headers["Location"]?.should be_nil
        end
      ensure
        fragment_app.try &.destroy
        app.try &.destroy
        user.try &.destroy
      end

      it "refuses a scope the client is not registered for" do
        user, password = make_user.call
        app = make_app.call(unique_redirect.call("badscope"), true)
        cookie = Spec.signin!(client, user, password)

        control = authorize.call(cookie, token_request.call(app, {"scope" => "public openid"}))
        control.status_code.should eq 302

        result = authorize.call(cookie, token_request.call(app, {"scope" => "public repositories"}))
        result.status_code.should eq 400
        JSON.parse(result.body)["error"].as_s.should eq "invalid_scope"
        result.headers["Location"]?.should be_nil
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "refuses a self registered client, without asking for consent" do
        user, password = make_user.call
        cookie = Spec.signin!(client, user, password)
        redirect = unique_redirect.call("dcr")
        app = ::PlaceOS::Model::DoorkeeperApplication.new.tap do |a|
          a.name = "implicit-dcr-#{Random.rand(999_999)}"
          a.uid = "#{AuthlyAdapter::Client::DYNAMIC_PREFIX}#{Random::Secure.hex(16)}"
          a.redirect_uri = redirect
          a.scopes = "public"
          a.confidential = false
          a.owner_id = "implicit-grant-owner"
          a.save!
        end

        # Control: the same client gets its consent page for the code flow.
        pkce = {
          "scope"                 => "public",
          "code_challenge"        => Base64.urlsafe_encode(Digest::SHA256.digest("verifier-#{Random::Secure.hex(16)}"), padding: false),
          "code_challenge_method" => "S256",
        }
        control = authorize.call(cookie, token_request.call(app, pkce).merge({"response_type" => "code"}))
        control.status_code.should eq 200
        control.body.should contain app.name.as(String)

        result = authorize.call(cookie, token_request.call(app, pkce))
        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "unauthorized_client"
        result.headers["Location"]?.should be_nil
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    describe "consent" do
      it "asks for consent when the app does not skip authorization, then issues the token" do
        user, password = make_user.call
        app = make_app.call(unique_redirect.call("consent"), false)
        redirect = app.redirect_uri.as(String)
        cookie = Spec.signin!(client, user, password)

        page = authorize.call(cookie, token_request.call(app, {"scope" => "public", "state" => "xyz"}))
        page.status_code.should eq 200
        page.headers["X-Frame-Options"].should eq "DENY"
        fields = consent_fields.call(page.body)
        fields["response_type"].should eq "token"
        fields["consent_token"].should_not be_empty

        approved = submit_consent.call(fields, "allow", cookie)
        approved.status_code.should eq 302
        location = approved.headers["Location"]
        location.should start_with "#{redirect}#"
        fragment = fragment_params.call(location)
        fragment["access_token"].should_not be_empty
        fragment["state"].should eq "xyz"
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "does not accept a consent that was given for the code flow" do
        user, password = make_user.call
        app = make_app.call(unique_redirect.call("replay"), false)
        redirect = app.redirect_uri.as(String)
        cookie = Spec.signin!(client, user, password)

        page = authorize.call(cookie, token_request.call(app, {"scope" => "public"}).merge({"response_type" => "code"}))
        page.status_code.should eq 200
        fields = consent_fields.call(page.body)

        # the same approval, replayed for a token: the consent page again
        replayed = submit_consent.call(fields.merge({"response_type" => "token"}), "allow", cookie)
        replayed.status_code.should eq 200
        replayed.headers["Location"]?.should be_nil

        # Control: unmodified, it grants the code it was given for.
        granted = submit_consent.call(fields, "allow", cookie)
        granted.status_code.should eq 302
        granted.headers["Location"].should start_with "#{redirect}?code="
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "puts a denial in the fragment, where the token would have gone" do
        user, password = make_user.call
        app = make_app.call(unique_redirect.call("deny"), false)
        redirect = app.redirect_uri.as(String)
        cookie = Spec.signin!(client, user, password)

        page = authorize.call(cookie, token_request.call(app, {"scope" => "public", "state" => "xyz"}))
        page.status_code.should eq 200

        denied = submit_consent.call(consent_fields.call(page.body), "deny", cookie)
        denied.status_code.should eq 302
        denied.headers["Location"].should start_with "#{redirect}#error=access_denied"
        fragment_params.call(denied.headers["Location"])["state"].should eq "xyz"

        # DELETE /auth/oauth/authorize, the other deny path
        query = URI::Params.encode(token_request.call(app, {"state" => "abc"}))
        deleted = client.delete("/auth/oauth/authorize?#{query}", headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie})
        deleted.status_code.should eq 302
        deleted.headers["Location"].should start_with "#{redirect}#error=access_denied"
        fragment_params.call(deleted.headers["Location"])["state"].should eq "abc"
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end
  end
end
