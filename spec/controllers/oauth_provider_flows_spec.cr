require "webmock"
require "../helper"

module PlaceOS::Auth
  # Drop-in coverage for the common external OAuth2 identity providers a
  # PlaceOS tenant configures as `generic_oauth` (oauth2) strats:
  #
  #   * Google
  #   * Azure AD / Entra ID
  #   * Azure AD B2C (the `*.b2clogin.com` special case)
  #
  # Each flow asserts:
  #   1. the outbound authorize request — host, params, and the exact
  #      `redirect_uri` the IdP has registered (must not change on
  #      cutover);
  #   2. the B2C path-form `redirect_uri` rewrite; and
  #   3. the full code -> token -> userinfo -> local user round-trip with
  #      the provider's own claim names, landing a `UserAuthLookup` under
  #      the `oauth2` provider (matching the legacy service).
  #
  # NB: `multi_auth`'s GenericOAuth2 derives the authorize + token host
  # from the strat `site`. Azure and B2C serve both from one host, so
  # those flows are exercised end-to-end as configured in production;
  # Google splits authorize (accounts.google.com) from token
  # (oauth2.googleapis.com), which this generic provider can't, so the
  # Google token stub sits on the authorize host — the claim-mapping and
  # flow mechanics are what this test locks.
  describe ProviderCallbacks, tags: "provider-flows" do
    json_headers = HTTP::Headers{"Content-Type" => "application/json"}

    new_oauth_strat = ->(site : String, authorize_url : String, token_url : String, raw_info_url : String, scope : String, info_mappings : Hash(String, String)) {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      strat = ::PlaceOS::Model::OAuthAuthentication.new
      strat.name = "flow-#{Random.rand(999999)}"
      strat.client_id = "client-#{Random.rand(999999)}"
      strat.client_secret = "secret-value"
      strat.site = site
      strat.authorize_url = authorize_url
      strat.token_url = token_url
      strat.auth_scheme = "request_body"
      strat.token_method = "post"
      strat.scope = scope
      strat.raw_info_url = raw_info_url
      strat.info_mappings = info_mappings
      strat.authority_id = authority.id
      strat.save!
      strat
    }

    # Kicks off `/auth/oauth2?id=<strat>` and returns the outbound
    # authorize URL + the session cookie + the CSRF state to echo back.
    kickoff = ->(strat_id : String) {
      result = client.get(
        "/auth/oauth2?id=#{URI.encode_www_form(strat_id)}",
        headers: HTTP::Headers{"Host" => "localhost"},
      )
      raise "kickoff failed: #{result.status_code} #{result.body}" unless result.status_code == 303
      location = result.headers["Location"]
      cookie = result.headers["Set-Cookie"].split(';', 2).first.strip
      state = URI::Params.parse(location.split('?', 2).last)["state"]
      {location: location, cookie: cookie, state: state}
    }

    authority_id = -> { ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!.id.as(String) }

    # Destroys the user + lookup created by a round-trip.
    cleanup_login = ->(uid : String) {
      lookup = ::PlaceOS::Model::UserAuthLookup.find?("auth-#{authority_id.call}-oauth2-#{uid}")
      return unless lookup
      if user_id = lookup.user_id
        ::PlaceOS::Model::User.find?(user_id).try &.destroy
      end
      lookup.destroy
    }

    ::Spec.before_each { WebMock.reset; WebMock.allow_net_connect = false }
    ::Spec.after_each { WebMock.reset }

    # ---- Google ------------------------------------------------------

    describe "Google" do
      google_strat = -> {
        new_oauth_strat.call(
          "https://accounts.google.com",
          "/o/oauth2/v2/auth",
          "/token",
          "https://openidconnect.googleapis.com/v1/userinfo",
          "openid email profile",
          {
            "uid"        => "sub",
            "email"      => "email",
            "name"       => "name",
            "first_name" => "given_name",
            "last_name"  => "family_name",
          },
        )
      }

      it "builds the Google authorize request with the registered redirect_uri" do
        strat = google_strat.call
        k = kickoff.call(strat.id.as(String))
        k[:location].should start_with "https://accounts.google.com/o/oauth2/v2/auth?"
        params = URI::Params.parse(k[:location].split('?', 2).last)
        params["client_id"].should eq strat.client_id
        params["response_type"].should eq "code"
        params["scope"].should contain "openid"
        params["redirect_uri"].should eq "http://localhost/auth/oauth2/callback?id=#{strat.id}"
      ensure
        strat.try &.destroy
      end

      it "completes the round-trip and maps the Google profile claims" do
        strat = google_strat.call
        uid = "google-#{Random.rand(999999)}"
        email = "ada-#{Random.rand(999999)}@localhost"

        WebMock.stub(:post, "https://accounts.google.com/token").to_return(
          status: 200, headers: json_headers,
          body: {access_token: "g-access", token_type: "Bearer", expires_in: 3600}.to_json,
        )
        WebMock.stub(:get, "https://openidconnect.googleapis.com/v1/userinfo").to_return(
          status: 200, headers: json_headers,
          body: {sub: uid, email: email, name: "Ada Lovelace", given_name: "Ada", family_name: "Lovelace"}.to_json,
        )

        k = kickoff.call(strat.id.as(String))
        result = client.get(
          "/auth/oauth2/callback?id=#{URI.encode_www_form(strat.id.as(String))}&code=g-code&state=#{k[:state]}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => k[:cookie]},
        )
        result.status_code.should eq 303

        lookup = ::PlaceOS::Model::UserAuthLookup.find?("auth-#{authority_id.call}-oauth2-#{uid}")
        lookup.should_not be_nil
        user = ::PlaceOS::Model::User.find!(lookup.not_nil!.user_id.not_nil!)
        user.email.to_s.should eq email
        user.first_name.should eq "Ada"
        user.last_name.should eq "Lovelace"
      ensure
        cleanup_login.call(uid) if uid
        strat.try &.destroy
      end

      it "recovers the strat id from the session when the IdP drops ?id= on the callback" do
        strat = google_strat.call
        uid = "google-noid-#{Random.rand(999999)}"
        email = "grace-#{Random.rand(999999)}@localhost"

        WebMock.stub(:post, "https://accounts.google.com/token").to_return(
          status: 200, headers: json_headers,
          body: {access_token: "g-access", token_type: "Bearer", expires_in: 3600}.to_json,
        )
        WebMock.stub(:get, "https://openidconnect.googleapis.com/v1/userinfo").to_return(
          status: 200, headers: json_headers,
          body: {sub: uid, email: email, name: "Grace Hopper", given_name: "Grace", family_name: "Hopper"}.to_json,
        )

        k = kickoff.call(strat.id.as(String))
        # The callback URL deliberately OMITS `?id=` (some IdPs don't round-trip
        # it). The id must be recovered from the session state stashed at kickoff
        # — otherwise this 401s "oauth state mismatch".
        result = client.get(
          "/auth/oauth2/callback?code=g-code&state=#{k[:state]}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => k[:cookie]},
        )
        result.status_code.should eq 303
        ::PlaceOS::Model::UserAuthLookup.find?("auth-#{authority_id.call}-oauth2-#{uid}").should_not be_nil
      ensure
        cleanup_login.call(uid) if uid
        strat.try &.destroy
      end
    end

    # ---- Azure AD / Entra ID -----------------------------------------

    describe "Azure AD (Entra ID)" do
      azure_strat = -> {
        new_oauth_strat.call(
          "https://login.microsoftonline.com",
          "/common/oauth2/v2.0/authorize",
          "/common/oauth2/v2.0/token",
          "https://graph.microsoft.com/oidc/userinfo",
          "openid email profile",
          {
            "uid"        => "oid",
            "email"      => "email",
            "name"       => "name",
            "first_name" => "given_name",
            "last_name"  => "family_name",
          },
        )
      }

      it "builds the Azure authorize request with the registered redirect_uri" do
        strat = azure_strat.call
        k = kickoff.call(strat.id.as(String))
        k[:location].should start_with "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?"
        params = URI::Params.parse(k[:location].split('?', 2).last)
        params["client_id"].should eq strat.client_id
        params["response_type"].should eq "code"
        params["scope"].should contain "openid"
        params["redirect_uri"].should eq "http://localhost/auth/oauth2/callback?id=#{strat.id}"
      ensure
        strat.try &.destroy
      end

      it "completes the round-trip and maps the Azure profile claims" do
        strat = azure_strat.call
        uid = "azure-oid-#{Random.rand(999999)}"
        email = "bob-#{Random.rand(999999)}@localhost"

        WebMock.stub(:post, "https://login.microsoftonline.com/common/oauth2/v2.0/token").to_return(
          status: 200, headers: json_headers,
          body: {access_token: "az-access", token_type: "Bearer", expires_in: 3600}.to_json,
        )
        WebMock.stub(:get, "https://graph.microsoft.com/oidc/userinfo").to_return(
          status: 200, headers: json_headers,
          body: {oid: uid, email: email, name: "Bob Barker", given_name: "Bob", family_name: "Barker"}.to_json,
        )

        k = kickoff.call(strat.id.as(String))
        result = client.get(
          "/auth/oauth2/callback?id=#{URI.encode_www_form(strat.id.as(String))}&code=az-code&state=#{k[:state]}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => k[:cookie]},
        )
        result.status_code.should eq 303

        lookup = ::PlaceOS::Model::UserAuthLookup.find?("auth-#{authority_id.call}-oauth2-#{uid}")
        lookup.should_not be_nil
        user = ::PlaceOS::Model::User.find!(lookup.not_nil!.user_id.not_nil!)
        user.email.to_s.should eq email
        user.first_name.should eq "Bob"
        user.last_name.should eq "Barker"
      ensure
        cleanup_login.call(uid) if uid
        strat.try &.destroy
      end
    end

    # ---- Azure AD B2C (*.b2clogin.com) -------------------------------

    describe "Azure AD B2C" do
      policy = "B2C_1_signupsignin"
      b2c_host = "https://contoso.b2clogin.com"
      b2c_base = "/contoso.onmicrosoft.com/#{policy}/oauth2/v2.0"

      b2c_strat = -> {
        new_oauth_strat.call(
          b2c_host,
          "#{b2c_base}/authorize",
          "#{b2c_base}/token",
          "#{b2c_host}/contoso.onmicrosoft.com/openid/v2.0/userinfo",
          "openid",
          {
            "uid"        => "sub",
            "email"      => "email",
            "name"       => "name",
            "first_name" => "given_name",
            "last_name"  => "family_name",
          },
        )
      }

      it "rewrites redirect_uri to the path form in the authorize request" do
        strat = b2c_strat.call
        k = kickoff.call(strat.id.as(String))
        k[:location].should start_with "#{b2c_host}#{b2c_base}/authorize?"
        params = URI::Params.parse(k[:location].split('?', 2).last)
        # B2C won't round-trip a query string on redirect_uri, so the
        # strat id is carried as a path segment (legacy middleware parity).
        params["redirect_uri"].should eq "http://localhost/auth/oauth2/callback/#{strat.id}"
      ensure
        strat.try &.destroy
      end

      it "completes the round-trip via the path-form callback" do
        strat = b2c_strat.call
        uid = "b2c-#{Random.rand(999999)}"
        email = "carol-#{Random.rand(999999)}@localhost"

        WebMock.stub(:post, "#{b2c_host}#{b2c_base}/token").to_return(
          status: 200, headers: json_headers,
          body: {access_token: "b2c-access", token_type: "Bearer", expires_in: 3600}.to_json,
        )
        WebMock.stub(:get, "#{b2c_host}/contoso.onmicrosoft.com/openid/v2.0/userinfo").to_return(
          status: 200, headers: json_headers,
          body: {sub: uid, email: email, name: "Carol Danvers", given_name: "Carol", family_name: "Danvers"}.to_json,
        )

        k = kickoff.call(strat.id.as(String))
        # IdP returns via the B2C path-form callback.
        result = client.get(
          "/auth/oauth2/callback/#{URI.encode_www_form(strat.id.as(String))}?code=b2c-code&state=#{k[:state]}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => k[:cookie]},
        )
        result.status_code.should eq 303

        lookup = ::PlaceOS::Model::UserAuthLookup.find?("auth-#{authority_id.call}-oauth2-#{uid}")
        lookup.should_not be_nil
        user = ::PlaceOS::Model::User.find!(lookup.not_nil!.user_id.not_nil!)
        user.email.to_s.should eq email
        user.first_name.should eq "Carol"
      ensure
        cleanup_login.call(uid) if uid
        strat.try &.destroy
      end
    end

    # ---- Failure & edge cases ----------------------------------------

    describe "failure handling" do
      generic_strat = -> {
        new_oauth_strat.call(
          "https://idp.example.test",
          "/authorize",
          "/token",
          "https://idp.example.test/userinfo",
          "openid email",
          {"uid" => "sub", "email" => "email", "name" => "name"},
        )
      }

      # OmniAuth (Ruby) bounces any provider round-trip failure to
      # `/auth/failure`; auth.cr must do the same rather than surfacing a
      # 500 to the browser.
      it "redirects to /auth/failure when the token endpoint errors" do
        strat = generic_strat.call
        WebMock.stub(:post, "https://idp.example.test/token").to_return(
          status: 400, headers: json_headers,
          body: {error: "invalid_grant"}.to_json,
        )
        k = kickoff.call(strat.id.as(String))
        result = client.get(
          "/auth/oauth2/callback?id=#{URI.encode_www_form(strat.id.as(String))}&code=bad-code&state=#{k[:state]}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => k[:cookie]},
        )
        result.status_code.should eq 302
        result.headers["Location"].should start_with "/auth/failure"
      ensure
        strat.try &.destroy
      end

      it "redirects to /auth/failure when the userinfo endpoint errors" do
        strat = generic_strat.call
        WebMock.stub(:post, "https://idp.example.test/token").to_return(
          status: 200, headers: json_headers,
          body: {access_token: "ok", token_type: "Bearer", expires_in: 3600}.to_json,
        )
        WebMock.stub(:get, "https://idp.example.test/userinfo").to_return(
          status: 500, headers: HTTP::Headers{"Content-Type" => "text/plain"},
          body: "upstream boom",
        )
        k = kickoff.call(strat.id.as(String))
        result = client.get(
          "/auth/oauth2/callback?id=#{URI.encode_www_form(strat.id.as(String))}&code=ok-code&state=#{k[:state]}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => k[:cookie]},
        )
        result.status_code.should eq 302
        result.headers["Location"].should start_with "/auth/failure"
      ensure
        strat.try &.destroy
      end

      it "rejects a state mismatch on the B2C path-form callback with 401" do
        strat = new_oauth_strat.call(
          "https://contoso.b2clogin.com",
          "/contoso.onmicrosoft.com/B2C_1_signupsignin/oauth2/v2.0/authorize",
          "/contoso.onmicrosoft.com/B2C_1_signupsignin/oauth2/v2.0/token",
          "https://contoso.b2clogin.com/contoso.onmicrosoft.com/openid/v2.0/userinfo",
          "openid",
          {"uid" => "sub", "email" => "email", "name" => "name"},
        )
        k = kickoff.call(strat.id.as(String))
        result = client.get(
          "/auth/oauth2/callback/#{URI.encode_www_form(strat.id.as(String))}?code=x&state=NOT-#{k[:state]}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => k[:cookie]},
        )
        result.status_code.should eq 401
      ensure
        strat.try &.destroy
      end
    end

    describe "claim mapping edge cases" do
      # Azure AD B2C commonly returns the address in an `emails` array
      # rather than a scalar `email` claim; admins map it with index
      # syntax (`emails[0]`). Verify the mapper resolves it.
      it "maps a B2C emails[] array claim via index syntax" do
        strat = new_oauth_strat.call(
          "https://contoso.b2clogin.com",
          "/contoso.onmicrosoft.com/B2C_1_signupsignin/oauth2/v2.0/authorize",
          "/contoso.onmicrosoft.com/B2C_1_signupsignin/oauth2/v2.0/token",
          "https://contoso.b2clogin.com/contoso.onmicrosoft.com/openid/v2.0/userinfo",
          "openid",
          {"uid" => "sub", "email" => "emails[0]", "name" => "name"},
        )
        uid = "b2c-arr-#{Random.rand(999999)}"
        email = "dinah-#{Random.rand(999999)}@localhost"

        WebMock.stub(:post, "https://contoso.b2clogin.com/contoso.onmicrosoft.com/B2C_1_signupsignin/oauth2/v2.0/token").to_return(
          status: 200, headers: json_headers,
          body: {access_token: "b2c-arr", token_type: "Bearer", expires_in: 3600}.to_json,
        )
        WebMock.stub(:get, "https://contoso.b2clogin.com/contoso.onmicrosoft.com/openid/v2.0/userinfo").to_return(
          status: 200, headers: json_headers,
          body: {sub: uid, emails: [email], name: "Dinah Drake"}.to_json,
        )

        k = kickoff.call(strat.id.as(String))
        result = client.get(
          "/auth/oauth2/callback/#{URI.encode_www_form(strat.id.as(String))}?code=arr-code&state=#{k[:state]}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => k[:cookie]},
        )
        result.status_code.should eq 303

        lookup = ::PlaceOS::Model::UserAuthLookup.find?("auth-#{authority_id.call}-oauth2-#{uid}")
        lookup.should_not be_nil
        user = ::PlaceOS::Model::User.find!(lookup.not_nil!.user_id.not_nil!)
        user.email.to_s.should eq email
      ensure
        cleanup_login.call(uid) if uid
        strat.try &.destroy
      end
    end

    # ---- post-login continue + ensure_matching (PPT-2536) --------------

    session_cookie = ->(result : HTTP::Client::Response, fallback : String) {
      sc = result.cookies[PlaceOS::Auth::SESSION_COOKIE_NAME]?
      sc ? "#{sc.name}=#{sc.value}" : fallback
    }

    google_urls = ->(scopes : String, mappings : Hash(String, String)) {
      new_oauth_strat.call(
        "https://accounts.google.com", "/o/oauth2/v2/auth", "/token",
        "https://openidconnect.googleapis.com/v1/userinfo", scopes, mappings,
      )
    }

    describe "post-login continue" do
      it "returns to the app that started the login (continue survives the SSO round-trip)" do
        strat = google_urls.call("openid email", {"uid" => "sub", "email" => "email"})
        uid = "google-cont-#{Random.rand(999999)}"

        WebMock.stub(:post, "https://accounts.google.com/token").to_return(
          status: 200, headers: json_headers,
          body: {access_token: "g-access", token_type: "Bearer", expires_in: 3600}.to_json,
        )
        WebMock.stub(:get, "https://openidconnect.googleapis.com/v1/userinfo").to_return(
          status: 200, headers: json_headers,
          body: {sub: uid, email: "cont-#{Random.rand(999999)}@localhost"}.to_json,
        )

        # Hop 1: the login entrypoint stores `continue` on the session and
        # bounces to the provider kickoff.
        login = client.get(
          "/auth/login?provider=oauth2&id=#{URI.encode_www_form(strat.id.as(String))}&continue=%2Fbackoffice%2F",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        login.status_code.should eq 303
        cookie = session_cookie.call(login, "")
        cookie.should_not be_empty

        # Hop 2: kickoff -> IdP redirect (state minted, session updated).
        kick = client.get(login.headers["Location"], headers: HTTP::Headers{
          "Host" => "localhost", "Cookie" => cookie,
        })
        kick.status_code.should eq 303
        state = URI::Params.parse(kick.headers["Location"].split('?', 2).last)["state"]
        cookie = session_cookie.call(kick, cookie)

        # Hop 3: provider callback -> must land back on /backoffice/.
        result = client.get(
          "/auth/oauth2/callback?id=#{URI.encode_www_form(strat.id.as(String))}&code=g-code&state=#{state}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie},
        )
        result.status_code.should eq 303
        result.headers["Location"].should eq "/backoffice/"
      ensure
        cleanup_login.call(uid) if uid
        strat.try &.destroy
      end

      it "refuses to land on an off-host continue after the SSO round-trip (SEC-05)" do
        # The callback replays whatever `/auth/login` stored, so this is the
        # one redirect target that survives an entire IdP round-trip. It is
        # safe only because `set_continue` sanitises on *write* — nothing
        # re-checks it on the way out at `provider_callbacks.cr:195`.
        #
        # `/\evil.example` is the case that mattered: browsers resolve it as
        # scheme-relative (WHATWG treats `\` as `/` for http/https), and the
        # guard's `//` test missed it, so a hostile continue could be parked
        # on the session and fired after a *successful* login.
        strat = google_urls.call("openid email", {"uid" => "sub", "email" => "email"})
        uid = "google-eviljmp-#{Random.rand(999999)}"

        WebMock.stub(:post, "https://accounts.google.com/token").to_return(
          status: 200, headers: json_headers,
          body: {access_token: "g-access", token_type: "Bearer", expires_in: 3600}.to_json,
        )
        WebMock.stub(:get, "https://openidconnect.googleapis.com/v1/userinfo").to_return(
          status: 200, headers: json_headers,
          body: {sub: uid, email: "eviljmp-#{Random.rand(999999)}@localhost"}.to_json,
        )

        login = client.get(
          "/auth/login?provider=oauth2&id=#{URI.encode_www_form(strat.id.as(String))}" \
          "&continue=#{URI.encode_www_form("/\\evil.example/x")}",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        login.status_code.should eq 303
        cookie = session_cookie.call(login, "")

        kick = client.get(login.headers["Location"], headers: HTTP::Headers{
          "Host" => "localhost", "Cookie" => cookie,
        })
        kick.status_code.should eq 303
        state = URI::Params.parse(kick.headers["Location"].split('?', 2).last)["state"]
        cookie = session_cookie.call(kick, cookie)

        result = client.get(
          "/auth/oauth2/callback?id=#{URI.encode_www_form(strat.id.as(String))}&code=g-code&state=#{state}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie},
        )

        # Login still succeeds — the hostile continue is dropped, not fatal.
        result.status_code.should eq 303
        result.headers["Location"].should eq "/"
        result.headers["Location"].tr("\\", "/").should_not contain "evil.example"
      ensure
        cleanup_login.call(uid) if uid
        strat.try &.destroy
      end
    end

    describe "ensure_matching" do
      make_restricted_strat = -> {
        strat = google_urls.call("openid email", {"uid" => "sub", "email" => "email"})
        strat.ensure_matching = {"email" => ["@corp.example$"]}
        strat.save!
        strat
      }

      stub_round_trip = ->(email : String, uid : String) {
        WebMock.stub(:post, "https://accounts.google.com/token").to_return(
          status: 200, headers: json_headers,
          body: {access_token: "g-access", token_type: "Bearer", expires_in: 3600}.to_json,
        )
        WebMock.stub(:get, "https://openidconnect.googleapis.com/v1/userinfo").to_return(
          status: 200, headers: json_headers,
          body: {sub: uid, email: email}.to_json,
        )
      }

      it "rejects a login whose userinfo fails the restriction (-> /auth/failure)" do
        strat = make_restricted_strat.call
        uid = "google-em-reject-#{Random.rand(999999)}"
        stub_round_trip.call("eve@evil.test", uid)

        k = kickoff.call(strat.id.as(String))
        result = client.get(
          "/auth/oauth2/callback?id=#{URI.encode_www_form(strat.id.as(String))}&code=g-code&state=#{k[:state]}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => k[:cookie]},
        )
        result.status_code.should eq 302
        result.headers["Location"].should eq "/auth/failure"
        # and no local account was minted for the rejected identity
        ::PlaceOS::Model::UserAuthLookup.find?("auth-#{authority_id.call}-oauth2-#{uid}").should be_nil
      ensure
        cleanup_login.call(uid) if uid
        strat.try &.destroy
      end

      it "admits a login whose userinfo satisfies the restriction" do
        strat = make_restricted_strat.call
        uid = "google-em-pass-#{Random.rand(999999)}"
        stub_round_trip.call("alice@corp.example", uid)

        k = kickoff.call(strat.id.as(String))
        result = client.get(
          "/auth/oauth2/callback?id=#{URI.encode_www_form(strat.id.as(String))}&code=g-code&state=#{k[:state]}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => k[:cookie]},
        )
        result.status_code.should eq 303
        ::PlaceOS::Model::UserAuthLookup.find?("auth-#{authority_id.call}-oauth2-#{uid}").should_not be_nil
      ensure
        cleanup_login.call(uid) if uid
        strat.try &.destroy
      end
    end

    # ---- authorize_params + info_mappings comma-fallback (PPT-2536) ----

    describe "authorize_params" do
      it "merges the strat's authorize_params into the outbound authorize URL" do
        strat = new_oauth_strat.call(
          "https://accounts.google.com", "/o/oauth2/v2/auth", "/token",
          "https://openidconnect.googleapis.com/v1/userinfo",
          "openid email", {"uid" => "sub", "email" => "email"},
        )
        strat.authorize_params = {"access_type" => "offline", "prompt" => "consent"}
        strat.save!

        k = kickoff.call(strat.id.as(String))
        params = URI::Params.parse(k[:location].split('?', 2).last)
        # the extra params Ruby merged (Google refresh-token flow) are present
        params["access_type"].should eq "offline"
        params["prompt"].should eq "consent"
        # and the standard params + embedded redirect_uri are untouched
        params["client_id"].should eq strat.client_id
        params["response_type"].should eq "code"
        params["redirect_uri"].should eq "http://localhost/auth/oauth2/callback?id=#{strat.id}"
      ensure
        strat.try &.destroy
      end
    end

    describe "info_mappings comma-fallback" do
      it "resolves through comma-separated mapping keys, incl. the getter-only uid" do
        strat = new_oauth_strat.call(
          "https://login.microsoftonline.com", "/common/oauth2/v2.0/authorize",
          "/common/oauth2/v2.0/token", "https://graph.microsoft.com/oidc/userinfo",
          "openid email profile",
          {
            "uid"   => "id,sub,oid",                   # getter-only field, 3rd key wins
            "email" => "email,mail,userPrincipalName", # settable field, 3rd key wins
            "name"  => "name,displayName",
          },
        )
        uid = "az-oid-#{Random.rand(999999)}"
        upn = "grace-#{Random.rand(999999)}@contoso.com"

        WebMock.stub(:post, "https://login.microsoftonline.com/common/oauth2/v2.0/token").to_return(
          status: 200, headers: json_headers,
          body: {access_token: "az-access", token_type: "Bearer", expires_in: 3600}.to_json,
        )
        # profile carries ONLY the fallback keys: `oid` (not id/sub) and
        # `userPrincipalName` (not email/mail) and `displayName` (not name)
        WebMock.stub(:get, "https://graph.microsoft.com/oidc/userinfo").to_return(
          status: 200, headers: json_headers,
          body: {oid: uid, userPrincipalName: upn, displayName: "Grace Hopper"}.to_json,
        )

        k = kickoff.call(strat.id.as(String))
        result = client.get(
          "/auth/oauth2/callback?id=#{URI.encode_www_form(strat.id.as(String))}&code=az-code&state=#{k[:state]}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => k[:cookie]},
        )
        result.status_code.should eq 303

        # the lookup key is derived from `uid` — proves comma-fallback fixed the
        # getter-only uid field (only the get_value_from_json patch can)
        lookup = ::PlaceOS::Model::UserAuthLookup.find?("auth-#{authority_id.call}-oauth2-#{uid}")
        lookup.should_not be_nil
        user = ::PlaceOS::Model::User.find!(lookup.not_nil!.user_id.not_nil!)
        # and the settable email field fell back to userPrincipalName
        user.email.to_s.should eq upn
      ensure
        cleanup_login.call(uid) if uid
        strat.try &.destroy
      end
    end
  end
end
