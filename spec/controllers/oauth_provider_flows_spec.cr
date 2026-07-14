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
  end
end
