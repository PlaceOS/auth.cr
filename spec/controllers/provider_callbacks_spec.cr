require "webmock"
require "../helper"

module PlaceOS::Auth
  describe ProviderCallbacks do
    # ---- Fixture helpers --------------------------------------------

    create_strat = ->(site : String, scopes : String) {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      strat = ::PlaceOS::Model::OAuthAuthentication.new
      strat.name = "test-oauth-#{Random.rand(99999)}"
      strat.client_id = "test-client"
      strat.client_secret = "test-secret"
      strat.site = site
      strat.authorize_url = "/authorize"
      strat.token_url = "/token"
      strat.auth_scheme = "request_body"
      strat.token_method = "post"
      strat.scope = scopes
      strat.raw_info_url = "#{site}/userinfo"
      strat.info_mappings = {
        "uid"        => "id",
        "email"      => "email",
        "name"       => "name",
        "first_name" => "first_name",
        "last_name"  => "last_name",
      }
      strat.authority_id = authority.id
      strat.save!
      strat
    }

    # Returns headers carrying the session cookie set by `/auth/:provider`.
    # The kickoff stores the CSRF state, and we'll need to send it back
    # in subsequent callback requests.
    kickoff = ->(strat_id : String) {
      result = client.get(
        "/auth/oauth2?id=#{URI.encode_www_form(strat_id)}",
        headers: HTTP::Headers{"Host" => "localhost"},
      )
      raise "kickoff failed: #{result.status_code} #{result.body}" unless result.status_code == 303
      location = result.headers["Location"]
      set_cookie = result.headers["Set-Cookie"]?.try(&.split(';', 2).first.strip)
      raise "kickoff did not set a session cookie" if set_cookie.nil?

      # extract `state` from the authorize URL we redirect to
      query = location.split('?', 2).last
      state = URI::Params.parse(query)["state"]
      {cookie: set_cookie, state: state}
    }

    stub_token_endpoint = ->(site : String, access_token : String) {
      WebMock.stub(:post, "#{site}/token").to_return(
        status: 200,
        headers: HTTP::Headers{"Content-Type" => "application/json"},
        body: {
          "access_token" => access_token,
          "token_type"   => "Bearer",
          "expires_in"   => 3600,
        }.to_json,
      )
    }

    stub_userinfo = ->(site : String, profile : Hash(String, String)) {
      WebMock.stub(:get, "#{site}/userinfo").to_return(
        status: 200,
        headers: HTTP::Headers{"Content-Type" => "application/json"},
        body: profile.to_json,
      )
    }

    # NB: top-level `Spec` resolves to `PlaceOS::Auth::Spec` inside this
    # module — qualify with `::Spec` to reach the stdlib hooks.
    ::Spec.before_each { WebMock.reset; WebMock.allow_net_connect = false }
    ::Spec.after_each { WebMock.reset }

    # ---- GET /auth/:provider ----------------------------------------

    describe "GET /auth/:provider" do
      it "redirects to the IdP's authorize URL with state + scope" do
        strat = create_strat.call("https://idp.example.test", "openid email profile")

        result = client.get(
          "/auth/oauth2?id=#{URI.encode_www_form(strat.id.as(String))}",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        result.status_code.should eq 303
        location = result.headers["Location"]
        location.should start_with "https://idp.example.test/authorize?"
        params = URI::Params.parse(location.split('?', 2).last)
        params["client_id"].should eq "test-client"
        params["response_type"].should eq "code"
        params["state"].should_not be_empty
        params["scope"].should contain "openid"
      ensure
        strat.try &.destroy
      end

      it "404s when the strat id is unknown" do
        result = client.get(
          "/auth/oauth2?id=does-not-exist",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        result.status_code.should eq 404
      end
    end

    # ---- redirect_uri parity (drop-in) ------------------------------

    # The legacy Ruby service (generic_oauth#callback_url) sends
    # `redirect_uri = <host>/auth/oauth2/callback?id=<strat>` to the IdP,
    # and its RewriteRedirectResponse middleware rewrites that to the
    # path form `<host>/auth/oauth2/callback/<strat>` for `*.b2clogin.com`
    # hosts (B2C won't round-trip a query string on redirect_uri). These
    # URLs are registered in external IdPs and cannot change, so auth.cr
    # must emit them byte-for-byte.
    describe "redirect_uri parity", tags: "oauth-redirect-uri" do
      it "sends redirect_uri carrying ?id=<strat> (matches legacy)" do
        strat = create_strat.call("https://idp.example.test", "openid")
        result = client.get(
          "/auth/oauth2?id=#{URI.encode_www_form(strat.id.as(String))}",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        result.status_code.should eq 303
        location = result.headers["Location"]
        params = URI::Params.parse(location.split('?', 2).last)
        params["redirect_uri"].should eq "http://localhost/auth/oauth2/callback?id=#{strat.id}"
      ensure
        strat.try &.destroy
      end

      it "rewrites redirect_uri to the path form for *.b2clogin.com hosts" do
        strat = create_strat.call("https://org.b2clogin.com", "openid")
        result = client.get(
          "/auth/oauth2?id=#{URI.encode_www_form(strat.id.as(String))}",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        result.status_code.should eq 303
        location = result.headers["Location"]
        location.should start_with "https://org.b2clogin.com/authorize?"
        params = URI::Params.parse(location.split('?', 2).last)
        params["redirect_uri"].should eq "http://localhost/auth/oauth2/callback/#{strat.id}"
      ensure
        strat.try &.destroy
      end

      it "accepts the path-form callback and completes the round-trip" do
        strat = create_strat.call("https://idp.example.test", "openid email")
        stub_token_endpoint.call("https://idp.example.test", "idp-token-xyz")
        stub_userinfo.call("https://idp.example.test", {
          "id"    => "idp-uid-#{Random.rand(99999)}",
          "email" => "bob-#{Random.rand(99999)}@localhost",
          "name"  => "Bob Barker",
        })

        kickoff_data = kickoff.call(strat.id.as(String))

        # IdP returns via the path-form callback (B2C style).
        result = client.get(
          "/auth/oauth2/callback/#{URI.encode_www_form(strat.id.as(String))}?code=test-code&state=#{kickoff_data[:state]}",
          headers: HTTP::Headers{
            "Host"   => "localhost",
            "Cookie" => kickoff_data[:cookie],
          },
        )
        result.status_code.should eq 303
      ensure
        strat.try &.destroy
      end
    end

    # ---- GET /auth/:provider/callback -------------------------------

    describe "GET /auth/:provider/callback" do
      it "creates a new user on first callback" do
        strat = create_strat.call("https://idp.example.test", "openid email profile")
        stub_token_endpoint.call("https://idp.example.test", "idp-token-xyz")
        stub_userinfo.call("https://idp.example.test", {
          "id"         => "idp-uid-#{Random.rand(99999)}",
          "email"      => "alice-#{Random.rand(99999)}@localhost",
          "name"       => "Alice Adams",
          "first_name" => "Alice",
          "last_name"  => "Adams",
        })

        kickoff_data = kickoff.call(strat.id.as(String))

        result = client.get(
          "/auth/oauth2/callback?id=#{URI.encode_www_form(strat.id.as(String))}&code=test-code&state=#{kickoff_data[:state]}",
          headers: HTTP::Headers{
            "Host"   => "localhost",
            "Cookie" => kickoff_data[:cookie],
          },
        )

        result.status_code.should eq 303
        result.headers["Set-Cookie"]?.should_not be_nil

        # Confirm the local row was created and linked.
        lookup_id = "auth-#{::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!.id}-oauth2-#{kickoff_data[:state]}"
        # ^^ we can't easily reconstruct the lookup id without the uid;
        # instead query by provider+authority
        authority_id = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!.id.as(String)
        ::PlaceOS::Model::UserAuthLookup.where(authority_id: authority_id, provider: "oauth2").count.should be > 0
      ensure
        strat.try &.destroy
      end

      it "rejects a state mismatch with 401" do
        strat = create_strat.call("https://idp.example.test", "openid")

        kickoff_data = kickoff.call(strat.id.as(String))

        result = client.get(
          "/auth/oauth2/callback?id=#{URI.encode_www_form(strat.id.as(String))}&code=test-code&state=NOT-THE-STATE",
          headers: HTTP::Headers{
            "Host"   => "localhost",
            "Cookie" => kickoff_data[:cookie],
          },
        )

        result.status_code.should eq 401
      ensure
        strat.try &.destroy
      end

      it "logs in an existing user via UserAuthLookup" do
        strat = create_strat.call("https://idp.example.test", "openid email")
        authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!

        # Pre-seed the linked user + lookup
        uid = "stable-uid-#{Random.rand(99999)}"
        existing = ::PlaceOS::Model::Generator.user(authority)
        existing.save!
        lookup = ::PlaceOS::Model::UserAuthLookup.new
        lookup.uid = uid
        lookup.provider = "oauth2"
        lookup.authority_id = authority.id
        lookup.user_id = existing.id
        lookup.save!

        stub_token_endpoint.call("https://idp.example.test", "idp-token-xyz")
        stub_userinfo.call("https://idp.example.test", {
          "id"    => uid,
          "email" => existing.email.to_s,
          "name"  => "Renamed Person",
        })

        kickoff_data = kickoff.call(strat.id.as(String))

        result = client.get(
          "/auth/oauth2/callback?id=#{URI.encode_www_form(strat.id.as(String))}&code=test-code&state=#{kickoff_data[:state]}",
          headers: HTTP::Headers{
            "Host"   => "localhost",
            "Cookie" => kickoff_data[:cookie],
          },
        )

        result.status_code.should eq 303

        # User row should have been refreshed from the OAuth profile.
        reloaded = ::PlaceOS::Model::User.find!(existing.id.as(String))
        reloaded.name.should eq "Renamed Person"
      ensure
        lookup.try &.destroy
        existing.try &.destroy
        strat.try &.destroy
      end
    end
  end
end
