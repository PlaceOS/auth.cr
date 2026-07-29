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

    # ---- info_mappings comma-fallback (matrix ID-08) -----------------
    #
    # The legacy Ruby `generic_oauth` strategy treated each info_mappings value
    # as a COMMA-SEPARATED FALLBACK LIST, using the first key present in the
    # provider's profile — notably how Azure/Entra surfaces the email as
    # `userPrincipalName` rather than `email`. multi_auth does a single literal
    # lookup, so a comma-list resolves to nil and the email arrives EMPTY.
    #
    # When that fallback was lost, real logins produced users with no email,
    # which then duplicated on the next sign-in. `multi_auth_patch.cr` restores
    # it; these pin both sides of the fallback so it cannot silently regress.

    describe "info_mappings comma-fallback", tags: "idp-mapping" do
      azure_strat = ->(site : String) {
        strat = create_strat.call(site, "openid email")
        strat.info_mappings = {
          "uid"   => "id",
          "email" => "email,mail,userPrincipalName",
          "name"  => "displayName,name",
        }
        strat.save!
        strat
      }

      callback = ->(strat_id : String, data : NamedTuple(cookie: String, state: String)) {
        client.get(
          "/auth/oauth2/callback?id=#{URI.encode_www_form(strat_id)}&code=test-code&state=#{data[:state]}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => data[:cookie]},
        )
      }

      user_for = ->(uid : String) {
        lookup = ::PlaceOS::Model::UserAuthLookup.where(uid: uid, provider: "oauth2").first?
        lookup.nil? ? nil : ::PlaceOS::Model::User.find!(lookup.user_id.as(String))
      }

      it "falls back to a later key when earlier ones are absent (Azure userPrincipalName)" do
        strat = azure_strat.call("https://idp.example.test")
        uid = "azure-uid-#{Random.rand(99999)}"
        upn = "upn-#{Random.rand(99999)}@localhost"

        stub_token_endpoint.call("https://idp.example.test", "idp-token-xyz")
        # NB: neither `email` nor `mail` is present — only the third candidate.
        stub_userinfo.call("https://idp.example.test", {
          "id"                => uid,
          "userPrincipalName" => upn,
          "displayName"       => "Azure Person",
        })

        callback.call(strat.id.as(String), kickoff.call(strat.id.as(String))).status_code.should eq 303

        created = user_for.call(uid)
        created.should_not be_nil
        # Without the patch this is "" — and the account duplicates next login.
        created.not_nil!.email.to_s.should eq upn
        created.not_nil!.name.should eq "Azure Person"
      ensure
        strat.try &.destroy
      end

      it "prefers the FIRST present key over later fallbacks" do
        strat = azure_strat.call("https://idp.example.test")
        uid = "azure-uid-#{Random.rand(99999)}"
        primary = "primary-#{Random.rand(99999)}@localhost"

        stub_token_endpoint.call("https://idp.example.test", "idp-token-xyz")
        stub_userinfo.call("https://idp.example.test", {
          "id"                => uid,
          "email"             => primary,
          "mail"              => "wrong-#{Random.rand(99999)}@localhost",
          "userPrincipalName" => "also-wrong-#{Random.rand(99999)}@localhost",
          "displayName"       => "Primary Person",
        })

        callback.call(strat.id.as(String), kickoff.call(strat.id.as(String)))

        user_for.call(uid).not_nil!.email.to_s.should eq primary
      ensure
        strat.try &.destroy
      end

      it "skips blank candidates rather than mapping an empty value" do
        strat = azure_strat.call("https://idp.example.test")
        uid = "azure-uid-#{Random.rand(99999)}"
        upn = "upn-#{Random.rand(99999)}@localhost"

        stub_token_endpoint.call("https://idp.example.test", "idp-token-xyz")
        # `email` is present but EMPTY — the fallback must continue past it,
        # not stop and map "".
        stub_userinfo.call("https://idp.example.test", {
          "id"                => uid,
          "email"             => "",
          "userPrincipalName" => upn,
          "displayName"       => "Blank First Person",
        })

        callback.call(strat.id.as(String), kickoff.call(strat.id.as(String)))

        user_for.call(uid).not_nil!.email.to_s.should eq upn
      ensure
        strat.try &.destroy
      end
    end

    # ---- authorize_params merge (matrix ID-07) -----------------------
    #
    # The legacy Ruby service merged the strat's `authorize_params` column into
    # the outbound authorize URL. Dropping it is silent but consequential:
    # Google returns NO refresh_token without `access_type=offline`, so every
    # session dies at the first token expiry with no way to renew.

    describe "authorize_params merge", tags: "idp-authorize-params" do
      it "merges the strat's authorize_params into the authorize URL" do
        strat = create_strat.call("https://idp.example.test", "openid")
        strat.authorize_params = {"access_type" => "offline", "prompt" => "consent"}
        strat.save!

        result = client.get(
          "/auth/oauth2?id=#{URI.encode_www_form(strat.id.as(String))}",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        result.status_code.should eq 303
        params = URI::Params.parse(result.headers["Location"].split('?', 2).last)
        params["access_type"].should eq "offline"
        params["prompt"].should eq "consent"
        # the merge must not disturb the embedded redirect_uri
        params["redirect_uri"].should eq "http://localhost/auth/oauth2/callback?id=#{strat.id}"
      ensure
        strat.try &.destroy
      end

      it "leaves the authorize URL untouched when none are configured" do
        strat = create_strat.call("https://idp.example.test", "openid")
        result = client.get(
          "/auth/oauth2?id=#{URI.encode_www_form(strat.id.as(String))}",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        location = result.headers["Location"]
        location.should_not contain "access_type"
        location.should_not contain "&&"
      ensure
        strat.try &.destroy
      end
    end

    # ---- ensure_matching fails closed (matrix ID-06) -----------------
    #
    # The hosted-domain restriction (Ruby's "Invalid Hosted Domain"). Every
    # configured field must have at least one value matching at least one
    # pattern. Dropping it admits ANY account the IdP will authenticate — for a
    # multi-tenant IdP that is the whole internet.
    #
    # NB: `oauth_provider_flows_spec.cr` already covers the match and
    # non-match cases. The gap was the ABSENT-field case, which is the one
    # that actually matters: a missing field must FAIL, not pass vacuously.
    # Only that case is added here, to avoid duplicating existing coverage.

    describe "ensure_matching", tags: "idp-ensure-matching" do
      hd_strat = -> {
        strat = create_strat.call("https://idp.example.test", "openid email")
        strat.ensure_matching = {"hd" => ["example\\.com"]}
        strat.save!
        strat
      }

      run_callback = ->(strat : ::PlaceOS::Model::OAuthAuthentication, profile : Hash(String, String)) {
        stub_token_endpoint.call("https://idp.example.test", "idp-token-xyz")
        stub_userinfo.call("https://idp.example.test", profile)
        data = kickoff.call(strat.id.as(String))
        client.get(
          "/auth/oauth2/callback?id=#{URI.encode_www_form(strat.id.as(String))}&code=test-code&state=#{data[:state]}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => data[:cookie]},
        )
      }

      it "FAILS CLOSED when the required field is absent entirely" do
        strat = hd_strat.call
        result = run_callback.call(strat, {
          "id"    => "hd-missing-#{Random.rand(99999)}",
          "email" => "missing-#{Random.rand(99999)}@localhost",
          "name"  => "No Domain Person",
          # no `hd` key at all
        })
        result.status_code.should eq 302
        result.headers["Location"].should contain "/auth/failure"
      ensure
        strat.try &.destroy
      end
    end

    # ---- OAuthUserMapper Link branch (matrix ID-11) ------------------
    #
    # Branch (2): a user who is ALREADY signed in completes a callback for a
    # provider identity we have never seen. That must attach the new identity
    # to the existing account, not mint a second one — otherwise linking a
    # second IdP silently forks the user.

    describe "linking a provider to a signed-in user", tags: "idp-link" do
      it "links the new identity to the session user instead of creating one" do
        authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
        strat = create_strat.call("https://idp.example.test", "openid email")

        password = "link-branch-pw-#{Random.rand(99999)}"
        existing = ::PlaceOS::Model::Generator.user(authority)
        existing.password = password
        existing.save!

        # Counted AFTER `existing` is created, so a correct link leaves this
        # unchanged. If the mapper wrongly took the Created branch instead,
        # the count goes UP by one — that is the account silently forking.
        count_with_existing = ::PlaceOS::Model::User.count

        session = Spec.signin!(client, existing, password)

        # kickoff mutates the EXISTING session (adds oauth_state), so the
        # signed-in uid survives into the callback.
        kick = client.get(
          "/auth/oauth2?id=#{URI.encode_www_form(strat.id.as(String))}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => session},
        )
        kick.status_code.should eq 303
        cookie = kick.cookies[PlaceOS::Auth::SESSION_COOKIE_NAME].try { |c| "#{c.name}=#{c.value}" } || session
        state = URI::Params.parse(kick.headers["Location"].split('?', 2).last)["state"]

        uid = "link-uid-#{Random.rand(99999)}"
        stub_token_endpoint.call("https://idp.example.test", "idp-token-xyz")
        stub_userinfo.call("https://idp.example.test", {
          "id"    => uid,
          "email" => "someone-else-#{Random.rand(99999)}@localhost",
          "name"  => "Linked Identity",
        })

        result = client.get(
          "/auth/oauth2/callback?id=#{URI.encode_www_form(strat.id.as(String))}&code=test-code&state=#{state}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie},
        )
        result.status_code.should eq 303

        lookup = ::PlaceOS::Model::UserAuthLookup.where(uid: uid, provider: "oauth2").first?
        lookup.should_not be_nil
        # the crux: the new identity points at the ALREADY signed-in user
        lookup.not_nil!.user_id.should eq existing.id
        # no SECOND account was minted for the new provider identity
        ::PlaceOS::Model::User.count.should eq count_with_existing
      ensure
        strat.try &.destroy
        existing.try &.destroy
      end
    end
  end
end
