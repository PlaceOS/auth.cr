require "../helper"

module PlaceOS::Auth
  # RFC 7662 introspection caller-authentication and RFC 7009 revocation
  # (PPT-2536 test matrix, section I: rows IR-01, IR-02, IR-07).
  #
  # **IR-02 is a security regression test.** Adversarial review of PR #2 found
  # that `authenticate_introspection_caller` returned an *empty string* as the
  # client id for bearer-authenticated callers, and the cross-client guard read:
  #
  #     if caller_client_id && !caller_client_id.empty? && token_client != caller_client_id
  #       return IntrospectionResponse.inactive
  #     end
  #
  # An empty caller id therefore short-circuited the guard completely: any
  # holder of any valid access token could introspect any *other* application's
  # token and read back its active state, `client_id`, `scope` and `exp`. Fixed
  # in 67114b2 ("restrict token introspection to the caller's own application")
  # by identifying the bearer caller from its own persisted token record.
  #
  # The specs below pin that fix from the attacker's side: they assert the
  # *exact* rejection (status 401, `error: invalid_token`) **and** that the
  # rejection body carries none of the victim token's metadata, with a
  # positive control in the same example proving the victim token really is
  # introspectable by its owner (so the 401 cannot be passing vacuously).
  describe OAuth, tags: "introspection-security" do
    # `uid` is derived from `redirect_uri` (MD5) and is globally unique, so
    # every application in a spec needs its own redirect.
    make_app = ->(confidential : Bool) {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      user = ::PlaceOS::Model::Generator.user(authority).tap do |u|
        u.password = "ignored-#{Random.rand(99999)}"
        u.save!
      end
      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "introspect-test-#{Random.rand(99999)}"
      app.redirect_uri = "https://app.example/cb/#{UUID.random}"
      app.scopes = "public"
      app.owner_id = user.id.as(String)
      app.confidential = confidential
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

    # ---- IR-02: the empty-client-id introspection bypass ----------------

    describe "POST /auth/oauth/introspect — cross-application disclosure (IR-02)" do
      it "does not let a bearer caller read another application's token, and leaks nothing in the 401" do
        victim_user, victim_app = make_app.call(true)
        attacker_user, attacker_app = make_app.call(true)
        victim_token = issue_token.call(victim_app)
        attacker_bearer = issue_token.call(attacker_app)

        # --- the attack: a valid bearer of application B asks about a token
        # --- belonging to application A. Under the pre-67114b2 code this
        # --- returned 200 with the victim token's full metadata.
        attack = form_post.call("/auth/oauth/introspect",
          {"token" => victim_token},
          HTTP::Headers{"Authorization" => "Bearer #{attacker_bearer}"})

        attack.status_code.should eq 401
        attack_body = JSON.parse(attack.body).as_h
        attack_body["error"].as_s.should eq "invalid_token"

        # Nothing about the victim token may appear in the rejection: not its
        # state, not its owning client, not its scope, not its expiry. These
        # are the exact four fields the bypass disclosed.
        attack_body.has_key?("active").should be_false
        attack_body.has_key?("client_id").should be_false
        attack_body.has_key?("scope").should be_false
        attack_body.has_key?("exp").should be_false
        attack.body.should_not contain victim_app.uid.as(String)

        # --- positive control, same example: the victim application CAN
        # --- introspect its own token and gets all four fields back. Without
        # --- this the 401 above could be passing for an unrelated reason
        # --- (e.g. the token never existed).
        owner = form_post.call("/auth/oauth/introspect", {
          "token"         => victim_token,
          "client_id"     => victim_app.uid.as(String),
          "client_secret" => victim_app.secret,
        }, nil)
        owner.status_code.should eq 200
        owner_body = JSON.parse(owner.body)
        owner_body["active"].as_bool.should be_true
        owner_body["client_id"].as_s.should eq victim_app.uid.as(String)
        owner_body["scope"].as_s.should contain "public"
        owner_body["exp"].as_i64.should be > Time.utc.to_unix
      ensure
        victim_app.try &.destroy
        attacker_app.try &.destroy
        victim_user.try &.destroy
        attacker_user.try &.destroy
      end

      it "treats a literally empty client_id as no client identity at all (401 invalid_client)" do
        user, app = make_app.call(true)
        token = issue_token.call(app)

        # The historical bypass hinged on an empty string being accepted as a
        # caller identity. Sending one explicitly must authenticate nothing:
        # `AuthlyAdapter::Client#find_app` returns nil for an empty client_id,
        # so `authorized?` is false and the caller is rejected outright.
        blank_id = form_post.call("/auth/oauth/introspect", {
          "token"         => token,
          "client_id"     => "",
          "client_secret" => "",
        }, nil)
        blank_id.status_code.should eq 401
        JSON.parse(blank_id.body)["error"].as_s.should eq "invalid_client"

        # ...and an empty client_id paired with a real-looking secret is no
        # better: it must not fall through to the "no credentials" branch and
        # it must never reach the token record.
        blank_id_real_secret = form_post.call("/auth/oauth/introspect", {
          "token"         => token,
          "client_id"     => "",
          "client_secret" => app.secret,
        }, nil)
        blank_id_real_secret.status_code.should eq 401
        JSON.parse(blank_id_real_secret.body)["error"].as_s.should eq "invalid_client"
        blank_id_real_secret.body.should_not contain app.uid.as(String)
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "treats HTTP Basic with an empty username as no client identity (401 invalid_token)" do
        user, app = make_app.call(true)
        token = issue_token.call(app)

        # `basic_auth_credentials` refuses an empty user part, so the header
        # falls through to `acquire_token`, which hands the raw "Basic ..."
        # string to the bearer branch — where it fails to decode as a JWT.
        # The observable contract is a hard 401, never a disclosure.
        basic = Base64.strict_encode(":#{app.secret}")
        result = form_post.call("/auth/oauth/introspect",
          {"token" => token},
          HTTP::Headers{"Authorization" => "Basic #{basic}"})

        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "invalid_token"
        result.body.should_not contain app.uid.as(String)
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "authenticates a public client by client_id alone — Doorkeeper by_uid_and_secret parity" do
        # DELIBERATE PARITY PIN, not an endorsement. `Client#authorized?`
        # returns true for a non-confidential application whatever secret is
        # presented (Doorkeeper's `by_uid_and_secret` likewise returned the
        # application when the secret was blank and the client public). Since
        # every client on the dev install base is public and `client_id` is
        # MD5(redirect_uri) — i.e. publicly derivable — introspection's client
        # authentication is effectively open for those clients. The blast
        # radius is bounded by the cross-application guard asserted above: the
        # caller still only ever sees `{"active": false}` for tokens it does
        # not own, which is what this example proves.
        public_user, public_app = make_app.call(false)
        other_user, other_app = make_app.call(true)
        other_token = issue_token.call(other_app)

        result = form_post.call("/auth/oauth/introspect", {
          "token"         => other_token,
          "client_id"     => public_app.uid.as(String),
          "client_secret" => "not-the-secret",
        }, nil)

        # 200 (rather than the 401 an unknown client_id earns) is the proof
        # that the bogus secret authenticated the caller...
        result.status_code.should eq 200
        # ...and the body is the inactive envelope and nothing else, so the
        # foreign token's state, scope and expiry stay hidden.
        body = JSON.parse(result.body).as_h
        body["active"].as_bool.should be_false
        body.keys.should eq ["active"]
      ensure
        public_app.try &.destroy
        other_app.try &.destroy
        public_user.try &.destroy
        other_user.try &.destroy
      end
    end

    # ---- IR-01: caller authentication, enumerated ------------------------

    describe "POST /auth/oauth/introspect — caller authentication (IR-01)" do
      it "rejects an unknown client_id with 401 invalid_client" do
        user, app = make_app.call(true)
        token = issue_token.call(app)

        result = form_post.call("/auth/oauth/introspect", {
          "token"         => token,
          "client_id"     => "ghost-#{Random.rand(99999)}",
          "client_secret" => "anything",
        }, nil)

        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "invalid_client"
        result.headers["WWW-Authenticate"].should contain %(error="invalid_client")
        result.headers["Cache-Control"].should contain "no-store"
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "rejects a confidential client presenting the wrong secret with 401 invalid_client" do
        user, app = make_app.call(true)
        token = issue_token.call(app)

        result = form_post.call("/auth/oauth/introspect", {
          "token"         => token,
          "client_id"     => app.uid.as(String),
          "client_secret" => "#{app.secret}-wrong",
        }, nil)

        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "invalid_client"
        # The victim token's metadata must not ride along on the failure.
        result.body.should_not contain app.uid.as(String)
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "rejects a bearer caller whose token is not a token we issued with 401 invalid_token" do
        user, app = make_app.call(true)
        token = issue_token.call(app)

        result = form_post.call("/auth/oauth/introspect",
          {"token" => token},
          HTTP::Headers{"Authorization" => "Bearer not-a-real-jwt"})

        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "invalid_token"
        result.headers["WWW-Authenticate"].should contain %(error="invalid_token")
        result.headers["Cache-Control"].should contain "no-store"
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "rejects a caller presenting no credentials with 400 invalid_request and no-store" do
        user, app = make_app.call(true)
        token = issue_token.call(app)

        result = form_post.call("/auth/oauth/introspect", {"token" => token}, nil)

        result.status_code.should eq 400
        JSON.parse(result.body)["error"].as_s.should eq "invalid_request"
        # Doorkeeper set no-store on every OAuth error envelope; caches must
        # never hold an introspection outcome.
        result.headers["Cache-Control"].should contain "no-store"
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # ---- IR-07: revocation cascade ---------------------------------------

    describe "POST /auth/oauth/revoke — cascade (IR-07)" do
      # Mints a real user grant so the access token and the refresh token are
      # the shapes a browser client actually holds (the refresh token is
      # re-minted by the `Authly::AccessToken#initialize` patch to embed the
      # resource owner and the granted scope).
      user_grant = -> {
        authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
        user = ::PlaceOS::Model::Generator.user(authority)
        password = "bcrypt-please-#{Random.rand(99999)}"
        user.password = password
        user.save!

        redirect = "https://app.example/cb/#{UUID.random}"
        app = ::PlaceOS::Model::DoorkeeperApplication.new
        app.name = "revoke-test-#{Random.rand(99999)}"
        app.redirect_uri = redirect
        app.scopes = "public"
        app.owner_id = user.id.as(String)
        app.confidential = true
        app.save!

        cookie = Spec.signin!(client, user, password)
        authorize_result = client.get(
          "/auth/authorize?response_type=code" \
          "&client_id=#{URI.encode_www_form(app.uid.as(String))}" \
          "&redirect_uri=#{URI.encode_www_form(redirect)}" \
          "&scope=public",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie},
        )
        authorize_result.status_code.should eq 302
        code = URI::Params.parse(authorize_result.headers["Location"].split('?', 2).last)["code"]

        token_result = form_post.call("/auth/oauth/token", {
          "grant_type"    => "authorization_code",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "code"          => code,
          "redirect_uri"  => redirect,
        }, nil)
        token_result.status_code.should eq 200
        body = JSON.parse(token_result.body)
        {user, app, redirect, body["access_token"].as_s, body["refresh_token"].as_s}
      }

      it "accepts a refresh token at the revocation endpoint and marks it revoked" do
        user, app, _redirect, access_token, refresh_token = user_grant.call

        # RFC 7009 §2.1: the endpoint takes either token type. Pre-condition
        # is asserted so the post-condition cannot pass vacuously.
        ::Authly.revoked?(refresh_token).should be_false

        result = form_post.call("/auth/oauth/revoke", {
          "token"           => refresh_token,
          "token_type_hint" => "refresh_token",
        }, nil)
        result.status_code.should eq 200
        ::Authly.revoked?(refresh_token).should be_true

        # The access token minted alongside it is a separate `jti` and is
        # unaffected — see the two pending examples below.
        ::Authly.revoked?(access_token).should be_false
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      # Pins the IMPLEMENTATION nuance of the cascade, not a gap. Revoking an
      # access token gives us no way to find the refresh token's jti — the
      # `ati` link only runs refresh -> access — so the refresh token's own
      # row is never stamped. The cascade is enforced at redemption instead
      # (the example below). This is pinned so nobody "corrects" the false
      # into a reverse lookup that cannot exist.
      it "does not stamp the refresh token's own row when the access token is revoked" do
        user, app, _redirect, access_token, refresh_token = user_grant.call

        ::Authly.valid?(access_token).should be_true
        form_post.call("/auth/oauth/revoke", {"token" => access_token}, nil).status_code.should eq 200
        ::Authly.valid?(access_token).should be_false

        ::Authly.revoked?(refresh_token).should be_false
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      # RFC 7009 §2.1 and Doorkeeper both invalidate the whole grant: in
      # Doorkeeper the access and refresh tokens were two columns of one
      # `oauth_access_tokens` row, so revoking either killed both. Ours are
      # independent JWTs, so revocation used to leave the refresh token
      # minting access tokens for its full 30-day TTL — revocation, and
      # therefore logout, did not end the session.
      #
      # Closed by the `ati` claim (written by the `AccessToken#initialize`
      # patch) plus `RefreshToken#enforce_grant_not_revoked!`.
      it "revoking an access token also invalidates the refresh token issued with it (RFC 7009 §2.1)" do
        user, app, _redirect, access_token, refresh_token = user_grant.call

        # Pre-condition, so the assertion below cannot pass vacuously: this
        # refresh token works right now.
        working = form_post.call("/auth/oauth/token", {
          "grant_type"    => "refresh_token",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "refresh_token" => refresh_token,
        }, nil)
        working.status_code.should eq 200
        rotated = JSON.parse(working.body)["refresh_token"].as_s
        fresh_access = JSON.parse(working.body)["access_token"].as_s

        # Revoke the access token from THAT rotation, then its partner must
        # stop working.
        form_post.call("/auth/oauth/revoke", {"token" => fresh_access}, nil).status_code.should eq 200

        refreshed = form_post.call("/auth/oauth/token", {
          "grant_type"    => "refresh_token",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "refresh_token" => rotated,
        }, nil)
        refreshed.status_code.should eq 400
        JSON.parse(refreshed.body)["error"].as_s.should eq "invalid_grant"
        JSON.parse(refreshed.body)["access_token"]?.should be_nil

        # And the original access token is untouched by all of this — the
        # cascade is per grant, not a blanket kill of the user's tokens.
        access_token.should_not eq fresh_access
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      # The cascade must not fire on the ts-client boot race (RF-05): rotation
      # revokes the old REFRESH token and never the access token, so a
      # double-submitted refresh token still succeeds inside the grace window.
      it "does not let the cascade break a double-submitted refresh token" do
        user, app, _redirect, _access_token, refresh_token = user_grant.call

        body = {
          "grant_type"    => "refresh_token",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "refresh_token" => refresh_token,
        }

        first = form_post.call("/auth/oauth/token", body, nil)
        first.status_code.should eq 200

        # Same token again, immediately — the SPA boot race.
        second = form_post.call("/auth/oauth/token", body, nil)
        second.status_code.should eq 200
        JSON.parse(second.body)["access_token"].as_s.should_not be_empty
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      # The more serious half of IR-07, now closed. A refresh token the client
      # has explicitly revoked used to stay redeemable for its full 30-day TTL,
      # because `RefreshToken#validate_code!` only checked that the JWT decoded
      # and never consulted the token store — so revocation and logout did not
      # end a session. `enforce_not_revoked!` reads it back. No grace window
      # applies to a deliberate revocation; the window exists solely for
      # rotation (the ts-client boot race, RF-05).
      it "rejects a refresh token that was revoked via the revocation endpoint" do
        user, app, _redirect, _access_token, refresh_token = user_grant.call
        form_post.call("/auth/oauth/revoke", {"token" => refresh_token}, nil).status_code.should eq 200

        refreshed = form_post.call("/auth/oauth/token", {
          "grant_type"    => "refresh_token",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "refresh_token" => refresh_token,
        }, nil)
        refreshed.status_code.should eq 400
        JSON.parse(refreshed.body)["error"].as_s.should eq "invalid_grant"
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end
  end
end
