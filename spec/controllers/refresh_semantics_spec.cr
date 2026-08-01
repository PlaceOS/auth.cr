require "../helper"
require "jwt"

module PlaceOS::Auth
  # Remaining refresh semantics — PPT-2536 test-matrix rows RF-06, RF-07,
  # RF-08, RF-09.
  #
  # `refresh_scope_spec.cr` / `refresh_token_spec.cr` / `refresh_hardening_spec.cr`
  # cover the happy paths and the two cutover credential formats. This file
  # covers the boundaries around them: what a machine grant refreshes into,
  # what happens once clocks have moved, what a rejection looks like on the
  # wire, and what rotation actually does to the old token.
  #
  # Refresh is the highest-risk surface in this service — it caused both the
  # 2026-07-23 and 2026-07-25 dev reverts, in each case by silently producing
  # `scope: []` and 403ing every downstream call. So every success asserted
  # here checks the resulting access token's `scope` claim AND its `sub`, never
  # just the status code.
  describe OAuth, tags: "refresh-semantics" do
    decode = ->(token : String) {
      payload, _ = JWT.decode(token, ::Authly.config.public_key.as(String), JWT::Algorithm::RS256)
      payload
    }
    scopes_of = ->(claims : JSON::Any) { claims["scope"].as_a.map(&.as_s) }

    make_user = -> {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      ::PlaceOS::Model::Generator.user(authority).tap do |u|
        u.name = "Refresh Semantics User"
        u.save!
      end
    }

    make_app = ->(confidential : Bool) {
      ::PlaceOS::Model::DoorkeeperApplication.new.tap do |app|
        app.name = "refresh-semantics-#{Random.rand(999_999)}"
        # uid is MD5(redirect_uri), and redirect_uri is ensure_unique per owner
        app.redirect_uri = "https://rf.example/cb-#{Random.rand(999_999)}"
        app.scopes = "public"
        app.confidential = confidential
        app.owner_id = "authority-owner"
        app.save!
      end
    }

    form_headers = HTTP::Headers{
      "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
    }

    refresh = ->(app : ::PlaceOS::Model::DoorkeeperApplication, token : String, secret : String) {
      client.post("/auth/token", headers: form_headers, body: URI::Params.build { |fp|
        fp.add("grant_type", "refresh_token")
        fp.add("client_id", app.uid.as(String))
        fp.add("client_secret", secret)
        fp.add("refresh_token", token)
      })
    }

    # `Spec::LegacyFixtures` mints refresh tokens at "now". These rows need an
    # explicit clock (a token issued before the access TTL elapsed, and one past
    # its own 30-day TTL), which the shared factory deliberately doesn't express.
    mint_refresh = ->(client_uid : String, user_id : String?, scope : String?, issued : Time, expires : Time) {
      payload = {
        "jti"  => Random::Secure.hex(32),
        "sub"  => client_uid,
        "name" => "refresh token",
        "iat"  => issued.to_unix,
        "iss"  => ::Authly.config.issuer,
        "exp"  => expires.to_unix,
      } of String => JSON::Any::Type
      payload["user_id"] = user_id if user_id
      payload["scope"] = scope if scope
      ::Authly.jwt_encode(payload)
    }

    # `nil` when the jti was never recorded at all.
    row_revoked = ->(jti : String) {
      ::PlaceOS::Model::OAuthToken.where(jti: jti).first?.try(&.revoked?)
    }

    # ---- RF-07: machine grants are never healed -------------------------

    describe "client-credentials grants are never healed to public (RF-07)" do
      it "refreshes a client-credentials token with an empty scope" do
        app = make_app.call(true)

        issued = client.post("/auth/token", headers: form_headers, body: URI::Params.build { |fp|
          fp.add("grant_type", "client_credentials")
          fp.add("client_id", app.uid.as(String))
          fp.add("client_secret", app.secret)
          fp.add("scope", "public")
        })
        issued.status_code.should eq 200
        machine_refresh = JSON.parse(issued.body)["refresh_token"].as_s
        machine_refresh.should_not be_empty

        result = refresh.call(app, machine_refresh, app.secret)
        result.status_code.should eq 200
        body = JSON.parse(result.body)
        claims = decode.call(body["access_token"].as_s)

        # The PPT-2536 self-heal turns an unrecoverable scope into `public`, but
        # ONLY for grants that carry a resource owner (`Grant#scope` gates on
        # `@grant_strategy.user_id`). A machine grant has none, so healing it
        # would hand any leaked client_id the `public` scope that rest-api's
        # `can_read` gates on — a privilege the client never had.
        #
        # refresh_hardening_spec.cr has a synthetic version of this, but its
        # assertion sits inside `if result.status_code == 200`, so it passes
        # vacuously whenever the request is rejected. This drives the real
        # client-credentials refresh token the endpoint actually issues.
        scopes_of.call(claims).should eq [] of String
        claims.as_h.has_key?("u").should be_false
        # An empty scope is dropped from the response envelope entirely
        # (`TokenResponse#scope` is `at.scope.presence`), so a client cannot
        # mistake it for a granted scope.
        body.as_h.has_key?("scope").should be_false
      ensure
        app.try &.destroy
      end
    end

    # ---- RF-08: clocks --------------------------------------------------

    describe "expiry boundaries (RF-08)" do
      it "refreshes long after the 2-hour access-token TTL has elapsed" do
        user = make_user.call
        app = make_app.call(false)

        # A signage panel, or any SPA left open overnight, only ever presents an
        # access token that expired hours ago. Nothing on the refresh path may
        # depend on the access token still being live — authly's refresh grant
        # reads only the refresh token, and this pins that. `access_ttl` is 2h
        # (asserted in oauth_token_claims_spec.cr), `refresh_ttl` is 30 days.
        stale = mint_refresh.call(
          app.uid.as(String), user.id.as(String), "public",
          3.hours.ago, 27.days.from_now)

        # Control, so the success below is not vacuous: a token minted with the
        # same shape but already past its `exp` really is rejected.
        expired_access = ::Authly.jwt_encode({
          "jti"   => Random::Secure.hex(32),
          "sub"   => user.id.as(String),
          "iss"   => ::Authly.config.issuer,
          "iat"   => 3.hours.ago.to_unix,
          "exp"   => 1.hour.ago.to_unix,
          "scope" => "public",
        })
        ::Authly.valid?(expired_access).should be_false

        result = refresh.call(app, stale, "")
        result.status_code.should eq 200
        fresh_access = JSON.parse(result.body)["access_token"].as_s
        claims = decode.call(fresh_access)

        scopes_of.call(claims).should eq ["public"]
        claims["sub"].as_s.should eq user.id.as(String)
        ::Authly.valid?(fresh_access).should be_true
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # ---- RF-09: the rejection envelope ----------------------------------

    describe "rejection envelope (RF-09)" do
      # ts-client discards its refresh token on ANY 4xx and sends the user to
      # login, but keeps it on a 5xx and retries. So the *shape* of a rejection
      # is the contract: an unlabelled error or a 500 leaves every SPA retrying
      # a token that will never work again.

      it "rejects an unknown opaque refresh token with invalid_grant" do
        app = make_app.call(false)

        # Opaque (no '.') is the Ruby Doorkeeper shape, so this also exercises
        # the LegacyRefresh bridge's miss path. refresh_hardening_spec.cr has a
        # `should_not eq 200` version; this pins the whole envelope.
        result = refresh.call(app, Random::Secure.hex(32), "")

        result.status_code.should eq 400
        body = JSON.parse(result.body)
        body["error"].as_s.should eq "invalid_grant"
        body["error_description"].as_s.should_not be_empty
        result.headers["Cache-Control"].should contain "no-store"
      ensure
        app.try &.destroy
      end

      it "rejects a JWT-shaped refresh token that does not verify" do
        app = make_app.call(false)

        result = refresh.call(app, "a.b.c", "")

        result.status_code.should eq 400
        JSON.parse(result.body)["error"].as_s.should eq "invalid_grant"
        result.headers["Cache-Control"].should contain "no-store"
      ensure
        app.try &.destroy
      end

      it "rejects a refresh token signed with a key we do not hold" do
        user = make_user.call
        app = make_app.call(false)

        # Everything about this token is correct except the signature: right
        # issuer, right client, a real user, an unexpired `exp`. If the RS256
        # verification were ever weakened (or the algorithm taken from the token
        # header instead of the config), this forgery would mint a sys_admin
        # access token for a public client with no secret at all.
        forged = JWT.encode({
          "jti"     => Random::Secure.hex(32),
          "sub"     => app.uid.as(String),
          "user_id" => user.id.as(String),
          "scope"   => "public",
          "name"    => "refresh token",
          "iat"     => Time.utc.to_unix,
          "iss"     => ::Authly.config.issuer,
          "exp"     => 30.days.from_now.to_unix,
        }, "an-attacker-controlled-secret", JWT::Algorithm::HS256)

        result = refresh.call(app, forged, "")

        result.status_code.should eq 400
        JSON.parse(result.body)["error"].as_s.should eq "invalid_grant"
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "rejects a refresh token that is past its own expiry" do
        user = make_user.call
        app = make_app.call(false)

        # 31 days after issue: outside `Authly.config.refresh_ttl` (30 days).
        # The client has to re-authenticate; it must be told so with a 4xx, not
        # left retrying.
        expired = mint_refresh.call(
          app.uid.as(String), user.id.as(String), "public",
          31.days.ago, 1.day.ago)

        result = refresh.call(app, expired, "")

        result.status_code.should eq 400
        JSON.parse(result.body)["error"].as_s.should eq "invalid_grant"
        result.headers["Cache-Control"].should contain "no-store"
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "REFUSES a refresh token that was explicitly revoked" do
        user = make_user.call
        app = make_app.call(false)
        token = Spec::LegacyFixtures.current_refresh_token(app.uid.as(String), user.id.as(String))
        jti = decode.call(token)["jti"].as_s

        # `POST /auth/revoke` does record the revocation...
        client.post("/auth/revoke", headers: form_headers,
          body: URI::Params.build(&.add("token", token))).status_code.should eq 200
        row_revoked.call(jti).should be_true

        # ...and the refresh path now reads it back. Previously
        # `validate_code!` only checked that the JWT decoded, so a revoked
        # refresh token kept minting access tokens for its full 30-day TTL and
        # `POST /auth/revoke` was effectively a no-op — logout did not end the
        # session. `enforce_not_revoked!` closes that.
        #
        # NO grace window applies here: the grace exists solely for ROTATION
        # (the ts-client boot race, RF-05), and rotation is recorded distinctly
        # via TokenStore::ROTATED_MARKER. A deliberate revocation takes effect
        # immediately, which is the entire point.
        result = refresh.call(app, token, "")
        result.status_code.should eq 400
        JSON.parse(result.body)["error"].as_s.should eq "invalid_grant"
        JSON.parse(result.body)["access_token"]?.should be_nil
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # ---- RF-06: rotation & reuse ----------------------------------------

    describe "rotation and reuse (RF-06)" do
      it "records the redeemed refresh token as revoked when it rotates" do
        user = make_user.call
        app = make_app.call(false)
        original = Spec::LegacyFixtures.current_refresh_token(app.uid.as(String), user.id.as(String))
        original_jti = decode.call(original)["jti"].as_s

        result = refresh.call(app, original, "")
        result.status_code.should eq 200
        body = JSON.parse(result.body)

        # Rotation: a new refresh token is issued and it is not the old one.
        rotated = body["refresh_token"].as_s
        rotated.should_not eq original
        scopes_of.call(decode.call(body["access_token"].as_s)).should eq ["public"]

        # `Grant#revoke_old_refresh_token` writes a marker row for the redeemed
        # token's jti (the row is created on demand — a refresh token minted by
        # the `AccessToken#initialize` patch is never stored at issue time).
        row_revoked.call(original_jti).should be_true
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "tolerates an immediate replay (boot race) but refuses it once the grace window closes" do
        user = make_user.call
        app = make_app.call(false)
        original = Spec::LegacyFixtures.current_refresh_token(app.uid.as(String), user.id.as(String))

        first = refresh.call(app, original, "")
        first.status_code.should eq 200
        rotated = JSON.parse(first.body)["refresh_token"].as_s

        # (a) Immediate replay — the ts-client boot race (RF-05, P0). The SPA
        # legitimately submits the same refresh token twice within
        # milliseconds; rejecting this would log every SPA out on startup.
        # Rotation is recorded with TokenStore::ROTATED_MARKER, and rotated
        # tokens stay redeemable for REFRESH_REVOCATION_GRACE_SECONDS.
        replay = refresh.call(app, original, "")
        replay.status_code.should eq 200
        replay_claims = decode.call(JSON.parse(replay.body)["access_token"].as_s)
        scopes_of.call(replay_claims).should eq ["public"]
        replay_claims["sub"].as_s.should eq user.id.as(String)

        # (b) The same replay once the window has closed — a stolen token being
        # reused long after the legitimate client rotated it. Rather than
        # sleeping out the real window, collapse it to zero for this call.
        # RFC 6819 §5.2.2.3 / OAuth 2.0 Security BCP §4.13.
        previous_grace = ENV["REFRESH_REVOCATION_GRACE_SECONDS"]?
        begin
          ENV["REFRESH_REVOCATION_GRACE_SECONDS"] = "0"
          stale = refresh.call(app, original, "")
          stale.status_code.should eq 400
          JSON.parse(stale.body)["error"].as_s.should eq "invalid_grant"
          JSON.parse(stale.body)["access_token"]?.should be_nil
        ensure
          if prev = previous_grace
            ENV["REFRESH_REVOCATION_GRACE_SECONDS"] = prev
          else
            ENV.delete("REFRESH_REVOCATION_GRACE_SECONDS")
          end
        end

        # And the legitimate chain is not collateral damage — whatever policy
        # replaces the above, THIS must keep holding or every SPA logs out on
        # boot (RF-05).
        followup = refresh.call(app, rotated, "")
        followup.status_code.should eq 200
        followup_claims = decode.call(JSON.parse(followup.body)["access_token"].as_s)
        scopes_of.call(followup_claims).should eq ["public"]
        followup_claims["sub"].as_s.should eq user.id.as(String)
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end
  end
end
