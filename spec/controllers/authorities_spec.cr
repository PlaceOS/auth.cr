require "../helper"

module PlaceOS::Auth
  describe Authorities do
    describe "GET /auth/authority" do
      it "returns authority details when the host matches" do
        # the suite's authentication helper has already seeded "localhost"
        result = client.get("/auth/authority", headers: HTTP::Headers{"Host" => "localhost"})

        result.status_code.should eq 200
        body = JSON.parse(result.body)
        body["domain"].as_s.should eq "localhost"
        body["production"].as_bool.should be_false
        body["session"].as_bool.should be_false
        body["token_valid"].as_bool.should be_false
        body["version"].as_s.should start_with "v"
      end

      it "returns 404 when no authority matches the host" do
        result = client.get("/auth/authority", headers: HTTP::Headers{"Host" => "nope.example"})
        result.status_code.should eq 404
      end

      it "returns 200 with empty body for unknown host when ?health is set" do
        result = client.get("/auth/authority?health=1", headers: HTTP::Headers{"Host" => "nope.example"})
        result.status_code.should eq 200
        result.body.should be_empty
      end

      it "answers ?health with an empty 200 even for a matching host (no DB lookup)" do
        # The liveness short-circuit runs before any authority resolution, so a
        # matching host still gets the empty process-is-up 200 (not the JSON) —
        # proving a Postgres outage can't 500 the probe.
        result = client.get("/auth/authority?health=true", headers: HTTP::Headers{"Host" => "localhost"})
        result.status_code.should eq 200
        result.body.should be_empty
      end

      it "marks token_valid=true when a Bearer JWT is supplied" do
        _, headers = Spec::Authentication.authentication
        headers["Host"] = "localhost"

        result = client.get("/auth/authority", headers: headers)
        result.status_code.should eq 200
        body = JSON.parse(result.body)
        body["token_valid"].as_bool.should be_true
      end

      it "marks token_valid=true when an X-API-Key is supplied" do
        _, headers = Spec::Authentication.x_api_authentication
        headers["Host"] = "localhost"

        result = client.get("/auth/authority", headers: headers)
        result.status_code.should eq 200
        body = JSON.parse(result.body)
        body["token_valid"].as_bool.should be_true
      end

      # ---- MT-05: the `verified` asset-access cookie -------------------
      #
      # `/auth/authority` is the single most-called endpoint in the estate
      # (1,125 hits in the dev sample) because every SPA polls it. Ruby's
      # `AuthoritiesController#current` re-issued the nginx-validated
      # `verified` cookie whenever the caller's token checked out, so a
      # token-only client (no session cookie) keeps its asset access alive
      # just by polling. Without it those clients bounce through
      # `/auth/login` when the cookie eventually lapses.
      live_verified = ->(result : HTTP::Client::Response) {
        cookie = result.cookies[Utils::SessionHelper::VERIFIED_COOKIE_NAME]?
        cookie.should_not be_nil
        cookie = cookie.not_nil!
        # `clear_asset_access` writes the same name+path with an empty value
        # and `Time.unix(0)`, so asserting mere presence would pass on a
        # *cleared* cookie. Assert the live shape: 16 hex . 64 hex HMAC.
        cookie.value.should match(/\A[0-9a-f]{16}\.[0-9a-f]{64}\z/)
        cookie.expires.not_nil!.should be > Time.utc
        cookie
      }

      it "re-issues the verified cookie when a Bearer token validates" do
        _, headers = Spec::Authentication.authentication
        headers["Host"] = "localhost"

        result = client.get("/auth/authority", headers: headers)
        result.status_code.should eq 200
        JSON.parse(result.body)["token_valid"].as_bool.should be_true

        cookie = live_verified.call(result)
        cookie.path.should eq Utils::SessionHelper::VERIFIED_COOKIE_PATH
        cookie.secure.should be_true
        cookie.http_only.should be_true
        cookie.samesite.should eq HTTP::Cookie::SameSite::None
      end

      it "re-issues the verified cookie for an X-API-Key caller" do
        _, headers = Spec::Authentication.x_api_authentication
        headers["Host"] = "localhost"

        result = client.get("/auth/authority", headers: headers)
        result.status_code.should eq 200
        live_verified.call(result)
      end

      it "does not issue a verified cookie to an unauthenticated caller" do
        # The control: asset access is granted on a *valid* credential, not
        # on merely asking. Without this the two above would pass even if
        # the cookie were issued unconditionally.
        result = client.get("/auth/authority", headers: HTTP::Headers{"Host" => "localhost"})
        result.status_code.should eq 200
        JSON.parse(result.body)["token_valid"].as_bool.should be_false
        result.cookies[Utils::SessionHelper::VERIFIED_COOKIE_NAME]?.should be_nil
      end

      it "does not let a stale session's teardown clobber the fresh cookie" do
        # `configure_asset_access` runs *after* `signed_in?` deliberately:
        # resolving a dead session calls `remove_session`, which calls
        # `clear_asset_access` and writes the expired cookie. If the order
        # were reversed, a client holding a logged-out session cookie *and*
        # a good token would be handed the cleared cookie and bounce to
        # /auth/login on its next asset fetch — while being told
        # `token_valid: true`.
        password = "ok-password-1234"
        authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
        stale_user = ::PlaceOS::Model::Generator.user(authority)
        stale_user.password = password
        stale_user.save!
        stale_cookie = Spec.signin!(client, stale_user, password)

        # Kill that session server-side: logging out stamps `logged_out_at`,
        # so `session_user` tears the session down on the next request.
        stale_user.logged_out_at = Time.utc
        stale_user.save!

        _, headers = Spec::Authentication.authentication
        headers["Host"] = "localhost"
        headers["Cookie"] = stale_cookie

        result = client.get("/auth/authority", headers: headers)
        result.status_code.should eq 200
        body = JSON.parse(result.body)
        body["session"].as_bool.should be_false
        body["token_valid"].as_bool.should be_true

        live_verified.call(result)
      ensure
        stale_user.try &.destroy
      end

      it "keeps token_valid=false for a malformed Bearer token" do
        headers = HTTP::Headers{
          "Host"          => "localhost",
          "Authorization" => "Bearer not-a-real-jwt",
        }
        result = client.get("/auth/authority", headers: headers)
        result.status_code.should eq 200
        body = JSON.parse(result.body)
        body["token_valid"].as_bool.should be_false
      end
    end
  end
end
