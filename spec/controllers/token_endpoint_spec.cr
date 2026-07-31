require "../helper"
require "base64"
require "digest/sha256"
require "jwt"

module PlaceOS::Auth
  # Token-endpoint grants and error envelopes — PPT-2536 test-matrix rows
  # TK-03, TK-04, TK-06, TK-07, TK-08.
  #
  # `oauth_spec.cr` already covers the happy paths (TK-01/TK-02, the
  # confidential client_credentials grant, and the public-client denial).
  # What was missing is everything a real client hits when something is
  # *wrong*: the exact status, the exact `error` code, the RFC 6750 challenge
  # headers, and which parameters the endpoint will read from where.
  #
  # That last point is not cosmetic. ts-client discards its refresh token on
  # ANY 4xx (tasks/PPT-2536/research/client-auth-contract.md §1), so the
  # difference between "401 with a challenge" and "422 missing parameter" is
  # the difference between a retry and a forced re-login for every user — the
  # B.3 incident class.
  #
  # Where auth.cr deliberately diverges from RFC 6749 / Ruby Doorkeeper, the
  # divergence is pinned here rather than fixed, so it stays a reviewed
  # decision instead of drifting.
  describe OAuth, tags: "token-endpoint" do
    decode = ->(token : String) {
      payload, _ = JWT.decode(token, ::Authly.config.public_key.as(String), JWT::Algorithm::RS256)
      payload
    }
    scopes_of = ->(claims : JSON::Any) { claims["scope"].as_a.map(&.as_s) }

    # `DoorkeeperApplication#uid` is MD5(redirect_uri.downcase), so every app
    # needs a distinct redirect or the second `save!` collides. `secret` is
    # regenerated in `before_create`, so it is always read back off the model.
    make_app = ->(confidential : Bool, redirect : String) {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      user = ::PlaceOS::Model::Generator.user(authority)
      password = "bcrypt-please-#{Random.rand(999_999)}"
      user.password = password
      user.save!

      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "token-endpoint-#{Random.rand(999_999)}"
      app.redirect_uri = redirect
      app.scopes = "public"
      app.owner_id = user.id.as(String)
      app.confidential = confidential
      app.save!
      {user, app, password}
    }

    form_post = ->(path : String, params : Hash(String, String)) {
      client.post(path, headers: HTTP::Headers{
        "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
      }, body: URI::Params.build { |fp| params.each { |k, v| fp.add(k, v) } })
    }

    # Drives a real `GET /auth/authorize` and returns the issued code. Each
    # call mints an independent code so a spec can pair a failing exchange
    # with a passing control without depending on code-replay semantics.
    get_code = ->(app : ::PlaceOS::Model::DoorkeeperApplication, cookie : String, redirect : String, challenge : String?) {
      query = String.build do |io|
        io << "/auth/authorize?response_type=code"
        io << "&client_id=" << URI.encode_www_form(app.uid.as(String))
        io << "&redirect_uri=" << URI.encode_www_form(redirect)
        io << "&scope=public"
        if value = challenge
          io << "&code_challenge=" << URI.encode_www_form(value)
          io << "&code_challenge_method=S256"
        end
      end
      result = client.get(query, headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie})
      result.status_code.should eq 302
      URI::Params.parse(result.headers["Location"].split('?', 2).last)["code"]
    }

    # ---- TK-03: client_credentials by client type -----------------------

    describe "client_credentials grant (TK-03)" do
      # The confidential-allowed and public-denied-with-secret branches already
      # live in oauth_spec.cr ("issues an access token for the
      # client_credentials grant" / "denies the client_credentials grant to a
      # public client"). These are the facts neither of those pins.

      it "denies client_credentials to a public client that presents no secret at all" do
        user, app, _password = make_app.call(false, "https://tk03.example/cb-#{Random.rand(999_999)}")

        # `AuthlyAdapter::Client#authorized?` short-circuits to `true` for public
        # clients — they cannot hold a secret, PKCE is their proof of possession.
        # The only thing stopping that bypass from becoming a free machine-
        # credential grant is `allowed_grant_type?`. oauth_spec covers the
        # variant that presents the app's real secret; this is the request an
        # attacker who scraped a client_id out of the SPA bundle would send, and
        # it must fail on the *grant type*, not on a missing secret.
        result = form_post.call("/auth/token", {
          "grant_type" => "client_credentials",
          "client_id"  => app.uid.as(String),
        })

        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "unauthorized_client"
        result.headers["WWW-Authenticate"].should contain %(error="unauthorized_client")
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "issues a client-credentials token that carries no user identity" do
        user, app, _password = make_app.call(true, "https://tk03m.example/cb-#{Random.rand(999_999)}")

        result = form_post.call("/auth/token", {
          "grant_type"    => "client_credentials",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "scope"         => "public",
        })
        result.status_code.should eq 200
        claims = decode.call(JSON.parse(result.body)["access_token"].as_s)

        scopes_of.call(claims).should eq ["public"]
        # A machine grant has no resource owner, so authly assigns an opaque
        # 32-byte `sub`, `ClaimsProvider` finds no `User`, and neither the
        # legacy `u{n,e,p,r}` block nor `aud` is emitted.
        #
        # `AuthlyAdapter::Client#owner_id` exists and would return the app's
        # owner, but nothing in authly ever calls it. If it is ever wired up,
        # every client-credentials token silently inherits the owner's
        # permissions — and on dev the owners of these apps include sys_admins.
        # Keep these assertions: they are the guard on that.
        claims["sub"].as_s.should match(/\A[0-9a-f]{64}\z/)
        claims["sub"].as_s.should_not eq user.id.as(String)
        claims.as_h.has_key?("u").should be_false
        claims.as_h.has_key?("aud").should be_false
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "returns a refresh_token for client_credentials (divergence from RFC 6749 §4.4.3)" do
        user, app, _password = make_app.call(true, "https://tk03r.example/cb-#{Random.rand(999_999)}")

        result = form_post.call("/auth/token", {
          "grant_type"    => "client_credentials",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "scope"         => "public",
        })
        result.status_code.should eq 200

        # RFC 6749 §4.4.3 says a client-credentials response SHOULD NOT include
        # a refresh token, and Ruby Doorkeeper's ClientCredentialsRequest issued
        # none. authly's `AccessToken#initialize` always generates one, so
        # auth.cr does return it. Pinned rather than silently accepted: what it
        # redeems to is asserted by refresh_semantics_spec.cr (RF-07) — an empty
        # scope, never a healed `public`.
        JSON.parse(result.body)["refresh_token"].as_s.should_not be_empty
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # ---- TK-04: client authentication failures --------------------------

    describe "client authentication failures (TK-04)" do
      # NOTE on the error *code*: RFC 6749 §5.2 and Doorkeeper both name this
      # `invalid_client`; authly raises `unauthorized_client` and auth.cr passes
      # the symbol straight through. The HTTP status (401) and the challenge
      # headers match Doorkeeper exactly, and no PlaceOS client branches on the
      # code, so this is pinned as a known naming divergence.

      it "answers a wrong client_secret with 401 and the full challenge envelope" do
        user, app, _password = make_app.call(true, "https://tk04.example/cb-#{Random.rand(999_999)}")

        # Deliberately no `scope` param: `Grant#token` runs `validate_scope!`
        # BEFORE `authorized?`, so a request that carries a scope surfaces the
        # scope failure first (see the refresh case below).
        result = form_post.call("/auth/token", {
          "grant_type"    => "client_credentials",
          "client_id"     => app.uid.as(String),
          "client_secret" => "not-the-secret",
        })

        result.status_code.should eq 401
        body = JSON.parse(result.body)
        body["error"].as_s.should eq "unauthorized_client"
        body["error_description"].as_s.should_not be_empty
        # RFC 6750 §3 challenge, byte-compatible with the Doorkeeper 401s the
        # legacy service emitted.
        result.headers["WWW-Authenticate"].should contain %(Bearer realm="Doorkeeper")
        result.headers["WWW-Authenticate"].should contain %(error="unauthorized_client")
        result.headers["Cache-Control"].should contain "no-store"
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "answers an unknown client_id with the same 401 envelope" do
        result = form_post.call("/auth/token", {
          "grant_type"    => "client_credentials",
          "client_id"     => "ghost-#{Random.rand(999_999)}",
          "client_secret" => "anything",
        })

        # oauth_spec.cr pins the status + error code; the headers are the part a
        # browser/SDK actually consumes, and they were previously unasserted.
        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "unauthorized_client"
        result.headers["WWW-Authenticate"].should contain %(error="unauthorized_client")
        result.headers["Cache-Control"].should contain "no-store"
      end

      it "surfaces invalid_scope (not a client error) when refreshing with an unknown client_id" do
        user, app, _password = make_app.call(false, "https://tk04r.example/cb-#{Random.rand(999_999)}")
        token = Spec::LegacyFixtures.current_refresh_token(app.uid.as(String), user.id.as(String))

        result = form_post.call("/auth/token", {
          "grant_type"    => "refresh_token",
          "client_id"     => "ghost-#{Random.rand(999_999)}",
          "refresh_token" => token,
        })

        # Ordering artefact worth pinning because it is genuinely confusing in a
        # log: `Grant#token` validates the scope first, the scope is recovered
        # from the refresh token as `public`, and `allowed_scopes?` returns false
        # for a client that does not exist — so a *wrong client_id* is reported
        # as `invalid_scope` (400) rather than Doorkeeper's `invalid_client`
        # (401). Practical impact is bounded: ts-client drops the refresh token
        # on any 4xx.
        result.status_code.should eq 400
        JSON.parse(result.body)["error"].as_s.should eq "invalid_scope"
        result.headers["Cache-Control"].should contain "no-store"
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # ---- TK-06: redirect_uri binding ------------------------------------

    describe "redirect_uri binding (TK-06)" do
      it "rejects a code redeemed against a different (but registered) redirect_uri" do
        suffix = Random.rand(999_999)
        primary = "https://tk06.example/cb-#{suffix}"
        alternate = "https://tk06.example/alt-#{suffix}"
        # Doorkeeper stores multiple redirect URIs whitespace-separated in one
        # column, so both of these are registered for this client.
        user, app, password = make_app.call(true, "#{primary} #{alternate}")
        cookie = Spec.signin!(client, user, password)

        mismatched = get_code.call(app, cookie, primary, nil)
        control = get_code.call(app, cookie, primary, nil)

        bad = form_post.call("/auth/token", {
          "grant_type"    => "authorization_code",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "code"          => mismatched,
          "redirect_uri"  => alternate,
        })

        # RFC 6749 §4.1.3 requires the token request's redirect_uri to be
        # identical to the one the code was issued for — otherwise a client with
        # two registered callbacks can have a code stolen at one and redeemed at
        # the other. authly names this `invalid_redirect_uri`; Doorkeeper named
        # it `invalid_grant`. Both are non-retryable 400s; the code is pinned so
        # it stays stable for anything that parses it.
        bad.status_code.should eq 400
        JSON.parse(bad.body)["error"].as_s.should eq "invalid_redirect_uri"
        bad.headers["Cache-Control"].should contain "no-store"

        # Positive control — the ONLY difference is the redirect_uri, so a
        # sibling code redeemed against `primary` must succeed. Without this the
        # 400 above could be any unrelated breakage in the fixture.
        good = form_post.call("/auth/token", {
          "grant_type"    => "authorization_code",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "code"          => control,
          "redirect_uri"  => primary,
        })
        good.status_code.should eq 200
        claims = decode.call(JSON.parse(good.body)["access_token"].as_s)
        claims["sub"].as_s.should eq user.id.as(String)
        scopes_of.call(claims).should eq ["public"]
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "rejects an unregistered redirect_uri at the token endpoint without echoing it" do
        suffix = Random.rand(999_999)
        redirect = "https://tk06u.example/cb-#{suffix}"
        user, app, password = make_app.call(true, redirect)
        cookie = Spec.signin!(client, user, password)
        code = get_code.call(app, cookie, redirect, nil)

        bad = form_post.call("/auth/token", {
          "grant_type"    => "authorization_code",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "code"          => code,
          "redirect_uri"  => "https://evil.example/steal",
        })

        bad.status_code.should eq 400
        JSON.parse(bad.body)["error"].as_s.should eq "invalid_redirect_uri"
        # The error must be non-redirectable and must not reflect the attacker's
        # URI anywhere. Asserted alongside the exact status/code above so this
        # cannot pass merely because the response has no body.
        bad.headers["Location"]?.should be_nil
        bad.body.should_not contain "evil.example"
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # ---- TK-07: secrets by client type ----------------------------------

    describe "client_secret handling by client type (TK-07)" do
      it "rejects a confidential client that omits client_secret on the code exchange" do
        suffix = Random.rand(999_999)
        redirect = "https://tk07c.example/cb-#{suffix}"
        user, app, password = make_app.call(true, redirect)
        cookie = Spec.signin!(client, user, password)
        without_secret = get_code.call(app, cookie, redirect, nil)
        with_secret = get_code.call(app, cookie, redirect, nil)

        # The public-client bypass in `Client#authorized?` is gated on
        # `app.confidential`; a confidential client must still prove itself.
        result = form_post.call("/auth/token", {
          "grant_type"   => "authorization_code",
          "client_id"    => app.uid.as(String),
          "code"         => without_secret,
          "redirect_uri" => redirect,
        })
        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "unauthorized_client"
        result.headers["WWW-Authenticate"].should contain %(error="unauthorized_client")

        # Positive control: same client, same redirect, sibling code — the
        # secret is the only variable.
        good = form_post.call("/auth/token", {
          "grant_type"    => "authorization_code",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "code"          => with_secret,
          "redirect_uri"  => redirect,
        })
        good.status_code.should eq 200
        decode.call(JSON.parse(good.body)["access_token"].as_s)["sub"].as_s.should eq user.id.as(String)
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "accepts a public client that sends a client_secret anyway" do
        suffix = Random.rand(999_999)
        redirect = "https://tk07p.example/cb-#{suffix}"
        user, app, password = make_app.call(false, redirect)
        cookie = Spec.signin!(client, user, password)
        code = get_code.call(app, cookie, redirect, nil)

        # B.3-adjacent. All 66 dev clients are public, and some carry a leftover
        # secret in their bundle config. If auth.cr either required the parameter
        # (422 before any OAuth logic ran) or validated it for public clients
        # (401), every one of those exchanges would fail. Doorkeeper ignored it;
        # so must auth.cr — even when the value is wrong.
        result = form_post.call("/auth/token", {
          "grant_type"    => "authorization_code",
          "client_id"     => app.uid.as(String),
          "client_secret" => "totally-wrong-left-over-value",
          "code"          => code,
          "redirect_uri"  => redirect,
        })

        result.status_code.should eq 200
        claims = decode.call(JSON.parse(result.body)["access_token"].as_s)
        claims["sub"].as_s.should eq user.id.as(String)
        scopes_of.call(claims).should eq ["public"]
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "accepts a stray client_secret on a public-client refresh" do
        user, app, _password = make_app.call(false, "https://tk07r.example/cb-#{Random.rand(999_999)}")
        token = Spec::LegacyFixtures.current_refresh_token(app.uid.as(String), user.id.as(String))

        result = form_post.call("/auth/token", {
          "grant_type"    => "refresh_token",
          "client_id"     => app.uid.as(String),
          "client_secret" => "stale-value-from-an-old-config",
          "refresh_token" => token,
        })

        result.status_code.should eq 200
        claims = decode.call(JSON.parse(result.body)["access_token"].as_s)
        # scope + sub are the two claims the 2026-07-25 revert was about; they
        # get asserted on every refresh path here, not just the happy one.
        scopes_of.call(claims).should eq ["public"]
        claims["sub"].as_s.should eq user.id.as(String)
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # ---- TK-08: where parameters may be supplied ------------------------

    describe "parameter placement (TK-08)" do
      it "honours the ts-client asymmetry: code exchange in the query, refresh in the body" do
        suffix = Random.rand(999_999)
        redirect = "https://tk08.example/cb-#{suffix}"
        # public client + PKCE + no secret: the shape every real PlaceOS SPA uses
        user, app, password = make_app.call(false, redirect)
        cookie = Spec.signin!(client, user, password)

        # ts-client `generateChallenge`: base64url(SHA256(verifier)).
        verifier = "dBjftJeZ4CVPmB92K27uhbUJU1p1r-wW1gFWFOEjXk"
        challenge = Base64.strict_encode(Digest::SHA256.digest(verifier)).tr("+/", "-_")
        code = get_code.call(app, cookie, redirect, challenge)

        # Request 3 from client-auth-contract.md §6: every parameter in the URL
        # query, no request body at all, no Content-Type.
        query = URI::Params.build do |qp|
          qp.add("grant_type", "authorization_code")
          qp.add("client_id", app.uid.as(String))
          qp.add("redirect_uri", redirect)
          qp.add("code", code)
          qp.add("code_verifier", verifier)
        end
        exchanged = client.post("/auth/oauth/token?#{query}", headers: HTTP::Headers{"Host" => "localhost"})

        exchanged.status_code.should eq 200
        exchanged_body = JSON.parse(exchanged.body)
        exchanged_claims = decode.call(exchanged_body["access_token"].as_s)
        exchanged_claims["sub"].as_s.should eq user.id.as(String)
        scopes_of.call(exchanged_claims).should eq ["public"]

        # Request 4: the same client immediately refreshes with everything in the
        # POST body instead. The asymmetry is ts-client's, not a spec artefact —
        # both halves have to work against the same registration.
        refreshed = client.post("/auth/oauth/token", headers: HTTP::Headers{
          "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
        }, body: URI::Params.build { |fp|
          fp.add("grant_type", "refresh_token")
          fp.add("client_id", app.uid.as(String))
          fp.add("redirect_uri", redirect)
          fp.add("refresh_token", exchanged_body["refresh_token"].as_s)
        })

        refreshed.status_code.should eq 200
        refreshed_claims = decode.call(JSON.parse(refreshed.body)["access_token"].as_s)
        scopes_of.call(refreshed_claims).should eq ["public"]
        refreshed_claims["sub"].as_s.should eq user.id.as(String)
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "reads parameters split across the query string and the form body" do
        suffix = Random.rand(999_999)
        redirect = "https://tk08s.example/cb-#{suffix}"
        user, app, password = make_app.call(true, redirect)
        cookie = Spec.signin!(client, user, password)
        code = get_code.call(app, cookie, redirect, nil)

        # action-controller merges query params and the url-encoded body into a
        # single param set. Server-to-server integrations (and anything behind a
        # proxy that rewrites one side) legitimately split them, so the token
        # action must not care which side a parameter arrived on.
        result = client.post(
          "/auth/token?grant_type=authorization_code&client_id=#{URI.encode_www_form(app.uid.as(String))}",
          headers: HTTP::Headers{
            "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
          },
          body: URI::Params.build { |fp|
            fp.add("client_secret", app.secret)
            fp.add("code", code)
            fp.add("redirect_uri", redirect)
          })

        result.status_code.should eq 200
        claims = decode.call(JSON.parse(result.body)["access_token"].as_s)
        claims["sub"].as_s.should eq user.id.as(String)
        scopes_of.call(claims).should eq ["public"]
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "answers a JSON token request with a 422 naming the missing parameter" do
        # Rails merged JSON bodies into `params`, so Doorkeeper accepted a JSON
        # token request; action-controller's BodyParser only merges url-encoded
        # and multipart, so the typed route arguments never see them. No PlaceOS
        # client posts JSON here (client-auth-contract.md §6 requests 3 and 4 are
        # query and form respectively), so this is pinned as a bounded divergence
        # rather than fixed. What matters is that it is a clean, attributable
        # 422 — not a 500, and not a misleading OAuth error.
        result = client.post("/auth/token",
          headers: HTTP::Headers{"Host" => "localhost", "Content-Type" => "application/json"},
          body: {grant_type: "client_credentials", client_id: "anything"}.to_json)

        result.status_code.should eq 422
        JSON.parse(result.body)["parameter"].as_s.should eq "grant_type"
      end
    end
  end
end
