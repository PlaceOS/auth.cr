require "../helper"
require "jwt"

module PlaceOS::Auth
  # OpenID Connect ID-token coverage (PPT-2536 test matrix, section H:
  # rows OI-01, OI-02, OI-03, plus the issuer half of OI-07).
  #
  # The `id_token` is the only part of the OIDC surface an external relying
  # party consumes directly — everything inside PlaceOS validates the *access*
  # token instead (rest-api and staff-api decode it with
  # `PlaceOS::Model::UserJWT`). So these specs are the contract for the
  # standards-facing consumers the consumer sweep could not enumerate.
  #
  # Two adapter patches make the `sub` claim correct and are asserted here
  # because both are compensations for upstream authly gaps:
  #
  #   * `Authly::Code#jwt` (authly_adapter.cr) embeds `user_id` in the
  #     authorization code, because upstream captured the issuer/TTL
  #     constants at class-load time and carried no resource owner.
  #   * `Authly::Grant#generate_id_token` reads that `user_id` back out; with
  #     no code (the refresh and client-credentials grants) it returns nil
  #     rather than raising, which is what stops a legacy `openid` grant from
  #     500ing the token endpoint.
  #
  # Without them the ID token's `sub` would be a random hex string rather than
  # the resource owner's id — an RP would key its user records off a value
  # that changes on every login.
  describe OAuth, tags: "oidc-id-token" do
    form_post = ->(path : String, params : Hash(String, String)) {
      headers = HTTP::Headers{
        "Host"         => "localhost",
        "Content-Type" => "application/x-www-form-urlencoded",
      }
      body = URI::Params.build { |fp| params.each { |k, v| fp.add(k, v) } }
      client.post(path, headers: headers, body: body)
    }

    # Runs a complete authorization-code flow for `scopes` and returns the
    # user, the application, its redirect and the parsed token response.
    authorize_and_exchange = ->(scopes : String) {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      user = ::PlaceOS::Model::Generator.user(authority)
      user.first_name = "Ada"
      user.last_name = "Lovelace"
      user.nickname = "ada"
      user.login_name = "ada-#{Random.rand(99999)}"
      password = "bcrypt-please-#{Random.rand(99999)}"
      user.password = password
      user.save!

      # `uid` is MD5(redirect_uri) and globally unique — every application in
      # a spec needs its own redirect.
      redirect = "https://oidc.example/cb/#{UUID.random}"
      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "oidc-test-#{Random.rand(99999)}"
      app.redirect_uri = redirect
      app.scopes = scopes
      app.owner_id = user.id.as(String)
      app.confidential = true
      app.save!

      cookie = Spec.signin!(client, user, password)
      authorize_result = client.get(
        "/auth/oauth/authorize?response_type=code" \
        "&client_id=#{URI.encode_www_form(app.uid.as(String))}" \
        "&redirect_uri=#{URI.encode_www_form(redirect)}" \
        "&scope=#{URI.encode_www_form(scopes)}",
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
      })
      token_result.status_code.should eq 200
      {user, app, redirect, JSON.parse(token_result.body)}
    }

    decode = ->(token : String) {
      JWT.decode(token, ::Authly.config.public_key.as(String), JWT::Algorithm::RS256)
    }

    # ---- OI-01: is an id_token issued, and only when it should be? -------

    describe "id_token issuance (OI-01)" do
      it "returns an id_token on the code grant when openid was requested" do
        user, app, _redirect, body = authorize_and_exchange.call("public openid")

        id_token = body["id_token"].as_s
        id_token.should_not be_empty
        # Three dot-separated segments, i.e. a signed JWS rather than a
        # placeholder string.
        id_token.split('.').size.should eq 3
        # Issued alongside — not instead of — the access token.
        body["access_token"].as_s.should_not be_empty
        body["token_type"].as_s.should eq "Bearer"
        body["scope"].as_s.should eq "public openid"
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "omits id_token entirely when openid was not requested" do
        user, app, _redirect, body = authorize_and_exchange.call("public")

        # `TokenResponse#id_token` is `emit_null: false`, so absence is the
        # key being missing rather than a null — assert the key, not the value.
        body.as_h.has_key?("id_token").should be_false
        body["access_token"].as_s.should_not be_empty
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "omits id_token on the client_credentials grant even when openid is requested" do
        authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
        user = ::PlaceOS::Model::Generator.user(authority).tap do |u|
          u.password = "ignored-#{Random.rand(99999)}"
          u.save!
        end
        app = ::PlaceOS::Model::DoorkeeperApplication.new
        app.name = "oidc-cc-#{Random.rand(99999)}"
        app.redirect_uri = "https://oidc.example/cb/#{UUID.random}"
        app.scopes = "public openid"
        app.owner_id = user.id.as(String)
        app.confidential = true
        app.save!

        # There is no resource owner behind a machine grant, so there is no
        # subject to assert about. Upstream authly would have reached for
        # `auth_code["user_id"]` and raised; the `generate_id_token` patch
        # returns nil when there is no code.
        result = form_post.call("/auth/oauth/token", {
          "grant_type"    => "client_credentials",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "scope"         => "public openid",
        })
        result.status_code.should eq 200
        body = JSON.parse(result.body)
        body.as_h.has_key?("id_token").should be_false
        body["access_token"].as_s.should_not be_empty
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "refreshes an openid grant without an id_token and without a 500" do
        user, app, _redirect, body = authorize_and_exchange.call("public openid")

        # A refresh has no authorization code to derive an ID token from.
        # Before the `generate_id_token` patch this path read
        # `auth_code["user_id"]` unconditionally and 500'd the token endpoint
        # for any grant whose scope included `openid` — including every
        # legacy Doorkeeper row carrying that scope.
        refreshed = form_post.call("/auth/oauth/token", {
          "grant_type"    => "refresh_token",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "refresh_token" => body["refresh_token"].as_s,
        })
        refreshed.status_code.should eq 200
        refreshed_body = JSON.parse(refreshed.body)
        refreshed_body.as_h.has_key?("id_token").should be_false
        refreshed_body["access_token"].as_s.should_not be_empty
        # The granted scope survives the refresh (PR #8 / PR #10).
        refreshed_body["scope"].as_s.should eq "public openid"
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # ---- OI-02: the claim values --------------------------------------

    describe "id_token claims (OI-02)" do
      it "sets iss to the configured token issuer" do
        user, app, _redirect, body = authorize_and_exchange.call("public openid")
        claims, _header = decode.call(body["id_token"].as_s)

        # `POS` is the legacy Doorkeeper::JWT issuer; every PlaceOS service
        # validates against exactly this string.
        claims["iss"].as_s.should eq "POS"
        claims["iss"].as_s.should eq ::Authly.config.issuer
        claims["iss"].as_s.should eq ::PlaceOS::Model::UserJWT::ISSUER
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "sets aud to the client_id that requested the authorization" do
        user, app, _redirect, body = authorize_and_exchange.call("public openid")
        claims, _header = decode.call(body["id_token"].as_s)

        # OIDC Core §2: `aud` MUST contain the RP's client_id. We emit the
        # single client id as a string (Doorkeeper did the same).
        claims["aud"].as_s.should eq app.uid.as(String)
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "sets sub to the resource owner's user id — never the jti, never the client id" do
        user, app, _redirect, body = authorize_and_exchange.call("public openid")
        id_claims, _ = decode.call(body["id_token"].as_s)
        access_claims, _ = decode.call(body["access_token"].as_s)

        user_id = user.id.as(String)
        id_claims["sub"].as_s.should eq user_id

        # The three values `sub` must never be confused with. Upstream authly
        # assigned a random hex here (`AccessToken#initialize`), and the
        # introspection/claims code paths all have a `jti` and a client id in
        # scope, so these are the realistic regressions.
        id_claims["sub"].as_s.should_not eq app.uid.as(String)
        id_claims["sub"].as_s.should_not eq access_claims["jti"].as_s
        id_claims["sub"].as_s.should_not eq id_claims["aud"].as_s

        # The same subject must appear on the access token and at userinfo,
        # or an RP correlating the two would see two different principals.
        access_claims["sub"].as_s.should eq user_id
        userinfo = client.get("/auth/oauth/userinfo", headers: HTTP::Headers{
          "Host"          => "localhost",
          "Authorization" => "Bearer #{body["access_token"].as_s}",
        })
        userinfo.status_code.should eq 200
        JSON.parse(userinfo.body)["sub"].as_s.should eq user_id
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "carries the profile claims the legacy service emitted" do
        user, app, _redirect, body = authorize_and_exchange.call("public openid")
        claims, _header = decode.call(body["id_token"].as_s)

        claims["email"].as_s.should eq user.email.to_s
        claims["full_name"].as_s.should eq user.name
        # `preferred_username` prefers login_name and falls back to email.
        claims["preferred_username"].as_s.should eq user.login_name.as(String)
        claims["given_name"].as_s.should eq "Ada"
        claims["family_name"].as_s.should eq "Lovelace"
        claims["nickname"].as_s.should eq "ada"
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "is signed RS256 with the JWKS key and rejects a tampered payload" do
        user, app, _redirect, body = authorize_and_exchange.call("public openid")
        id_token = body["id_token"].as_s
        _claims, header = decode.call(id_token)

        header["alg"].as_s.should eq "RS256"
        header["typ"].as_s.should eq "JWT"

        # Swap the payload for one claiming a different subject while keeping
        # the original signature: verification must fail. This is what proves
        # the successful decode above was a signature check and not a decode.
        encoded_header, _encoded_payload, signature = id_token.split('.')
        forged_payload = Base64.urlsafe_encode(%({"sub":"attacker","iss":"POS"}), false)
        expect_raises(JWT::Error) do
          JWT.decode(
            "#{encoded_header}.#{forged_payload}.#{signature}",
            ::Authly.config.public_key.as(String),
            JWT::Algorithm::RS256,
          )
        end
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      # NOT IMPLEMENTED — see the PPT-2536 report for OI-02.
      #
      # OIDC Core §2 lists `exp` and `iat` as REQUIRED ID-token claims, and
      # doorkeeper-openid_connect emitted both. `Authly::Grant#generate_id_token`
      # builds the payload from `Authly.owners.id_token(user_id)` plus `iss`
      # and `aud` only, and `Authly.jwt_encode` is a bare `JWT.encode` that
      # adds nothing — so our ID token has no lifetime at all and a strict RP
      # will reject it (or, worse, accept it forever). Nothing inside PlaceOS
      # consumes the ID token, so this is an interop gap rather than a live
      # vulnerability, but it must be closed before an external RP is
      # onboarded.
      it "carries exp and iat (OIDC Core §2 REQUIRED)" do
        user, app, _redirect, body = authorize_and_exchange.call("public openid")
        claims, _header = decode.call(body["id_token"].as_s)

        now = Time.utc.to_unix
        claims["iat"].as_i64.should be_close(now, 60)
        claims["exp"].as_i64.should be > now
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      # Ruby parity: PlaceOS left doorkeeper-openid_connect's `expiration`
      # commented out, so its default of 120s applied. Pinned because an
      # ID token with a long life is a bearer assertion in disguise — it is
      # meant to be consumed once at sign-in, not held.
      it "gives the id_token the 120-second Doorkeeper lifetime" do
        user, app, _redirect, body = authorize_and_exchange.call("public openid")
        claims, _header = decode.call(body["id_token"].as_s)

        (claims["exp"].as_i64 - claims["iat"].as_i64).should eq 120
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      # The access token's own lifetime is 2 hours; the two must not be
      # confused for one another.
      it "expires the id_token well before the access token" do
        user, app, _redirect, body = authorize_and_exchange.call("public openid")
        claims, _header = decode.call(body["id_token"].as_s)
        access, _ = decode.call(body["access_token"].as_s)

        claims["exp"].as_i64.should be < access["exp"].as_i64
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # ---- OI-03: algorithm confusion --------------------------------------

    describe "algorithm confusion (OI-03)" do
      # Re-signs a genuine token's payload under a different algorithm. Both
      # `Authly.jwt_decode` and `PlaceOS::Model::UserJWT.decode` pass RS256
      # explicitly to `JWT.decode`, which ignores the header's `alg` — these
      # specs pin that, because the block form of `JWT.decode` *does* honour
      # the header and switching to it would open both attacks at once.
      forge = ->(token : String, algorithm : JWT::Algorithm, key : String) {
        payload, _header = JWT.decode(token, ::Authly.config.public_key.as(String), JWT::Algorithm::RS256)
        JWT.encode(payload, key, algorithm)
      }

      # Every surface that turns a presented JWT into an identity.
      assert_rejected = ->(app : ::PlaceOS::Model::DoorkeeperApplication, forged : String) {
        ::Authly.valid?(forged).should be_false

        introspect = form_post.call("/auth/oauth/introspect", {
          "token"         => forged,
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
        })
        introspect.status_code.should eq 200
        introspect_body = JSON.parse(introspect.body).as_h
        introspect_body["active"].as_bool.should be_false
        # The inactive envelope and nothing else — no scope, no client, no exp.
        introspect_body.keys.should eq ["active"]

        info = client.get("/auth/oauth/token/info", headers: HTTP::Headers{
          "Host" => "localhost", "Authorization" => "Bearer #{forged}",
        })
        info.status_code.should eq 401
        JSON.parse(info.body)["error"].as_s.should eq "invalid_token"

        userinfo = client.get("/auth/oauth/userinfo", headers: HTTP::Headers{
          "Host" => "localhost", "Authorization" => "Bearer #{forged}",
        })
        userinfo.status_code.should eq 401
      }

      # The same three surfaces accept the genuine article, so a rejection
      # above can never be an artefact of the fixture or the request shape.
      assert_accepted = ->(app : ::PlaceOS::Model::DoorkeeperApplication, genuine : String) {
        ::Authly.valid?(genuine).should be_true

        introspect = form_post.call("/auth/oauth/introspect", {
          "token"         => genuine,
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
        })
        introspect.status_code.should eq 200
        JSON.parse(introspect.body)["active"].as_bool.should be_true

        info = client.get("/auth/oauth/token/info", headers: HTTP::Headers{
          "Host" => "localhost", "Authorization" => "Bearer #{genuine}",
        })
        info.status_code.should eq 200

        userinfo = client.get("/auth/oauth/userinfo", headers: HTTP::Headers{
          "Host" => "localhost", "Authorization" => "Bearer #{genuine}",
        })
        userinfo.status_code.should eq 200
      }

      it "rejects an alg=none forgery of a live access token everywhere" do
        user, app, _redirect, body = authorize_and_exchange.call("public openid")
        genuine = body["access_token"].as_s

        # Identical claims — same jti, same sub, same exp — but unsigned.
        # If any surface trusted the header's `alg`, this would authenticate
        # as the user with a signature of zero bytes.
        forged = forge.call(genuine, JWT::Algorithm::None, "")
        forged.split('.').last.should be_empty

        assert_accepted.call(app, genuine)
        assert_rejected.call(app, forged)
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "rejects an RS256-to-HS256 confusion signed with the published public key" do
        user, app, _redirect, body = authorize_and_exchange.call("public openid")
        genuine = body["access_token"].as_s

        # The classic asymmetric-to-symmetric confusion: the verification key
        # is public (we serve it at /auth/oauth/discovery/keys), so if the
        # header chose the algorithm an attacker could HMAC arbitrary claims
        # with it and be believed.
        public_key = ::Authly.config.public_key.as(String)
        forged = forge.call(genuine, JWT::Algorithm::HS256, public_key)
        JWT.decode(forged, public_key, JWT::Algorithm::HS256).first["sub"].as_s.should_not be_empty

        assert_accepted.call(app, genuine)
        assert_rejected.call(app, forged)
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # ---- OI-07: discovery issuer vs the token iss claim ------------------

    describe "discovery issuer vs token iss (OI-07)" do
      it "advertises a host-derived issuer while tokens carry the legacy POS issuer" do
        user, app, _redirect, body = authorize_and_exchange.call("public openid")
        id_claims, _ = decode.call(body["id_token"].as_s)
        access_claims, _ = decode.call(body["access_token"].as_s)

        discovery = client.get("/.well-known/openid-configuration",
          headers: HTTP::Headers{"Host" => "localhost"})
        discovery.status_code.should eq 200
        advertised = JSON.parse(discovery.body)["issuer"].as_s

        # ACCEPTED DIVERGENCE, inherited from the Ruby service: Doorkeeper::JWT
        # signed tokens with `issuer: "POS"` while doorkeeper-openid_connect
        # derived the discovery issuer from the request host. auth.cr
        # reproduces both halves exactly, so PlaceOS services keep validating
        # `POS`...
        access_claims["iss"].as_s.should eq "POS"
        id_claims["iss"].as_s.should eq "POS"
        # ...while discovery keeps advertising the origin it was fetched from.
        advertised.should match /\Ahttps?:\/\/localhost\z/
        URI.parse(advertised).host.should eq "localhost"
        # The consequence, pinned so it is impossible to rediscover by
        # accident: a spec-compliant external RP compares `id_token.iss`
        # against the discovery `issuer` and will reject our ID token.
        id_claims["iss"].as_s.should_not eq advertised
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # ---- OI-04: nonce ---------------------------------------------------

    describe "nonce is not supported (OI-04)" do
      it "drops a nonce sent to the authorize endpoint instead of echoing it" do
        # OIDC Core §3.1.2.1 makes `nonce` OPTIONAL for the code flow, and
        # §3.1.3.7 step 11 says that if the client sent one, it MUST verify
        # the same value comes back in the ID token. auth.cr never captures
        # it: `/auth/authorize` has no `nonce` parameter, `Authly::Code`
        # has no field for it, and `AuthlyAdapter::Owner#id_token` never
        # emits one (there is a comment saying as much).
        #
        # The consequence is a real interop limit, not a cosmetic gap: an RP
        # library that sends `nonce` by default — most do, even on the code
        # flow — will reject our ID token as tampered. It is a *safe*
        # failure (login refused, never wrongly accepted), and no PlaceOS
        # client sends one today, which is why it has never been noticed.
        # Pinned so that anyone integrating an external RP finds this here
        # rather than in a support ticket, and so an implementation lands
        # with a test already waiting for it.
        user, app, redirect, cookie, password = nil, nil, nil, nil, nil
        authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
        user = ::PlaceOS::Model::Generator.user(authority)
        password = "bcrypt-please-#{Random.rand(99999)}"
        user.password = password
        user.save!

        redirect = "https://oidc.example/cb/#{UUID.random}"
        app = ::PlaceOS::Model::DoorkeeperApplication.new
        app.name = "oidc-nonce-#{Random.rand(99999)}"
        app.redirect_uri = redirect
        app.scopes = "openid public"
        app.owner_id = user.id.as(String)
        app.confidential = true
        app.save!

        cookie = Spec.signin!(client, user, password)
        the_nonce = "nonce-#{Random.rand(999_999_999)}"
        authorized = client.get(
          "/auth/oauth/authorize?response_type=code" \
          "&client_id=#{URI.encode_www_form(app.uid.as(String))}" \
          "&redirect_uri=#{URI.encode_www_form(redirect)}" \
          "&scope=#{URI.encode_www_form("openid public")}" \
          "&nonce=#{URI.encode_www_form(the_nonce)}",
          headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie},
        )

        # An unknown parameter must not break the flow — the login still
        # works, which is exactly why the missing claim is easy to miss.
        authorized.status_code.should eq 302
        code = URI::Params.parse(authorized.headers["Location"].split('?', 2).last)["code"]

        token = form_post.call("/auth/token", {
          "grant_type"    => "authorization_code",
          "client_id"     => app.uid.as(String),
          "client_secret" => app.secret,
          "code"          => code,
          "redirect_uri"  => redirect,
        })
        token.status_code.should eq 200

        id_token = JSON.parse(token.body)["id_token"].as_s
        id_token.should_not be_empty
        payload, _ = JWT.decode(id_token, ::Authly.config.public_key.as(String), JWT::Algorithm::RS256)

        # The claim an OIDC-conformant RP would check, and its absence.
        payload.as_h.has_key?("nonce").should be_false
        # Positive control: the ID token IS otherwise well-formed, so this is
        # a missing claim and not a broken flow.
        payload["sub"].as_s.should eq user.id.as(String)
        payload["aud"].as_s.should eq app.uid.as(String)
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # ---- OI-05 / OI-06: the userinfo endpoint ---------------------------

    describe "userinfo (OI-05, OI-06)" do
      it "answers GET and POST identically, with a sub matching the id_token" do
        # OIDC Core §5.3 requires both verbs, and §5.3.2 requires the
        # `sub` returned here to match the `sub` of the ID token issued in
        # the same grant. An RP that keys its user records off userinfo
        # while validating the ID token separately breaks silently if the
        # two ever disagree — `discovery_spec.cr` proves both verbs are
        # ROUTED; this proves they agree, and with what.
        user, app, _redirect, token = authorize_and_exchange.call("openid public")
        access = token["access_token"].as_s
        id_payload, _ = JWT.decode(token["id_token"].as_s,
          ::Authly.config.public_key.as(String), JWT::Algorithm::RS256)

        headers = HTTP::Headers{"Host" => "localhost", "Authorization" => "Bearer #{access}"}
        via_get = client.get("/auth/userinfo", headers: headers)
        via_post = client.post("/auth/userinfo", headers: headers)

        via_get.status_code.should eq 200
        via_post.status_code.should eq 200
        JSON.parse(via_get.body).should eq JSON.parse(via_post.body)

        subject = JSON.parse(via_get.body)["sub"].as_s
        subject.should eq user.id.as(String)
        subject.should eq id_payload["sub"].as_s
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "404s with an empty error once the user behind the token is gone (OI-05 — DIVERGENCE)" do
        # A token can outlive its user: a deletion, or a tenant teardown,
        # inside the 2-hour access-token window. What comes back is
        # `404 {"error":""}`.
        #
        # Why 404 and not the `unknown subject` 401 the code appears to
        # intend: `authorize!` calls `::PlaceOS::Model::User.find(...)`,
        # which RAISES `PgORM::Error::RecordNotFound` rather than returning
        # nil. That escapes the `rescue e : JWT::Error` around it and lands
        # on the base controller's RecordNotFound handler — so
        # `OAuth#userinfo`'s own `raise Error::Unauthorized.new("unknown
        # subject")` guard is never reached by this route. (It still covers
        # the guest-scope path, which skips the user lookup entirely.)
        #
        # Two problems, both diagnosability rather than security. RFC 6750
        # §3.1 and OIDC Core §5.3.3 want 401 `invalid_token` here — an RP
        # reading 404 concludes the *endpoint* is missing and may disable
        # userinfo entirely, rather than refreshing the token. And the body
        # carries `{"error":""}`, because `RecordNotFound` is raised with no
        # message, so nothing in the response says what was not found.
        #
        # Pinned rather than fixed: changing it means either making
        # `authorize!` tolerate the missing row (which is a real semantic
        # decision about whether a userless token is authenticated at all)
        # or catching RecordNotFound per-controller. Worth doing
        # deliberately, with the guest-scope path considered alongside.
        user, app, _redirect, token = authorize_and_exchange.call("openid public")
        access = token["access_token"].as_s
        headers = HTTP::Headers{"Host" => "localhost", "Authorization" => "Bearer #{access}"}

        # Control: it works while the user exists, so the change below is
        # attributable to the deletion and nothing else.
        client.get("/auth/userinfo", headers: headers).status_code.should eq 200

        user.destroy
        user = nil

        result = client.get("/auth/userinfo", headers: headers)
        result.status_code.should eq 404
        JSON.parse(result.body)["error"].as_s.should be_empty
        # Whatever else changes, no claims may leak for a user that is gone.
        result.body.should_not contain "\"sub\""
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end
  end
end
