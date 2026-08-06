require "../helper"
require "jwt"

module PlaceOS::Auth
  # Multi-tenant boundaries — PPT-2536 test-matrix rows MT-03 and IR-04.
  #
  # One auth.cr process serves every authority (eight on dev), so every
  # tenant boundary here is enforced in code rather than by deployment.
  # `bearer_credentials_spec.cr` covers the token half (AZ-06/MT-02): a token
  # minted for one authority is refused at another. This covers the two
  # boundaries either side of it — the *session* that precedes a token, and
  # introspection, which reads other people's tokens for a living.
  describe OAuth, tags: "multi-tenant" do
    decode = ->(token : String) {
      payload, _ = JWT.decode(token, ::Authly.config.public_key.as(String), JWT::Algorithm::RS256)
      payload
    }

    # A second authority, with a user and a password, alongside `localhost`.
    other_tenant = -> {
      authority = ::PlaceOS::Model::Generator.authority
      authority.domain = "tenant-#{Random.rand(999_999)}.example"
      authority.save!
      password = "bcrypt-please-#{Random.rand(999_999)}"
      user = ::PlaceOS::Model::Generator.user(authority)
      user.password = password
      user.save!
      {authority, user, password}
    }

    local_user = -> {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      password = "bcrypt-please-#{Random.rand(999_999)}"
      user = ::PlaceOS::Model::Generator.user(authority)
      user.password = password
      user.save!
      {authority, user, password}
    }

    # `Spec.signin!` hardcodes `Host: localhost`, so it cannot sign a user
    # in at any other authority — which is exactly what these rows need.
    signin_at = ->(host : String, user : ::PlaceOS::Model::User, password : String) {
      result = client.post("/auth/signin",
        headers: HTTP::Headers{"Host" => host, "Content-Type" => "application/json"},
        body: {email: user.email.to_s, password: password}.to_json)
      raise "signin at #{host} failed: #{result.status_code} #{result.body}" unless {202, 303}.includes?(result.status_code)
      session = result.cookies[PlaceOS::Auth::SESSION_COOKIE_NAME]?
      raise "signin at #{host} set no session cookie" if session.nil?
      "#{session.name}=#{session.value}"
    }

    make_app = ->(owner : ::PlaceOS::Model::User, slug : String) {
      redirect = "https://mt.example/cb-#{slug}-#{Random.rand(999_999)}"
      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "mt-#{slug}-#{Random.rand(999_999)}"
      app.redirect_uri = redirect
      app.scopes = "public"
      app.owner_id = owner.id.as(String)
      app.confidential = true
      app.save!
      {app, redirect}
    }

    # ---- MT-03: the session is not bound to an authority ----------------

    describe "session / authority binding (MT-03)" do
      it "accepts a session cookie issued by one authority at another (PINNED)" do
        # `new_session` stores `uid`, `exp` and `iat` — no authority — and
        # `session_user` resolves it with a bare `User.find?(uid)`. The
        # session cookie is encrypted with ONE process-wide
        # `COOKIE_SESSION_SECRET`, so a cookie minted while signed in at
        # authority A decrypts and validates at authority B.
        #
        # Why this is a boundary worth writing down rather than a hole to
        # panic about: a browser will never do this by itself — cookies are
        # host-scoped, so B never receives A's cookie. It needs an attacker
        # who already holds the cookie value, and at that point they hold the
        # session regardless. And it does not yield a usable credential: the
        # token minted from it carries the USER's authority in `aud` (see the
        # next case), and `ensure_matching_domain` then refuses it at B.
        #
        # So the tenant boundary is enforced on the TOKEN, not on the
        # session. Pinned because that is a real design fact — anyone adding
        # a session-only surface to auth.cr (an admin page, a form post)
        # inherits this and would need their own check.
        _, user, password = local_user.call
        cookie = Spec.signin!(client, user, password)
        foreign_authority, _, _ = other_tenant.call

        result = client.get("/auth/authority", headers: HTTP::Headers{
          "Host" => foreign_authority.domain, "Cookie" => cookie,
        })

        result.status_code.should eq 200
        JSON.parse(result.body)["session"].as_bool.should be_true
      ensure
        user.try &.destroy
        foreign_authority.try &.destroy
      end

      it "stamps the token with the USER's authority, not the request Host" do
        # The control that makes the case above safe, and the assertion that
        # would fail first if it stopped being true. A code minted while
        # talking to authority B, with a session belonging to a `localhost`
        # user, still produces a token whose `aud` is `localhost` — so
        # `ensure_matching_domain` refuses it at B.
        _, user, password = local_user.call
        foreign_authority, _, _ = other_tenant.call
        app, redirect = make_app.call(user, "aud")
        cookie = Spec.signin!(client, user, password)

        authorized = client.get(
          "/auth/authorize?response_type=code" \
          "&client_id=#{URI.encode_www_form(app.uid.as(String))}" \
          "&redirect_uri=#{URI.encode_www_form(redirect)}&scope=public",
          headers: HTTP::Headers{"Host" => foreign_authority.domain, "Cookie" => cookie},
        )
        authorized.status_code.should eq 302
        code = URI::Params.parse(authorized.headers["Location"].split('?', 2).last)["code"]

        token = client.post("/auth/token",
          headers: HTTP::Headers{
            "Host"         => foreign_authority.domain,
            "Content-Type" => "application/x-www-form-urlencoded",
          },
          body: URI::Params.build { |fp|
            fp.add("grant_type", "authorization_code")
            fp.add("client_id", app.uid.as(String))
            fp.add("client_secret", app.secret)
            fp.add("code", code)
            fp.add("redirect_uri", redirect)
          })
        token.status_code.should eq 200

        access = JSON.parse(token.body)["access_token"].as_s
        claims = decode.call(access)
        # Minted while addressing the foreign authority, but bound to the
        # user's own.
        claims["aud"].as_s.should eq "localhost"
        claims["aud"].as_s.should_not eq foreign_authority.domain
        claims["sub"].as_s.should eq user.id.as(String)

        # And therefore unusable at the authority it was requested through.
        refused = client.get("/auth/userinfo", headers: HTTP::Headers{
          "Host" => foreign_authority.domain, "Authorization" => "Bearer #{access}",
        })
        refused.status_code.should eq 401
      ensure
        app.try &.destroy
        user.try &.destroy
        foreign_authority.try &.destroy
      end
    end

    # ---- IR-04: introspection across tenants ----------------------------

    describe "cross-tenant introspection (IR-04)" do
      it "reports another tenant's token as inactive rather than describing it" do
        # RFC 7662 §2.2: an introspection response for a token the caller is
        # not entitled to see must be `{"active": false}` — not an error, and
        # certainly not the token's metadata. `introspection_revocation_spec`
        # covers the cross-*application* case within one tenant; this is the
        # same guard across authorities, where a leak would cross an
        # organisational boundary rather than an app one.
        _, local, local_password = local_user.call
        foreign_authority, foreign_user, foreign_password = other_tenant.call

        victim_app, victim_redirect = make_app.call(foreign_user, "victim")
        caller_app, _ = make_app.call(local, "caller")

        # Mint a real token for the foreign tenant's app.
        foreign_cookie = signin_at.call(foreign_authority.domain, foreign_user, foreign_password)
        authorized = client.get(
          "/auth/authorize?response_type=code" \
          "&client_id=#{URI.encode_www_form(victim_app.uid.as(String))}" \
          "&redirect_uri=#{URI.encode_www_form(victim_redirect)}&scope=public",
          headers: HTTP::Headers{"Host" => foreign_authority.domain, "Cookie" => foreign_cookie},
        )
        authorized.status_code.should eq 302
        code = URI::Params.parse(authorized.headers["Location"].split('?', 2).last)["code"]

        issued = client.post("/auth/token",
          headers: HTTP::Headers{
            "Host"         => foreign_authority.domain,
            "Content-Type" => "application/x-www-form-urlencoded",
          },
          body: URI::Params.build { |fp|
            fp.add("grant_type", "authorization_code")
            fp.add("client_id", victim_app.uid.as(String))
            fp.add("client_secret", victim_app.secret)
            fp.add("code", code)
            fp.add("redirect_uri", victim_redirect)
          })
        issued.status_code.should eq 200
        victim_token = JSON.parse(issued.body)["access_token"].as_s

        # A different tenant's client asks about it, authenticating properly
        # as itself.
        result = client.post("/auth/introspect",
          headers: HTTP::Headers{
            "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
          },
          body: URI::Params.build { |fp|
            fp.add("token", victim_token)
            fp.add("client_id", caller_app.uid.as(String))
            fp.add("client_secret", caller_app.secret)
          })

        result.status_code.should eq 200
        body = JSON.parse(result.body)
        body["active"].as_bool.should be_false
        # Nothing about the token may leak alongside the `false` — not the
        # subject, not the scope, not the owning client.
        body.as_h.has_key?("scope").should be_false
        body.as_h.has_key?("client_id").should be_false
        body.as_h.has_key?("exp").should be_false
        result.body.should_not contain foreign_user.id.as(String)
        result.body.should_not contain victim_app.uid.as(String)
      ensure
        victim_app.try &.destroy
        caller_app.try &.destroy
        local.try &.destroy
        foreign_user.try &.destroy
        foreign_authority.try &.destroy
      end

      it "still describes the token to its own client (the control)" do
        # Without this, a build whose introspection always answered
        # `{"active": false}` would pass the case above.
        _, local, _ = local_user.call
        app, redirect = make_app.call(local, "self")

        issued = client.post("/auth/token",
          headers: HTTP::Headers{
            "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
          },
          body: URI::Params.build { |fp|
            fp.add("grant_type", "client_credentials")
            fp.add("client_id", app.uid.as(String))
            fp.add("client_secret", app.secret)
            fp.add("scope", "public")
          })
        issued.status_code.should eq 200
        own_token = JSON.parse(issued.body)["access_token"].as_s

        result = client.post("/auth/introspect",
          headers: HTTP::Headers{
            "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
          },
          body: URI::Params.build { |fp|
            fp.add("token", own_token)
            fp.add("client_id", app.uid.as(String))
            fp.add("client_secret", app.secret)
          })

        result.status_code.should eq 200
        JSON.parse(result.body)["active"].as_bool.should be_true
      ensure
        app.try &.destroy
        local.try &.destroy
      end
    end
  end
end
