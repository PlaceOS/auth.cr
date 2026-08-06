require "../helper"

module PlaceOS::Auth
  # The Bearer half of `authorize!` — PPT-2536 test-matrix rows AK-06,
  # AZ-05 and AZ-06/MT-02. All three were marked open and had no coverage
  # at all; each is an invariant something in production already depends on.
  #
  # `/auth/userinfo` is the probe: the one route that calls `authorize!`
  # unconditionally and answers with the resolved `sub`, so a 200 proves the
  # credential resolved to the right user rather than merely being accepted.
  describe Utils::CurrentUser, tags: "bearer" do
    userinfo = ->(headers : HTTP::Headers) {
      client.get("/auth/userinfo", headers: headers)
    }

    # Mints a JWT the way the real token endpoint does, but with the issue
    # time and authority under the spec's control — `Spec::Authentication`
    # hardcodes `localhost` and `5.minutes.ago`, and two of the rows below
    # need to vary exactly those.
    mint = ->(user : ::PlaceOS::Model::User, authority : ::PlaceOS::Model::Authority, iat : Time) {
      permissions = case ({user.support, user.sys_admin})
                    when {true, true}  then ::PlaceOS::Model::UserJWT::Permissions::AdminSupport
                    when {true, false} then ::PlaceOS::Model::UserJWT::Permissions::Support
                    when {false, true} then ::PlaceOS::Model::UserJWT::Permissions::Admin
                    else                    ::PlaceOS::Model::UserJWT::Permissions::User
                    end

      ::PlaceOS::Model::UserJWT.new(
        iss: ::PlaceOS::Model::UserJWT::ISSUER,
        iat: iat,
        exp: 1.hour.from_now,
        domain: authority.domain,
        id: user.id.as(String),
        user: ::PlaceOS::Model::UserJWT::Metadata.new(
          name: user.name,
          email: user.email.to_s,
          permissions: permissions,
          roles: user.groups,
        ),
        scope: [::PlaceOS::Model::UserJWT::Scope::PUBLIC],
      ).encode
    }

    local_user = -> {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      user = ::PlaceOS::Model::Generator.user(authority)
      user.save!
      {user, authority}
    }

    # ---- AK-06: every place a Bearer token is accepted from -------------

    describe "bearer token sources (AK-06)" do
      # `acquire_token` reads the `Authorization` header, then a
      # `bearer_token` param, then a `bearer_token` cookie. Only the header
      # was ever exercised, yet ts-client's WebSocket transport cannot set
      # headers: it puts the token on the query string and additionally
      # drops a 2-minute `bearer_token` cookie. Both were untested paths
      # carrying live sessions.
      it "authenticates a token on the Authorization header" do
        user, authority = local_user.call
        token = mint.call(user, authority, 5.minutes.ago)

        result = userinfo.call(HTTP::Headers{
          "Host" => "localhost", "Authorization" => "Bearer #{token}",
        })

        result.status_code.should eq 200
        JSON.parse(result.body)["sub"].as_s.should eq user.id.as(String)
      ensure
        user.try &.destroy
      end

      it "authenticates a token on the bearer_token query parameter" do
        user, authority = local_user.call
        token = mint.call(user, authority, 5.minutes.ago)

        result = client.get("/auth/userinfo?bearer_token=#{URI.encode_www_form(token)}",
          headers: HTTP::Headers{"Host" => "localhost"})

        result.status_code.should eq 200
        JSON.parse(result.body)["sub"].as_s.should eq user.id.as(String)
      ensure
        user.try &.destroy
      end

      it "authenticates a token in the bearer_token cookie" do
        user, authority = local_user.call
        token = mint.call(user, authority, 5.minutes.ago)

        result = userinfo.call(HTTP::Headers{
          "Host" => "localhost", "Cookie" => "bearer_token=#{token}",
        })

        result.status_code.should eq 200
        JSON.parse(result.body)["sub"].as_s.should eq user.id.as(String)
      ensure
        user.try &.destroy
      end

      it "accepts the `Token ` prefix as well as `Bearer `" do
        # `acquire_token` chops both. The legacy service accepted both, and
        # some integrations still send `Token`.
        user, authority = local_user.call
        token = mint.call(user, authority, 5.minutes.ago)

        result = userinfo.call(HTTP::Headers{
          "Host" => "localhost", "Authorization" => "Token #{token}",
        })

        result.status_code.should eq 200
        JSON.parse(result.body)["sub"].as_s.should eq user.id.as(String)
      ensure
        user.try &.destroy
      end

      it "prefers the Authorization header over the bearer_token cookie" do
        # A browser that still holds a stale `bearer_token` cookie must not
        # override the token the caller explicitly presented.
        header_user, authority = local_user.call
        cookie_user, _ = local_user.call
        header_token = mint.call(header_user, authority, 5.minutes.ago)
        cookie_token = mint.call(cookie_user, authority, 5.minutes.ago)

        result = userinfo.call(HTTP::Headers{
          "Host"          => "localhost",
          "Authorization" => "Bearer #{header_token}",
          "Cookie"        => "bearer_token=#{cookie_token}",
        })

        result.status_code.should eq 200
        subject = JSON.parse(result.body)["sub"].as_s
        subject.should eq header_user.id.as(String)
        subject.should_not eq cookie_user.id.as(String)
      ensure
        header_user.try &.destroy
        cookie_user.try &.destroy
      end
    end

    # ---- AZ-05: server-side logout invalidates existing tokens ----------

    describe "logout invalidates already-issued tokens (AZ-05)" do
      # Logout stamps `user.logged_out_at`, and `authorize!` refuses any JWT
      # issued at or before that stamp. `sessions_spec.cr` proves the stamp
      # is written; nothing proved it was ever *read*, which is the half
      # that makes logout mean anything for a token already in the wild.
      it "rejects a bearer token issued before the user logged out" do
        user, authority = local_user.call
        token = mint.call(user, authority, 5.minutes.ago)

        # Control first: the token works right up until the logout.
        before = userinfo.call(HTTP::Headers{
          "Host" => "localhost", "Authorization" => "Bearer #{token}",
        })
        before.status_code.should eq 200

        user.logged_out_at = Time.utc
        user.save!

        after = userinfo.call(HTTP::Headers{
          "Host" => "localhost", "Authorization" => "Bearer #{token}",
        })
        after.status_code.should eq 401
        JSON.parse(after.body)["error"].as_s.should eq "logged out"
      ensure
        user.try &.destroy
      end

      it "accepts a token issued after the logout" do
        # The other side of the same guard: logging out must not lock the
        # account out of its next login. `logged_out_at` is stored through
        # `Time::EpochConverterOptional` (whole seconds), so the fresh token
        # is issued a minute later rather than in the same second — a
        # same-second `iat` compares as *earlier* and would flake (this is
        # the `login_events_spec` trap).
        user, authority = local_user.call
        user.logged_out_at = 1.minute.ago
        user.save!

        token = mint.call(user, authority, Time.utc)
        result = userinfo.call(HTTP::Headers{
          "Host" => "localhost", "Authorization" => "Bearer #{token}",
        })

        result.status_code.should eq 200
        JSON.parse(result.body)["sub"].as_s.should eq user.id.as(String)
      ensure
        user.try &.destroy
      end
    end

    # ---- AZ-06 / MT-02: authority isolation -----------------------------

    describe "tokens do not cross authorities (AZ-06, MT-02)" do
      # `ensure_matching_domain` compares the token's `domain` claim against
      # the authority resolved from the request's Host. It is the only thing
      # standing between eight tenants on one deployment: without it a token
      # minted on one authority authenticates on every other. Every spec
      # helper seeds `localhost`, so this was never exercised in either
      # direction.
      other_authority = -> {
        authority = ::PlaceOS::Model::Generator.authority
        authority.domain = "tenant-#{Random.rand(999_999)}.example"
        authority.save!
        user = ::PlaceOS::Model::Generator.user(authority)
        user.save!
        {user, authority}
      }

      it "rejects a foreign authority's token at localhost" do
        user, authority = other_authority.call
        token = mint.call(user, authority, 5.minutes.ago)

        result = userinfo.call(HTTP::Headers{
          "Host" => "localhost", "Authorization" => "Bearer #{token}",
        })

        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "authority domain does not match token's"
      ensure
        user.try &.destroy
        authority.try &.destroy
      end

      it "accepts that same token at its own authority" do
        # The control that makes the rejection above meaningful: the token
        # is valid, it is simply being presented to the wrong tenant.
        user, authority = other_authority.call
        token = mint.call(user, authority, 5.minutes.ago)

        result = userinfo.call(HTTP::Headers{
          "Host" => authority.domain, "Authorization" => "Bearer #{token}",
        })

        result.status_code.should eq 200
        JSON.parse(result.body)["sub"].as_s.should eq user.id.as(String)
      ensure
        user.try &.destroy
        authority.try &.destroy
      end

      it "rejects a localhost token at a foreign authority" do
        local, local_authority = local_user.call
        _, foreign_authority = other_authority.call
        token = mint.call(local, local_authority, 5.minutes.ago)

        result = userinfo.call(HTTP::Headers{
          "Host" => foreign_authority.domain, "Authorization" => "Bearer #{token}",
        })

        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "authority domain does not match token's"
      ensure
        local.try &.destroy
        foreign_authority.try &.destroy
      end

      it "rejects a token presented at a Host with no authority at all" do
        # An unrecognised Host must fail closed. `current_authority` returns
        # nil and `ensure_matching_domain` raises before any comparison —
        # a `nil == nil` style match here would authenticate everything.
        user, authority = local_user.call
        token = mint.call(user, authority, 5.minutes.ago)

        result = userinfo.call(HTTP::Headers{
          "Host" => "nowhere-#{Random.rand(999_999)}.example", "Authorization" => "Bearer #{token}",
        })

        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "authority not found"
      ensure
        user.try &.destroy
      end

      it "rejects a foreign authority's API key at localhost" do
        # The same isolation boundary on the other credential type — the
        # key path calls `ensure_matching_domain` with the JWT it just
        # built, so the tenant check must hold there too.
        user, authority = other_authority.call
        key = ::PlaceOS::Model::ApiKey.new(name: "cross-#{Random.rand(999_999)}")
        key.user = user
        plaintext = key.x_api_key.as(String)
        key.save!

        result = userinfo.call(HTTP::Headers{
          "Host" => "localhost", "X-API-Key" => plaintext,
        })

        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "authority domain does not match token's"
      ensure
        key.try &.destroy
        user.try &.destroy
        authority.try &.destroy
      end
    end
  end
end
