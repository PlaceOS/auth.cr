require "../helper"

module PlaceOS::Auth
  describe Sessions do
    # Helper: seeds a fresh user on the `localhost` authority with a
    # known password.
    create_user = ->(password : String) {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      user = ::PlaceOS::Model::Generator.user(authority)
      user.password = password
      user.save!
      user
    }

    describe "POST /auth/signin" do
      it "returns 202 + Set-Cookie on the happy path" do
        password = "ok-password-1234"
        user = create_user.call(password)

        body = {email: user.email.to_s, password: password}.to_json
        headers = HTTP::Headers{
          "Host"         => "localhost",
          "Content-Type" => "application/json",
        }
        result = client.post("/auth/signin", headers: headers, body: body)
        result.status_code.should eq 202
        result.cookies[PlaceOS::Auth::SESSION_COOKIE_NAME]?.should_not be_nil
      ensure
        user.try &.destroy
      end

      it "accepts an application/x-www-form-urlencoded body (browser login form)", tags: "signin-form" do
        password = "ok-password-1234"
        user = create_user.call(password)

        body = URI::Params.build do |fp|
          fp.add("email", user.email.to_s)
          fp.add("password", password)
        end
        headers = HTTP::Headers{
          "Host"         => "localhost",
          "Content-Type" => "application/x-www-form-urlencoded",
        }
        result = client.post("/auth/signin", headers: headers, body: body)
        result.status_code.should eq 202
        result.headers["Set-Cookie"]?.should_not be_nil
      ensure
        user.try &.destroy
      end

      it "issues _coauth_session as SameSite=None; Secure (embedded/cross-site login parity)" do
        password = "ok-password-1234"
        user = create_user.call(password)

        body = {email: user.email.to_s, password: password}.to_json
        result = client.post("/auth/signin", headers: HTTP::Headers{
          "Host"         => "localhost",
          "Content-Type" => "application/json",
        }, body: body)
        result.status_code.should eq 202

        # A SameSite=Lax / non-Secure session cookie is silently dropped by the
        # browser in an embedded (third-party) context, so local login fails
        # there while the SameSite=None `verified` cookie survives. Match the
        # legacy Ruby `:user` cookie (same_site: :none) so embedded login works.
        session = result.cookies[PlaceOS::Auth::SESSION_COOKIE_NAME]?
        session.should_not be_nil
        session = session.not_nil!
        session.samesite.should eq HTTP::Cookie::SameSite::None
        session.secure.should be_true
        session.http_only.should be_true
        session.path.should eq PlaceOS::Auth::SESSION_COOKIE_PATH
      ensure
        user.try &.destroy
      end

      it "redirects to a safe `continue` target when supplied" do
        password = "ok-password-1234"
        user = create_user.call(password)

        body = {email: user.email.to_s, password: password, continue: "/dashboard"}.to_json
        headers = HTTP::Headers{
          "Host"         => "localhost",
          "Content-Type" => "application/json",
        }
        result = client.post("/auth/signin", headers: headers, body: body)
        result.status_code.should eq 303
        result.headers["Location"].should eq "/dashboard"
      ensure
        user.try &.destroy
      end

      it "401s on wrong password" do
        password = "ok-password-1234"
        user = create_user.call(password)

        body = {email: user.email.to_s, password: "nope"}.to_json
        headers = HTTP::Headers{
          "Host"         => "localhost",
          "Content-Type" => "application/json",
        }
        result = client.post("/auth/signin", headers: headers, body: body)
        result.status_code.should eq 401
      ensure
        user.try &.destroy
      end

      it "401s on unknown email" do
        body = {email: "missing@localhost", password: "anything"}.to_json
        headers = HTTP::Headers{
          "Host"         => "localhost",
          "Content-Type" => "application/json",
        }
        result = client.post("/auth/signin", headers: headers, body: body)
        result.status_code.should eq 401
      end

      it "401s for soft-deleted users even with the right password" do
        password = "ok-password-1234"
        user = create_user.call(password)
        user.deleted = true
        user.save!

        body = {email: user.email.to_s, password: password}.to_json
        headers = HTTP::Headers{
          "Host"         => "localhost",
          "Content-Type" => "application/json",
        }
        result = client.post("/auth/signin", headers: headers, body: body)
        result.status_code.should eq 401
      ensure
        user.try &.destroy
      end
    end

    # The nginx-validated `verified` asset-access cookie — nginx recomputes
    # HMAC-SHA256(SECRET_KEY_BASE, <data>) on every SPA asset request and
    # bounces the browser to /auth/login when it is missing or wrong, so a
    # login that doesn't set it produces an infinite redirect loop.
    describe "asset-access `verified` cookie" do
      it "is issued on signin, signed with SECRET_KEY_BASE, at path / SameSite=None" do
        password = "ok-password-1234"
        user = create_user.call(password)

        body = {email: user.email.to_s, password: password}.to_json
        result = client.post("/auth/signin", headers: HTTP::Headers{
          "Host"         => "localhost",
          "Content-Type" => "application/json",
        }, body: body)
        result.status_code.should eq 202

        verified = result.cookies["verified"]?
        verified.should_not be_nil
        verified = verified.not_nil!

        # value = "<16 hex>.<64 hex>"; recompute the HMAC exactly as nginx does
        verified.value.should match(/\A[0-9a-f]{16}\.[0-9a-f]{64}\z/)
        data, _, signature = verified.value.partition('.')
        expected = OpenSSL::HMAC.hexdigest(:sha256, PlaceOS::Auth::SECRET_KEY_BASE, data)
        signature.should eq expected

        verified.path.should eq "/"
        verified.secure.should be_true
        verified.http_only.should be_true
        verified.samesite.should eq HTTP::Cookie::SameSite::None
      ensure
        user.try &.destroy
      end

      it "is cleared on logout" do
        password = "ok-password-1234"
        user = create_user.call(password)
        cookie = Spec.signin!(client, user, password)

        result = client.get("/auth/logout", headers: HTTP::Headers{
          "Host"   => "localhost",
          "Cookie" => cookie,
        })

        verified = result.cookies["verified"]?
        verified.should_not be_nil
        verified = verified.not_nil!
        verified.value.should eq ""
        verified.expires.not_nil!.should be < Time.utc
        verified.path.should eq "/"
      ensure
        user.try &.destroy
      end
    end

    describe "GET /auth/logout" do
      # The legacy Ruby service redirects logout via `redirect_continue`,
      # which issues a 302 (Rails default) to `continue || "/"`, using the
      # authority's logout_url only as the cross-domain fallback.
      it "clears the session, stamps logged_out_at, and 302-redirects to /" do
        password = "ok-password-1234"
        user = create_user.call(password)
        cookie = Spec.signin!(client, user, password)

        before = Time.utc
        result = client.get("/auth/logout", headers: HTTP::Headers{
          "Host"   => "localhost",
          "Cookie" => cookie,
        })
        result.status_code.should eq 302
        result.headers["Location"].should eq "/"

        # The deletion cookie must carry the same cross-site attributes or the
        # browser won't match + clear it (same reasoning as the `verified` clear).
        cleared = result.cookies[PlaceOS::Auth::SESSION_COOKIE_NAME]?
        cleared.should_not be_nil
        cleared = cleared.not_nil!
        cleared.samesite.should eq HTTP::Cookie::SameSite::None
        cleared.secure.should be_true

        reloaded = ::PlaceOS::Model::User.find!(user.id.as(String))
        reloaded.logged_out_at.should_not be_nil
        reloaded.logged_out_at.not_nil!.should be >= before
      ensure
        user.try &.destroy
      end

      it "302-redirects to / even without a session" do
        result = client.get("/auth/logout", headers: HTTP::Headers{"Host" => "localhost"})
        result.status_code.should eq 302
        result.headers["Location"].should eq "/"
      end

      it "redirects to a safe same-site `continue` target" do
        result = client.get("/auth/logout?continue=%2Fbye", headers: HTTP::Headers{"Host" => "localhost"})
        result.status_code.should eq 302
        result.headers["Location"].should eq "/bye"
      end

      it "falls back to the authority logout_url for a cross-domain `continue`" do
        authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
        authority.logout_url = "/signed-out"
        authority.save!

        result = client.get(
          "/auth/logout?continue=https%3A%2F%2Fevil.example%2Fx",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        result.status_code.should eq 302
        result.headers["Location"].should eq "/signed-out"
      end
    end

    describe "GET /auth/login" do
      it "redirects to the authority's login_url with {{url}} substituted" do
        authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
        authority.login_url = "/login?continue={{url}}"
        authority.save!

        result = client.get(
          "/auth/login?continue=%2Fhome",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        result.status_code.should eq 303
        result.headers["Location"].should eq "/login?continue=/home"
      end

      it "redirects to /auth/:provider when provider+id supplied" do
        result = client.get(
          "/auth/login?provider=oauth2&id=strat-1&continue=%2Fhome",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        result.status_code.should eq 303
        result.headers["Location"].should eq "/auth/oauth2?id=strat-1"
      end

      it "400s when continue points at a non-html asset" do
        result = client.get(
          "/auth/login?continue=%2Fassets%2Fapp.js",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        result.status_code.should eq 400
      end
    end
  end
end
