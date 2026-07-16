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
        result.headers["Set-Cookie"]?.should_not be_nil
        result.headers["Set-Cookie"].not_nil!.should start_with PlaceOS::Auth::SESSION_COOKIE_NAME
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
