require "../helper"

module PlaceOS::Auth
  # Parity for the authorization-endpoint verbs the legacy Doorkeeper
  # service exposed beyond the plain GET (PPT-2536): POST (consent
  # submit), DELETE (deny), and the native OOB code page.
  describe OAuth, tags: "authorize-flow" do
    # Returns {user, plaintext password, app}. The app's redirect_uri is
    # unique because DoorkeeperApplication.uid = MD5(redirect_uri) with a
    # global unique index.
    make_app = -> {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      password = "bcrypt-please-#{Random.rand(99999)}"
      user = ::PlaceOS::Model::Generator.user(authority).tap do |u|
        u.password = password
        u.save!
      end
      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "authz-test-#{Random.rand(99999)}"
      app.redirect_uri = "https://app.example/cb/#{UUID.random}"
      app.scopes = "public"
      app.owner_id = user.id.as(String)
      app.save!
      {user, password, app}
    }

    describe "POST /auth/oauth/authorize" do
      it "issues a grant to a signed-in user, like the GET path" do
        user, password, app = make_app.call
        cookie = Spec.signin!(client, user, password)
        headers = HTTP::Headers{"Host" => "localhost", "Cookie" => cookie, "Content-Type" => "application/x-www-form-urlencoded"}
        body = URI::Params.build do |f|
          f.add "response_type", "code"
          f.add "client_id", app.uid.as(String)
          f.add "redirect_uri", app.redirect_uri.as(String)
          f.add "scope", "public"
          f.add "state", "xyz"
        end

        result = client.post("/auth/oauth/authorize", headers: headers, body: body)
        result.status_code.should eq 302
        location = result.headers["Location"]
        location.should start_with app.redirect_uri.as(String)
        location.should contain "code="
        location.should contain "state=xyz"
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "bounces an unauthenticated caller to login" do
        _, _, app = make_app.call
        body = URI::Params.build do |f|
          f.add "response_type", "code"
          f.add "client_id", app.uid.as(String)
          f.add "redirect_uri", app.redirect_uri.as(String)
        end
        result = client.post("/auth/oauth/authorize",
          headers: HTTP::Headers{"Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded"},
          body: body)
        result.status_code.should eq 303
        result.headers["Location"].should eq "/auth/login"
      ensure
        app.try &.destroy
      end
    end

    describe "DELETE /auth/oauth/authorize" do
      it "redirects back to the client with error=access_denied" do
        user, password, app = make_app.call
        cookie = Spec.signin!(client, user, password)
        headers = HTTP::Headers{"Host" => "localhost", "Cookie" => cookie}
        query = "redirect_uri=#{URI.encode_www_form(app.redirect_uri.as(String))}" \
                "&client_id=#{URI.encode_www_form(app.uid.as(String))}&response_type=code&state=abc"

        result = client.delete("/auth/oauth/authorize?#{query}", headers: headers)
        result.status_code.should eq 302
        location = result.headers["Location"]
        location.should start_with app.redirect_uri.as(String)
        location.should contain "error=access_denied"
        location.should contain "state=abc"
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "refuses to redirect to a URI not registered for the client (no open redirect)" do
        user, password, app = make_app.call
        cookie = Spec.signin!(client, user, password)
        headers = HTTP::Headers{"Host" => "localhost", "Cookie" => cookie}
        query = "redirect_uri=#{URI.encode_www_form("https://evil.example/")}" \
                "&client_id=#{URI.encode_www_form(app.uid.as(String))}&response_type=code"

        result = client.delete("/auth/oauth/authorize?#{query}", headers: headers)
        result.status_code.should eq 400
        result.headers["Location"]?.should be_nil
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    describe "GET /auth/oauth/authorize/native" do
      it "shows the code to a signed-in user" do
        user, password, _ = make_app.call
        cookie = Spec.signin!(client, user, password)
        headers = HTTP::Headers{"Host" => "localhost", "Cookie" => cookie}
        result = client.get("/auth/oauth/authorize/native?code=ABC123", headers: headers)
        result.status_code.should eq 200
        result.headers["Content-Type"].should contain "text/html"
        result.body.should contain "ABC123"
        result.body.should contain "authorization_code"
      ensure
        user.try &.destroy
      end

      it "bounces an unauthenticated caller to login" do
        result = client.get("/auth/oauth/authorize/native?code=ABC123",
          headers: HTTP::Headers{"Host" => "localhost"})
        result.status_code.should eq 303
        result.headers["Location"].should eq "/auth/login"
      end
    end
  end
end
