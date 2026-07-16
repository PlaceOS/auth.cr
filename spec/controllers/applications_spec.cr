require "../helper"

module PlaceOS::Auth
  # Parity for the Doorkeeper application-management routes (PPT-2536):
  # the admin-gated /auth/oauth/applications CRUD and the session-gated
  # /auth/oauth/authorized_applications endpoints.
  describe Applications, tags: "applications" do
    authority = uninitialized ::PlaceOS::Model::Authority

    admin_session = -> {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      password = "bcrypt-please-#{Random.rand(99999)}"
      user = ::PlaceOS::Model::Generator.user(authority)
      user.sys_admin = true
      user.password = password
      user.save!
      cookie = Spec.signin!(client, user, password)
      {user, HTTP::Headers{"Host" => "localhost", "Cookie" => cookie}}
    }

    plain_session = -> {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      password = "bcrypt-please-#{Random.rand(99999)}"
      user = ::PlaceOS::Model::Generator.user(authority)
      user.sys_admin = false
      user.password = password
      user.save!
      cookie = Spec.signin!(client, user, password)
      {user, HTTP::Headers{"Host" => "localhost", "Cookie" => cookie}}
    }

    make_app = ->(owner : ::PlaceOS::Model::User) {
      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "app-#{Random.rand(99999)}"
      app.redirect_uri = "https://app.example/cb/#{UUID.random}"
      app.scopes = "public"
      app.owner_id = owner.id.as(String)
      app.save!
      app
    }

    describe "admin gate" do
      it "hides the collection from a non-admin (404)" do
        _, headers = plain_session.call
        client.get("/auth/oauth/applications", headers: headers).status_code.should eq 404
      end

      it "hides the collection from an anonymous caller (404)" do
        client.get("/auth/oauth/applications",
          headers: HTTP::Headers{"Host" => "localhost"}).status_code.should eq 404
      end
    end

    describe "GET /auth/oauth/applications" do
      it "returns 204 with an empty body for an admin (Doorkeeper JSON parity)" do
        _, headers = admin_session.call
        result = client.get("/auth/oauth/applications", headers: headers)
        result.status_code.should eq 204
        result.body.empty?.should be_true
      end
    end

    describe "POST /auth/oauth/applications" do
      it "creates an application and returns the full record" do
        user, headers = admin_session.call
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        redirect = "https://created.example/cb/#{UUID.random}"
        body = URI::Params.build do |f|
          f.add "doorkeeper_application[name]", "created-app"
          f.add "doorkeeper_application[redirect_uri]", redirect
          f.add "doorkeeper_application[scopes]", "public"
        end

        result = client.post("/auth/oauth/applications", headers: headers, body: body)
        result.status_code.should eq 200
        record = JSON.parse(result.body)
        record["name"].as_s.should eq "created-app"
        record["redirect_uri"].as_s.should eq redirect
        record["uid"].as_s.should_not be_empty
        record["secret"].as_s.should_not be_empty
      ensure
        user.try &.destroy
      end

      it "returns 422 with an errors array on invalid input" do
        _, headers = admin_session.call
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = URI::Params.build do |f|
          f.add "doorkeeper_application[name]", "no-redirect"
          f.add "doorkeeper_application[redirect_uri]", ""
        end

        result = client.post("/auth/oauth/applications", headers: headers, body: body)
        result.status_code.should eq 422
        JSON.parse(result.body)["errors"].as_a.should_not be_empty
      end
    end

    describe "GET /auth/oauth/applications/:id" do
      it "returns the full record for an admin" do
        user, headers = admin_session.call
        app = make_app.call(user)

        result = client.get("/auth/oauth/applications/#{app.id}", headers: headers)
        result.status_code.should eq 200
        record = JSON.parse(result.body)
        record["id"].as_i64.should eq app.id
        record["uid"].as_s.should eq app.uid.as(String)
        record["secret"].as_s.should eq app.secret
      ensure
        user.try &.destroy
      end

      it "returns 404 for an unknown id" do
        _, headers = admin_session.call
        client.get("/auth/oauth/applications/999999999", headers: headers).status_code.should eq 404
      end
    end

    describe "PATCH /auth/oauth/applications/:id" do
      it "updates the record" do
        user, headers = admin_session.call
        app = make_app.call(user)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = URI::Params.build { |f| f.add "doorkeeper_application[name]", "renamed" }

        result = client.patch("/auth/oauth/applications/#{app.id}", headers: headers, body: body)
        result.status_code.should eq 200
        JSON.parse(result.body)["name"].as_s.should eq "renamed"
      ensure
        user.try &.destroy
      end
    end

    describe "DELETE /auth/oauth/applications/:id" do
      it "deletes the record and returns 204" do
        user, headers = admin_session.call
        app = make_app.call(user)

        result = client.delete("/auth/oauth/applications/#{app.id}", headers: headers)
        result.status_code.should eq 204
        ::PlaceOS::Model::DoorkeeperApplication.find?(app.id.as(Int64)).should be_nil
      ensure
        user.try &.destroy
      end
    end

    describe "GET /auth/oauth/authorized_applications" do
      it "requires a session (401)" do
        client.get("/auth/oauth/authorized_applications",
          headers: HTTP::Headers{"Host" => "localhost"}).status_code.should eq 401
      end

      it "lists apps the user holds a live token for" do
        user, headers = plain_session.call
        app = make_app.call(user)
        # mint a token for this user + app so it counts as authorized
        ::PlaceOS::Model::OAuthToken.new.tap do |t|
          t.jti = UUID.random.to_s
          t.client_id = app.uid
          t.sub = user.id
          t.scope = "public"
          t.issued_at = Time.utc.to_unix
          t.expires_at = Time.utc.to_unix + 3600
          t.save!
        end

        result = client.get("/auth/oauth/authorized_applications", headers: headers)
        result.status_code.should eq 200
        ids = JSON.parse(result.body).as_a.map(&.["id"].as_i64)
        ids.should contain app.id
      ensure
        user.try &.destroy
      end
    end

    describe "DELETE /auth/oauth/authorized_applications/:id" do
      it "revokes the user's tokens for that app" do
        user, headers = plain_session.call
        app = make_app.call(user)
        jti = UUID.random.to_s
        ::PlaceOS::Model::OAuthToken.new.tap do |t|
          t.jti = jti
          t.client_id = app.uid
          t.sub = user.id
          t.scope = "public"
          t.issued_at = Time.utc.to_unix
          t.expires_at = Time.utc.to_unix + 3600
          t.save!
        end

        result = client.delete("/auth/oauth/authorized_applications/#{app.id}", headers: headers)
        result.status_code.should eq 204
        ::PlaceOS::Model::OAuthToken.where(jti: jti).first.revoked?.should be_true
      ensure
        user.try &.destroy
      end
    end
  end
end
