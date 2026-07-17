require "../helper"

module PlaceOS::Auth
  # The legacy Ruby service mounts its OAuth server endpoints under the
  # Doorkeeper prefix `/auth/oauth/*` (token, authorize, revoke,
  # userinfo). `auth.cr` serves them at `/auth/*`. To stay a drop-in for
  # server-to-server and native clients that hardcode the documented
  # Doorkeeper paths (see auth/README.md, auth/docs/sample_auth.md), we
  # also serve the `/auth/oauth/*` aliases.
  describe OAuth, tags: "oauth-alias" do
    new_application = ->(redirect : String, scopes : String) {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      user = ::PlaceOS::Model::Generator.user(authority).tap do |u|
        u.password = "ignored-#{Random.rand(99999)}"
        u.save!
      end
      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "oauth-alias-#{Random.rand(99999)}"
      app.redirect_uri = redirect
      app.scopes = scopes
      app.owner_id = user.id.as(String)
      app.confidential = true
      app.save!
      {user, app}
    }

    form_post = ->(path : String, params : Hash(String, String)) {
      headers = HTTP::Headers{
        "Host"         => "localhost",
        "Content-Type" => "application/x-www-form-urlencoded",
      }
      body = URI::Params.build do |fp|
        params.each { |k, v| fp.add(k, v) }
      end
      client.post(path, headers: headers, body: body)
    }

    it "serves POST /auth/oauth/token (client_credentials)" do
      user, app = new_application.call("https://app.example/cb", "public")
      result = form_post.call("/auth/oauth/token", {
        "grant_type"    => "client_credentials",
        "client_id"     => app.uid.as(String),
        "client_secret" => app.secret,
        "scope"         => "public",
      })
      result.status_code.should eq 200
      JSON.parse(result.body)["access_token"].as_s.should_not be_empty
    ensure
      app.try &.destroy
      user.try &.destroy
    end

    it "serves POST /auth/oauth/revoke" do
      user, app = new_application.call("https://app.example/cb", "public")
      token_result = form_post.call("/auth/oauth/token", {
        "grant_type"    => "client_credentials",
        "client_id"     => app.uid.as(String),
        "client_secret" => app.secret,
        "scope"         => "public",
      })
      access_token = JSON.parse(token_result.body)["access_token"].as_s

      revoke_result = form_post.call("/auth/oauth/revoke", {"token" => access_token})
      revoke_result.status_code.should eq 200
      ::Authly.valid?(access_token).should be_false
    ensure
      app.try &.destroy
      user.try &.destroy
    end

    it "serves GET /auth/oauth/userinfo" do
      _, headers = Spec::Authentication.authentication
      headers["Host"] = "localhost"
      result = client.get("/auth/oauth/userinfo", headers: headers)
      result.status_code.should eq 200
      JSON.parse(result.body)["sub"].as_s.should_not be_empty
    end

    it "serves GET /auth/oauth/authorize (redirects unauthenticated callers)" do
      result = client.get(
        "/auth/oauth/authorize?response_type=code&client_id=x&redirect_uri=https%3A%2F%2Fa%2Fcb",
        headers: HTTP::Headers{"Host" => "localhost"},
      )
      result.status_code.should eq 303
      result.headers["Location"].should eq "/auth/login"
    end
  end
end
