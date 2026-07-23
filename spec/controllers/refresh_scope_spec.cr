require "../helper"
require "jwt"

module PlaceOS::Auth
  # Reproduction for the dev-server 403 (PPT-2536): a *refreshed* access token
  # was losing its `scope` entirely. authly's refresh grant derives scope from
  # the request (absent on a standard refresh) or the auth code (absent on a
  # refresh) and otherwise returns "" — so `ClaimsProvider` emitted
  # `scope: [] `. Downstream rest-api's `can_read` needs the `public` scope
  # present, so every API call with a refreshed token 403'd
  # (e.g. GET /api/engine/v2/oauth_apps).
  #
  # The fix must carry the originally-granted scope across refresh, matching
  # the Ruby Doorkeeper behaviour.
  describe OAuth, tags: "refresh-scope" do
    decode = ->(token : String) {
      payload, _ = JWT.decode(token, ::Authly.config.public_key.as(String), JWT::Algorithm::RS256)
      payload
    }

    scopes_of = ->(claims : JSON::Any) {
      # UserJWT emits scope as an array of scope strings.
      claims["scope"].as_a.map(&.as_s)
    }

    login = -> {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      user = ::PlaceOS::Model::Generator.user(authority).tap do |u|
        u.name = "Refresh Scope User"
        u.support = true
        u.sys_admin = true
        u.save!
      end
      password = "bcrypt-please-#{Random.rand(99999)}"
      user.password = password
      user.save!

      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "refresh-scope-#{Random.rand(99999)}"
      app.redirect_uri = "https://app.example/cb"
      app.scopes = "public"
      app.owner_id = user.id.as(String)
      app.save!

      cookie = Spec.signin!(client, user, password)
      authorize = client.get(
        "/auth/authorize?response_type=code" \
        "&client_id=#{URI.encode_www_form(app.uid.as(String))}" \
        "&redirect_uri=#{URI.encode_www_form("https://app.example/cb")}&scope=public",
        headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie},
      )
      code = URI::Params.parse(authorize.headers["Location"].split('?', 2).last)["code"]

      token = client.post("/auth/token", headers: HTTP::Headers{
        "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
      }, body: URI::Params.build { |fp|
        fp.add("grant_type", "authorization_code")
        fp.add("client_id", app.uid.as(String))
        fp.add("client_secret", app.secret)
        fp.add("code", code)
        fp.add("redirect_uri", "https://app.example/cb")
      })
      token.status_code.should eq 200
      body = JSON.parse(token.body)
      {user, app, body["access_token"].as_s, body["refresh_token"].as_s}
    }

    refresh = ->(app : ::PlaceOS::Model::DoorkeeperApplication, refresh_token : String) {
      result = client.post("/auth/token", headers: HTTP::Headers{
        "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
      }, body: URI::Params.build { |fp|
        fp.add("grant_type", "refresh_token")
        fp.add("client_id", app.uid.as(String))
        fp.add("client_secret", app.secret)
        fp.add("refresh_token", refresh_token)
      })
      result.status_code.should eq 200
      JSON.parse(result.body)
    }

    it "preserves scope across refresh (the 403 repro)" do
      user, app, access_token, refresh_token = login.call

      # sanity: the freshly-minted token carries the granted scope
      scopes_of.call(decode.call(access_token)).should eq ["public"]

      refreshed = refresh.call(app, refresh_token)
      claims = decode.call(refreshed["access_token"].as_s)

      # THE BUG: currently this is [] -> rest-api can_read fails -> 403
      scopes_of.call(claims).should eq ["public"]
    ensure
      app.try &.destroy
      user.try &.destroy
    end

    it "preserves scope across refresh-of-refresh" do
      user, app, _at, refresh_token = login.call
      first = refresh.call(app, refresh_token)
      second = refresh.call(app, first["refresh_token"].as_s)
      scopes_of.call(decode.call(second["access_token"].as_s)).should eq ["public"]
    ensure
      app.try &.destroy
      user.try &.destroy
    end
  end
end
