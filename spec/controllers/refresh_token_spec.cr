require "../helper"
require "jwt"

module PlaceOS::Auth
  # Refreshing an access token must preserve the resource owner. Upstream
  # authly loses it (refresh tokens carry no user id → refreshed `sub` is
  # random), which also strips the `u{}` + `aud` claims our ClaimsProvider
  # attaches. The authly_adapter patches embed the user id into the refresh
  # token and recover it on redeem; this locks that in (PPT-2536).
  describe OAuth, tags: "refresh" do
    decode = ->(token : String) {
      payload, _ = JWT.decode(token, ::Authly.config.public_key.as(String), JWT::Algorithm::RS256)
      payload
    }

    # Full code flow → {user, access_token, refresh_token}.
    login = -> {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      user = ::PlaceOS::Model::Generator.user(authority).tap do |u|
        u.name = "Refresh Parity User"
        u.support = true
        u.sys_admin = true
        u.save!
      end
      password = "bcrypt-please-#{Random.rand(99999)}"
      user.password = password
      user.save!

      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "refresh-test-#{Random.rand(99999)}"
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

    it "keeps the same sub, and the u{}/aud claims, across refresh" do
      user, app, access_token, refresh_token = login.call
      original = decode.call(access_token)
      original["sub"].as_s.should eq user.id.as(String)

      refreshed = refresh.call(app, refresh_token)
      claims = decode.call(refreshed["access_token"].as_s)

      # the whole point: the refreshed sub is the real user, not random hex
      claims["sub"].as_s.should eq user.id.as(String)
      claims["aud"].as_s.should eq "localhost"
      claims["u"]["e"].as_s.should eq user.email.to_s.downcase
      # p = permission bitflags: support (1) + sys_admin (2) => 3
      claims["u"]["p"].as_i.should eq 3
    ensure
      app.try &.destroy
      user.try &.destroy
    end

    it "preserves the user across refresh-of-refresh (identity chains)" do
      user, app, _at, refresh_token = login.call
      first = refresh.call(app, refresh_token)
      second = refresh.call(app, first["refresh_token"].as_s)
      decode.call(second["access_token"].as_s)["sub"].as_s.should eq user.id.as(String)
    ensure
      app.try &.destroy
      user.try &.destroy
    end
  end
end
