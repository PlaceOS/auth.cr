require "../helper"
require "digest/sha256"
require "base64"

module PlaceOS::Auth
  # PKCE (RFC 7636) encoding compatibility. ts-client / Backoffice send the
  # S256 `code_challenge` as base64url (`-`/`_`), but authly validates it
  # against Crystal's standard-base64 `Digest::SHA256.base64digest`. Without
  # normalization every real browser PKCE login fails with
  # `unauthorized_client`. `OAuth#normalize_code_challenge` bridges this.
  describe OAuth, tags: "pkce" do
    make_app = ->(redirect : String) {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      user = ::PlaceOS::Model::Generator.user(authority)
      password = "bcrypt-please-#{Random.rand(99999)}"
      user.password = password
      user.save!
      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "pkce-test-#{Random.rand(99999)}"
      app.redirect_uri = redirect
      app.scopes = "public"
      app.owner_id = user.id.as(String)
      app.save!
      {user, app, password}
    }

    # Mirror ts-client `generateChallenge`: base64url(SHA256(verifier)) with
    # `+`->`-`, `/`->`_`, padding kept.
    ts_client_challenge = ->(verifier : String) {
      Base64.strict_encode(Digest::SHA256.digest(verifier)).tr("+/", "-_")
    }

    it "accepts a base64url S256 challenge (ts-client / browser style)" do
      user, app, password = make_app.call("https://spa.example/cb")
      cookie = Spec.signin!(client, user, password)
      verifier = "dBjftJeZ4CVPmB92K27uhbUJU1p1r-wW1gFWFOEjXk"
      challenge = ts_client_challenge.call(verifier)
      # sanity: the challenge really is url-safe (would break authly raw)
      challenge.should match(/[-_]/)

      authorize = client.get(
        "/auth/authorize?response_type=code" \
        "&client_id=#{URI.encode_www_form(app.uid.as(String))}" \
        "&redirect_uri=#{URI.encode_www_form("https://spa.example/cb")}" \
        "&scope=public&code_challenge=#{URI.encode_www_form(challenge)}" \
        "&code_challenge_method=S256",
        headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie},
      )
      authorize.status_code.should eq 302
      code = URI::Params.parse(authorize.headers["Location"].split('?', 2).last)["code"]

      body = URI::Params.build do |fp|
        fp.add("grant_type", "authorization_code")
        fp.add("client_id", app.uid.as(String))
        fp.add("client_secret", app.secret)
        fp.add("code", code)
        fp.add("redirect_uri", "https://spa.example/cb")
        fp.add("code_verifier", verifier)
      end
      token = client.post("/auth/token", headers: HTTP::Headers{
        "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
      }, body: body)

      token.status_code.should eq 200
      JSON.parse(token.body)["access_token"].as_s.should_not be_empty
    ensure
      app.try &.destroy
      user.try &.destroy
    end

    it "rejects a valid challenge presented with the wrong verifier" do
      user, app, password = make_app.call("https://spa.example/cb2")
      cookie = Spec.signin!(client, user, password)
      challenge = ts_client_challenge.call("the-real-verifier-aaaaaaaaaaaaaaaaaaaaaaaa")

      authorize = client.get(
        "/auth/authorize?response_type=code" \
        "&client_id=#{URI.encode_www_form(app.uid.as(String))}" \
        "&redirect_uri=#{URI.encode_www_form("https://spa.example/cb2")}" \
        "&scope=public&code_challenge=#{URI.encode_www_form(challenge)}" \
        "&code_challenge_method=S256",
        headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie},
      )
      code = URI::Params.parse(authorize.headers["Location"].split('?', 2).last)["code"]

      body = URI::Params.build do |fp|
        fp.add("grant_type", "authorization_code")
        fp.add("client_id", app.uid.as(String))
        fp.add("client_secret", app.secret)
        fp.add("code", code)
        fp.add("redirect_uri", "https://spa.example/cb2")
        fp.add("code_verifier", "a-different-verifier-bbbbbbbbbbbbbbbbbbbbbbbb")
      end
      token = client.post("/auth/token", headers: HTTP::Headers{
        "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
      }, body: body)

      token.status_code.should eq 401
    ensure
      app.try &.destroy
      user.try &.destroy
    end
  end
end
