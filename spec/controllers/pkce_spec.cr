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

    # --- PKCE downgrade (RFC 7636 §4.6) --------------------------------
    #
    # `AuthorizationCode#verify_challenge!` opens with `return if
    # verifier.empty?`, so omitting `code_verifier` entirely skips the
    # check — the challenge baked into the code is simply never compared.
    # `Authly.config.enforce_pkce` does not help: it is only consulted by
    # the *authorize* handler, to decide whether a challenge must be
    # supplied when the code is minted. Nothing enforces it at redemption.
    #
    # RFC 7636 §4.6: "If the values are not equal, an error response
    # indicating 'invalid_grant' MUST be returned" — and §4.4 requires the
    # verifier to be sent whenever the authorization request carried a
    # challenge. A server that accepts the code without one lets an
    # attacker who has only stolen the code (redirect URI in a log, a
    # Referer header, a malicious app registered on the same custom
    # scheme) bypass PKCE by just leaving the parameter off, which defeats
    # the entire point of the exchange.
    it "refuses a code minted with a challenge when no verifier is presented" do
      user, app, password = make_app.call("https://spa.example/cb3")
      cookie = Spec.signin!(client, user, password)
      verifier = "downgrade-verifier-cccccccccccccccccccccccc"
      challenge = ts_client_challenge.call(verifier)

      authorize = client.get(
        "/auth/authorize?response_type=code" \
        "&client_id=#{URI.encode_www_form(app.uid.as(String))}" \
        "&redirect_uri=#{URI.encode_www_form("https://spa.example/cb3")}" \
        "&scope=public&code_challenge=#{URI.encode_www_form(challenge)}" \
        "&code_challenge_method=S256",
        headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie},
      )
      authorize.status_code.should eq 302
      code = URI::Params.parse(authorize.headers["Location"].split('?', 2).last)["code"]

      # The attacker's request: everything the real client would send
      # EXCEPT code_verifier.
      body = URI::Params.build do |fp|
        fp.add("grant_type", "authorization_code")
        fp.add("client_id", app.uid.as(String))
        fp.add("client_secret", app.secret)
        fp.add("code", code)
        fp.add("redirect_uri", "https://spa.example/cb3")
      end
      token = client.post("/auth/token", headers: HTTP::Headers{
        "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
      }, body: body)

      # Positive invariant: the response must be a refusal that carries no
      # token. Asserting only `!= 200` would pass on a 500.
      token.status_code.should be >= 400
      token.status_code.should be < 500
      parsed = JSON.parse(token.body)
      parsed["access_token"]?.should be_nil
      parsed["error"].as_s.should_not be_empty
    ensure
      app.try &.destroy
      user.try &.destroy
    end

    # The realistic form of the same attack. PlaceOS SPAs are PUBLIC
    # clients — ts-client's `createRefreshURL` sends no `client_secret` on
    # the authorization-code exchange — so an attacker who intercepts a
    # code needs nothing but the code itself and the (public) client_id.
    # PKCE is the only control standing between a stolen code and a token,
    # which is exactly why skipping it on an absent verifier matters.
    it "refuses a public-client exchange that omits both secret and verifier" do
      user, app, password = make_app.call("https://spa.example/cb4")
      cookie = Spec.signin!(client, user, password)
      challenge = ts_client_challenge.call("victim-verifier-dddddddddddddddddddddddd")

      authorize = client.get(
        "/auth/authorize?response_type=code" \
        "&client_id=#{URI.encode_www_form(app.uid.as(String))}" \
        "&redirect_uri=#{URI.encode_www_form("https://spa.example/cb4")}" \
        "&scope=public&code_challenge=#{URI.encode_www_form(challenge)}" \
        "&code_challenge_method=S256",
        headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie},
      )
      authorize.status_code.should eq 302
      code = URI::Params.parse(authorize.headers["Location"].split('?', 2).last)["code"]

      body = URI::Params.build do |fp|
        fp.add("grant_type", "authorization_code")
        fp.add("client_id", app.uid.as(String))
        fp.add("code", code)
        fp.add("redirect_uri", "https://spa.example/cb4")
      end
      token = client.post("/auth/token", headers: HTTP::Headers{
        "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
      }, body: body)

      token.status_code.should be >= 400
      token.status_code.should be < 500
      parsed = JSON.parse(token.body)
      parsed["access_token"]?.should be_nil
      parsed["error"].as_s.should_not be_empty
    ensure
      app.try &.destroy
      user.try &.destroy
    end

    # Adjacent defect in the same method. `/auth/authorize` stores
    # `code_challenge_method || ""` (oauth.cr), so a client that sends a
    # `code_challenge` WITHOUT a method mints a code carrying method "".
    # Redeeming it reaches `CodeChallengeBuilder.build(challenge, "")`,
    # which raises `ArgumentError` — not an `Authly::Error`, so it sails
    # past the controller's typed rescues and 500s the token endpoint.
    #
    # RFC 7636 §4.3 makes "plain" the default when the method is omitted,
    # so this input is legal, not hostile. Either way the token endpoint
    # must never 5xx (SEC-01).
    it "does not 500 when the code carries a challenge but no method" do
      user, app, password = make_app.call("https://spa.example/cb5")
      cookie = Spec.signin!(client, user, password)
      verifier = "plain-default-verifier-eeeeeeeeeeeeeeeeeeee"

      # No code_challenge_method -> RFC default "plain" -> challenge IS the
      # verifier verbatim.
      authorize = client.get(
        "/auth/authorize?response_type=code" \
        "&client_id=#{URI.encode_www_form(app.uid.as(String))}" \
        "&redirect_uri=#{URI.encode_www_form("https://spa.example/cb5")}" \
        "&scope=public&code_challenge=#{URI.encode_www_form(verifier)}",
        headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie},
      )
      authorize.status_code.should eq 302
      code = URI::Params.parse(authorize.headers["Location"].split('?', 2).last)["code"]

      body = URI::Params.build do |fp|
        fp.add("grant_type", "authorization_code")
        fp.add("client_id", app.uid.as(String))
        fp.add("client_secret", app.secret)
        fp.add("code", code)
        fp.add("redirect_uri", "https://spa.example/cb5")
        fp.add("code_verifier", verifier)
      end
      token = client.post("/auth/token", headers: HTTP::Headers{
        "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
      }, body: body)

      # The invariant that matters: never a 5xx.
      token.status_code.should be < 500
      # And since "plain" is the RFC default and the verifier matches the
      # challenge verbatim, this is a legitimate exchange -> it should work.
      token.status_code.should eq 200
      JSON.parse(token.body)["access_token"].as_s.should_not be_empty
    ensure
      app.try &.destroy
      user.try &.destroy
    end
  end
end
