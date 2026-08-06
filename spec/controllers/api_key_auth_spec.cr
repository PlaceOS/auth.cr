require "../helper"

module PlaceOS::Auth
  # `X-API-Key` authentication — PPT-2536 test-matrix rows AK-02 and AK-04.
  #
  # `authorize!` accepts a key from three places (header, query param,
  # cookie) and prefers it over a Bearer JWT. Only the header variant was
  # asserted anywhere (`authorities_spec.cr`), yet the query and cookie
  # sources are the ones that reach a browser: a cookie is replayed
  # automatically on every request for as long as it lives, and a query
  # param lands in nginx's access log and the browser's history.
  #
  # `/auth/userinfo` is the probe throughout. It is the one route that calls
  # `authorize!` unconditionally, and it answers with the resolved `sub`, so
  # a 200 proves the key authenticated *as the right user* rather than
  # merely being waved through.
  describe Utils::CurrentUser, tags: "api-key" do
    userinfo = ->(headers : HTTP::Headers) {
      client.get("/auth/userinfo", headers: headers)
    }

    # Builds a saved key for a fresh user on the `localhost` authority — the
    # domain `ensure_matching_domain` compares the minted JWT against — and
    # returns the plaintext `<id>.<secret>`, which is readable only before
    # the record is persisted (`before_create :hash!` replaces the secret
    # with its HMAC).
    make_key = ->(expires_at : Time?) {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      user = ::PlaceOS::Model::Generator.user(authority)
      user.save!

      key = ::PlaceOS::Model::ApiKey.new(name: "ak-#{Random.rand(999_999)}")
      key.user = user
      plaintext = key.x_api_key.as(String)
      key.save!

      if expiry = expires_at
        # The model validates `expires_at` as "must be in the future", so an
        # expired key cannot be *created* through it — only reached by an
        # existing key outliving its TTL. Write the column directly to land
        # on that state.
        ::PgORM::Database.connection do |db|
          db.exec("UPDATE api_key SET expires_at = $1 WHERE id = $2",
            args: [expiry, key.id.as(String)] of ::DB::Any)
        end
      end

      {user, key, plaintext}
    }

    # ---- AK-02: every accepted key source -------------------------------

    describe "key sources (AK-02)" do
      it "authenticates a key presented in the X-API-Key header" do
        user, key, plaintext = make_key.call(nil)

        result = userinfo.call(HTTP::Headers{
          "Host" => "localhost", "X-API-Key" => plaintext,
        })

        result.status_code.should eq 200
        JSON.parse(result.body)["sub"].as_s.should eq user.id.as(String)
      ensure
        key.try &.destroy
        user.try &.destroy
      end

      it "authenticates a key presented as the api-key query parameter" do
        user, key, plaintext = make_key.call(nil)

        result = client.get(
          "/auth/userinfo?api-key=#{URI.encode_www_form(plaintext)}",
          headers: HTTP::Headers{"Host" => "localhost"})

        result.status_code.should eq 200
        JSON.parse(result.body)["sub"].as_s.should eq user.id.as(String)
      ensure
        key.try &.destroy
        user.try &.destroy
      end

      it "authenticates a key presented as the api-key cookie" do
        user, key, plaintext = make_key.call(nil)

        result = userinfo.call(HTTP::Headers{
          "Host" => "localhost", "Cookie" => "api-key=#{plaintext}",
        })

        result.status_code.should eq 200
        JSON.parse(result.body)["sub"].as_s.should eq user.id.as(String)
      ensure
        key.try &.destroy
        user.try &.destroy
      end

      it "prefers the API key over a Bearer JWT for a different user" do
        # `authorize!` checks `extract_api_key` before `acquire_token`, so a
        # request carrying both credentials resolves to the key's owner. Pin
        # it: the precedence decides whose permissions a mixed request runs
        # with, and both PlaceOS clients and scanners send both.
        user, key, plaintext = make_key.call(nil)
        other, headers = Spec::Authentication.authentication
        headers["Host"] = "localhost"
        headers["X-API-Key"] = plaintext

        result = userinfo.call(headers)

        result.status_code.should eq 200
        subject = JSON.parse(result.body)["sub"].as_s
        subject.should eq user.id.as(String)
        subject.should_not eq other.id.as(String)
      ensure
        key.try &.destroy
        user.try &.destroy
      end
    end

    # ---- AK-04: rejected keys -------------------------------------------

    describe "rejected keys (AK-04)" do
      it "rejects a key that has passed its expiry with 401" do
        user, key, plaintext = make_key.call(1.hour.ago)

        result = userinfo.call(HTTP::Headers{
          "Host" => "localhost", "X-API-Key" => plaintext,
        })

        result.status_code.should eq 401
        # Name the reason, not just the status: `find_key!` raising
        # RecordNotFound also yields 401, so a status-only assertion would
        # pass even if the expiry check were deleted and the fixture broke.
        JSON.parse(result.body)["error"].as_s.should eq "API key has expired"
      ensure
        key.try &.destroy
        user.try &.destroy
      end

      it "accepts the same key while its expiry is still in the future" do
        # Control for the case above — proves the 401 is the expiry and not
        # something wrong with a key that carries `expires_at` at all.
        user, key, plaintext = make_key.call(1.hour.from_now)

        result = userinfo.call(HTTP::Headers{
          "Host" => "localhost", "X-API-Key" => plaintext,
        })

        result.status_code.should eq 200
        JSON.parse(result.body)["sub"].as_s.should eq user.id.as(String)
      ensure
        key.try &.destroy
        user.try &.destroy
      end

      it "rejects an expired key presented as a cookie" do
        # The cookie is the source a browser replays unprompted, long after
        # anyone thought the credential had lapsed.
        user, key, plaintext = make_key.call(1.hour.ago)

        result = userinfo.call(HTTP::Headers{
          "Host" => "localhost", "Cookie" => "api-key=#{plaintext}",
        })

        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "API key has expired"
      ensure
        key.try &.destroy
        user.try &.destroy
      end

      it "rejects an unknown key with 401" do
        result = userinfo.call(HTTP::Headers{
          "Host"      => "localhost",
          "X-API-Key" => "#{Random::Secure.hex(16)}.#{Random::Secure.urlsafe_base64(32)}",
        })

        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "unknown X-API-Key"
      end

      it "rejects a real key id carrying the wrong secret with 401" do
        # `find_key!` splits on the first `.` and compares the HMAC of the
        # supplied half — knowing a key's id must not be enough.
        user, key, plaintext = make_key.call(nil)
        id = plaintext.split('.', 2).first

        result = userinfo.call(HTTP::Headers{
          "Host" => "localhost", "X-API-Key" => "#{id}.#{Random::Secure.urlsafe_base64(32)}",
        })

        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "unknown X-API-Key"
      ensure
        key.try &.destroy
        user.try &.destroy
      end

      it "rejects a malformed key with 401 rather than 500" do
        # No `.` at all: `token.split('.', 2)` yields a single element and
        # the destructuring raises IndexError, which must land on the same
        # 401 as any other bad credential.
        result = userinfo.call(HTTP::Headers{
          "Host" => "localhost", "X-API-Key" => "no-separator-here",
        })

        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "unknown X-API-Key"
      end
    end
  end
end
