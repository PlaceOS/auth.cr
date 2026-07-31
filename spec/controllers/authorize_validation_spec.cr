require "../helper"
require "jwt"

module PlaceOS::Auth
  # Authorization-endpoint request validation (PPT-2536 test-matrix rows
  # AU-02..AU-06, AU-11, AU-13).
  #
  # `/auth/authorize` is the only endpoint that turns a caller-supplied
  # string (`redirect_uri`) into a `Location` header, so every rejection
  # here has to be *non-redirectable*: a 4xx carrying the OAuth error
  # envelope and NO `Location` at all. A rejection that still emitted a
  # Location would be an open redirect with an authorization code attached.
  #
  # Two habits are deliberate throughout, both learned the hard way on this
  # project (see `dev-forensics.md` B.4 and the vacuous-SAML-spec fix in
  # `d5cfabb`):
  #
  #   * every case asserts the redirect TARGET, not just the status code —
  #     the `continue`-loss bug shipped for weeks behind `status == 303`;
  #   * every rejection table is paired with a *positive control* in the
  #     same example: the identical request with the one hostile field made
  #     valid must succeed. Without it a fixture that stopped minting codes
  #     at all (wrong client, dead session) would make the whole table pass
  #     while proving nothing.
  describe OAuth, tags: "authorize-validation" do
    localhost = -> { ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil! }

    # Returns a saved user plus its plaintext password, ready for signin.
    make_user = -> {
      password = "bcrypt-please-#{Random.rand(999_999)}"
      user = ::PlaceOS::Model::Generator.user(localhost.call).tap do |u|
        u.password = password
        u.save!
      end
      {user, password}
    }

    # Public (`confidential: false`) client — all 66 OAuth clients on the
    # dev server are public, so that is the shape worth regression-testing.
    # `redirect_uri` may hold several whitespace-separated URIs, Doorkeeper
    # style; `uid` is MD5 of the whole column, so distinct strings give
    # distinct client_ids.
    make_app = ->(redirect : String) {
      ::PlaceOS::Model::DoorkeeperApplication.new.tap do |app|
        app.name = "authorize-validation-#{Random.rand(999_999)}"
        app.redirect_uri = redirect
        app.scopes = "public"
        app.confidential = false
        app.owner_id = "authorize-validation-owner"
        app.save!
      end
    }

    # GET /auth/authorize with the params form-encoded for us, so a spec
    # never hand-rolls (and mis-escapes) the query string.
    authorize = ->(cookie : String, params : Hash(String, String)) {
      query = URI::Params.build do |fp|
        params.each { |k, v| fp.add(k, v) }
      end
      client.get("/auth/authorize?#{query}", headers: HTTP::Headers{
        "Host" => "localhost", "Cookie" => cookie,
      })
    }

    form_post = ->(path : String, params : Hash(String, String)) {
      body = URI::Params.build do |fp|
        params.each { |k, v| fp.add(k, v) }
      end
      client.post(path, headers: HTTP::Headers{
        "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
      }, body: body)
    }

    # The query half of a redirect Location, parsed.
    redirect_params = ->(location : String) {
      URI::Params.parse(location.split('?', 2).last)
    }

    # --- AU-02: response_type ------------------------------------------

    describe "response_type (AU-02)" do
      # ts-client and most OIDC SDKs can be configured to emit implicit or
      # hybrid response types; a misconfigured integration will send one.
      # auth.cr implements `code` only, and the discovery document
      # advertises `response_types_supported: ["code"]`. If any of these
      # were silently honoured the caller would receive a bearer token in a
      # URL fragment — the flow OAuth 2.1 removed and the project brief
      # dropped alongside the password grant.
      #
      # `oauth_spec.cr` "rejects an unknown response_type" already covers
      # `response_type=token`, but it sends `client_id=x`, which is not a
      # registered client — so its 400 is not attributable to the response
      # type. This case uses a fully valid, registered client and a control.
      it "refuses implicit and hybrid response types on an otherwise valid request" do
        user, password = make_user.call
        app = make_app.call("https://au02.example/cb-#{Random.rand(999_999)}")
        redirect = app.redirect_uri.as(String)
        cookie = Spec.signin!(client, user, password)

        # Control: the identical request with `response_type=code` mints a
        # code, so every rejection below is attributable to that one field.
        control = authorize.call(cookie, {
          "response_type" => "code",
          "client_id"     => app.uid.as(String),
          "redirect_uri"  => redirect,
          "scope"         => "public",
        })
        control.status_code.should eq 302
        control.headers["Location"].should start_with "#{redirect}?code="

        {
          "token",               # implicit
          "id_token",            # OIDC implicit
          "id_token token",      # OIDC implicit, both artifacts
          "code token",          # hybrid
          "code id_token",       # hybrid
          "code id_token token", # hybrid, everything
          "none",                # OIDC "no response"
          "CODE",                # case must not be normalised into `code`
        }.each do |response_type|
          result = authorize.call(cookie, {
            "response_type" => response_type,
            "client_id"     => app.uid.as(String),
            "redirect_uri"  => redirect,
            "scope"         => "public",
          })
          result.status_code.should eq 400
          JSON.parse(result.body)["error"].as_s.should eq "unsupported_response_type"
          # A rejection must not hand back anything the browser will follow.
          result.headers["Location"]?.should be_nil
        end
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # --- AU-03: unregistered redirect_uri ------------------------------

    describe "unregistered redirect_uri (AU-03)" do
      # `oauth_spec.cr` "rejects an unregistered redirect_uri" asserts the
      # 401 + error code but never looks at `Location`, and
      # `hostile_input_spec.cr`'s open-redirect case runs *unauthenticated*
      # — so it only ever observes the `/auth/login` bounce and would still
      # pass if the signed-in path leaked a code. This is the signed-in
      # case: a session exists, so a missing check really would mint a code
      # and post it to the attacker's URI.
      it "never issues a Location to an unregistered redirect_uri" do
        user, password = make_user.call
        redirect = "https://au03.example/cb-#{Random.rand(999_999)}"
        app = make_app.call(redirect)
        cookie = Spec.signin!(client, user, password)

        # Control: this session + client really does mint codes.
        control = authorize.call(cookie, {
          "response_type" => "code",
          "client_id"     => app.uid.as(String),
          "redirect_uri"  => redirect,
          "scope"         => "public",
        })
        control.status_code.should eq 302
        redirect_params.call(control.headers["Location"])["code"].should_not be_empty

        {
          "https://evil.example/steal",
          # the registered URI smuggled in as a query value
          "https://evil.example/steal?next=#{redirect}",
          # protocol-relative: a browser reads this as an absolute host
          "//evil.example/steal",
          "javascript:alert(1)",
          "data:text/html,<script>1</script>",
          # userinfo trick — host is evil.example, not au03.example
          "https://au03.example@evil.example/cb",
        }.each do |hostile|
          result = authorize.call(cookie, {
            "response_type" => "code",
            "client_id"     => app.uid.as(String),
            "redirect_uri"  => hostile,
            "scope"         => "public",
          })
          result.status_code.should eq 401
          JSON.parse(result.body)["error"].as_s.should eq "unauthorized_client"
          result.headers["Location"]?.should be_nil
        end
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      # An empty `redirect_uri` is a distinct branch upstream
      # (`ResponseType#decode` raises before the client is ever looked up),
      # so it reports `invalid_redirect_uri`/400 rather than
      # `unauthorized_client`/401. Pinned because scanners send it
      # constantly and the two branches are easy to accidentally merge.
      it "rejects an empty redirect_uri with a non-redirectable 400" do
        user, password = make_user.call
        app = make_app.call("https://au03b.example/cb-#{Random.rand(999_999)}")
        cookie = Spec.signin!(client, user, password)

        result = authorize.call(cookie, {
          "response_type" => "code",
          "client_id"     => app.uid.as(String),
          "redirect_uri"  => "",
          "scope"         => "public",
        })
        result.status_code.should eq 400
        JSON.parse(result.body)["error"].as_s.should eq "invalid_redirect_uri"
        result.headers["Location"]?.should be_nil
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # --- AU-04: exact-match redirect validation ------------------------

    describe "exact-match redirect_uri validation (AU-04)" do
      # `AuthlyAdapter::Client#valid_redirect?` is a literal string
      # membership test over the whitespace-split `redirect_uri` column —
      # there is no normalisation, no prefix match, no "same origin is good
      # enough". That is the correct (RFC 6749 §3.1.2 / OAuth 2.1) rule, and
      # these two examples exist so nobody "helpfully" relaxes it into a
      # `starts_with?` or a URI-parse comparison. Every one of these strings
      # is a registered-URI near-miss that a prefix or host-only comparison
      # would wave through.

      it "rejects scheme, host and port variations of the registered URI" do
        user, password = make_user.call
        suffix = Random.rand(999_999)
        redirect = "https://au04.example/cb-#{suffix}"
        app = make_app.call(redirect)
        client_id = app.uid.as(String)
        cookie = Spec.signin!(client, user, password)

        ask = ->(uri : String) {
          authorize.call(cookie, {
            "response_type" => "code",
            "client_id"     => client_id,
            "redirect_uri"  => uri,
            "scope"         => "public",
          })
        }

        # Control first: the exact registered string is accepted.
        control = ask.call(redirect)
        control.status_code.should eq 302
        control.headers["Location"].should start_with "#{redirect}?code="

        {
          "http://au04.example/cb-#{suffix}",  # scheme downgrade
          "HTTPS://au04.example/cb-#{suffix}", # scheme case
          "https://AU04.EXAMPLE/cb-#{suffix}", # host case
          "https://au04.example.evil.com/cb-#{suffix}",
          "https://evil.au04.example/cb-#{suffix}", # attacker subdomain
          "https://au04.example:443/cb-#{suffix}",  # default port made explicit
          "https://au04.example:8443/cb-#{suffix}", # port swap
          "https://au04.example./cb-#{suffix}",     # trailing-dot FQDN
        }.each do |uri|
          result = ask.call(uri)
          result.status_code.should eq 401
          JSON.parse(result.body)["error"].as_s.should eq "unauthorized_client"
          result.headers["Location"]?.should be_nil
        end
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "rejects path, query and fragment variations of the registered URI" do
        user, password = make_user.call
        suffix = Random.rand(999_999)
        redirect = "https://au04b.example/cb-#{suffix}"
        app = make_app.call(redirect)
        client_id = app.uid.as(String)
        cookie = Spec.signin!(client, user, password)

        ask = ->(uri : String) {
          authorize.call(cookie, {
            "response_type" => "code",
            "client_id"     => client_id,
            "redirect_uri"  => uri,
            "scope"         => "public",
          })
        }

        control = ask.call(redirect)
        control.status_code.should eq 302
        control.headers["Location"].should start_with "#{redirect}?code="

        {
          "#{redirect}?utm_source=x",             # extra query param
          "#{redirect}#fragment",                 # fragment appended
          "#{redirect}/",                         # trailing slash
          "#{redirect}/extra",                    # extra path segment
          "#{redirect}/../cb-#{suffix}",          # dot-segment round trip
          "https://au04b.example/cb%2D#{suffix}", # percent-encoded '-'
          "https://au04b.example//cb-#{suffix}",  # doubled slash
          " #{redirect}",                         # leading whitespace
        }.each do |uri|
          result = ask.call(uri)
          result.status_code.should eq 401
          JSON.parse(result.body)["error"].as_s.should eq "unauthorized_client"
          result.headers["Location"]?.should be_nil
        end
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # --- AU-05: real-world redirect shapes -----------------------------

    describe "non-https registered redirects (AU-05)" do
      # The dev `oauth_applications` table contains all three of these
      # shapes: a custom scheme (the Booking Panel native app), a
      # `http://localhost:<port>` loopback (local SPA development, RFC 8252
      # §7.3) and a bare LAN IP (kiosks/signage on the building network).
      # None of them are https, and only the first is a valid `URI` in the
      # hierarchical sense — so any future "validate the redirect looks
      # sensible" hardening would silently lock out real, shipping clients.
      # A single client may register several, whitespace-separated,
      # Doorkeeper style; each one has to be independently accepted.
      real_world_uris = [
        "com.placeos.booking.panel://oauth",
        "http://localhost:8080/oauth-resp.html",
        "http://192.168.1.50:8080/oauth-resp.html",
      ]

      it "mints a code for every URI in a multi-URI registration" do
        user, password = make_user.call
        app = make_app.call(real_world_uris.join(' '))
        cookie = Spec.signin!(client, user, password)

        real_world_uris.each do |uri|
          result = authorize.call(cookie, {
            "response_type" => "code",
            "client_id"     => app.uid.as(String),
            "redirect_uri"  => uri,
            "scope"         => "public",
          })
          result.status_code.should eq 302
          location = result.headers["Location"]
          # The target must be that exact URI — not the first registered
          # one, not a normalised form of it.
          location.should start_with "#{uri}?code="
          redirect_params.call(location)["code"].should_not be_empty
        end
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      # Full native round trip. `AuthorizationCode#decode_code` compares the
      # token request's `redirect_uri` against the one baked into the code,
      # so a custom scheme has to survive being embedded in a JWT claim, put
      # in a Location header and posted back verbatim. This is the exact
      # wire shape of the Booking Panel login.
      it "exchanges a custom-scheme code at the token endpoint without a secret" do
        user, password = make_user.call
        native_uri = "com.placeos.booking.panel://oauth-#{Random.rand(999_999)}"
        app = make_app.call(native_uri)
        cookie = Spec.signin!(client, user, password)

        authorized = authorize.call(cookie, {
          "response_type" => "code",
          "client_id"     => app.uid.as(String),
          "redirect_uri"  => native_uri,
          "scope"         => "public",
        })
        authorized.status_code.should eq 302
        authorized.headers["Location"].should start_with "#{native_uri}?code="
        code = redirect_params.call(authorized.headers["Location"])["code"]

        token = form_post.call("/auth/token", {
          "grant_type"   => "authorization_code",
          "client_id"    => app.uid.as(String),
          "code"         => code,
          "redirect_uri" => native_uri,
        })
        token.status_code.should eq 200
        body = JSON.parse(token.body)
        body["access_token"].as_s.should_not be_empty
        # `sub` must be the signing-in user, not a random id — the
        # `AuthorizationCode#user_id` patch. Without it every native login
        # produces an anonymous token that rest-api rejects.
        claims, _ = JWT.decode(
          body["access_token"].as_s,
          ::Authly.config.public_key.as(String),
          JWT::Algorithm::RS256,
        )
        claims["sub"].as_s.should eq user.id.as(String)
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # --- AU-06: state round trip ---------------------------------------

    describe "state round trip (AU-06)" do
      # `state` is the client's CSRF token; ts-client compares the returned
      # value against the one it stored and aborts the login on any
      # difference. The endpoint appends it with `URI.encode_www_form`, so
      # anything that reserved characters could break — a raw `#` truncating
      # the URL at a fragment, a raw `&` injecting a parameter, a `+`
      # surviving as a literal plus — shows up as a login that silently
      # never completes. A trivial `state=xyz` (what the existing specs use)
      # cannot detect any of that.
      nasty_state = "a b&c=d?e#f/g+h%21"

      it "echoes a reserved-character state unmodified on success" do
        user, password = make_user.call
        redirect = "https://au06.example/cb-#{Random.rand(999_999)}"
        app = make_app.call(redirect)
        cookie = Spec.signin!(client, user, password)

        result = authorize.call(cookie, {
          "response_type" => "code",
          "client_id"     => app.uid.as(String),
          "redirect_uri"  => redirect,
          "scope"         => "public",
          "state"         => nasty_state,
        })
        result.status_code.should eq 302
        location = result.headers["Location"]
        location.should start_with "#{redirect}?code="
        params = redirect_params.call(location)
        params["code"].should_not be_empty
        params["state"].should eq nasty_state
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      # The deny half is the only redirect auth.cr emits on an error path
      # (every other authorize failure is a non-redirectable 4xx), so it is
      # where "state echoed on error" is actually observable. A client that
      # can't match the state on a denial treats it as an attack rather than
      # a user pressing Cancel.
      it "echoes a reserved-character state unmodified on the deny redirect" do
        user, password = make_user.call
        redirect = "https://au06b.example/cb-#{Random.rand(999_999)}"
        app = make_app.call(redirect)
        cookie = Spec.signin!(client, user, password)

        query = URI::Params.build do |fp|
          fp.add("response_type", "code")
          fp.add("client_id", app.uid.as(String))
          fp.add("redirect_uri", redirect)
          fp.add("state", nasty_state)
        end
        result = client.delete("/auth/authorize?#{query}", headers: HTTP::Headers{
          "Host" => "localhost", "Cookie" => cookie,
        })

        result.status_code.should eq 302
        location = result.headers["Location"]
        location.should start_with "#{redirect}?error=access_denied"
        params = redirect_params.call(location)
        params["error"].should eq "access_denied"
        params["state"].should eq nasty_state
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      # Doorkeeper omitted `state` entirely when the client didn't send one.
      # Echoing an empty `state=` back instead makes strict clients compare
      # `""` against `undefined` and fail the login.
      it "omits state entirely when the client did not send one" do
        user, password = make_user.call
        redirect = "https://au06c.example/cb-#{Random.rand(999_999)}"
        app = make_app.call(redirect)
        cookie = Spec.signin!(client, user, password)

        result = authorize.call(cookie, {
          "response_type" => "code",
          "client_id"     => app.uid.as(String),
          "redirect_uri"  => redirect,
          "scope"         => "public",
        })
        result.status_code.should eq 302
        location = result.headers["Location"]
        params = redirect_params.call(location)
        params["code"].should_not be_empty
        params.has_key?("state").should be_false
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # --- AU-11: authorization-code single use --------------------------

    describe "authorization-code single use (AU-11)" do
      # KNOWN DIVERGENCE — do not convert this to `it` until the server
      # actually consumes codes; it documents a gap, it does not pin
      # behaviour.
      #
      # auth.cr's authorization code is a *stateless* JWT
      # (`Authly::Code#jwt`: jti, code, challenge, method, scope, user_id,
      # redirect_uri, iat, iss, exp) with a 10-minute TTL. Redemption
      # (`Authly::AuthorizationCode#authorized?`) verifies the signature,
      # the embedded redirect_uri, the client and the PKCE challenge — and
      # nothing anywhere records that the code has been spent. There is no
      # consumption store: `TokenStore` only ever sees access/refresh token
      # jtis, never the code's.
      #
      # So a code can be replayed for the full 10 minutes, each replay
      # minting a fresh access+refresh pair. Ruby Doorkeeper revoked the
      # grant on first use (`Doorkeeper::AccessGrant#revoke`), so this is a
      # parity break as well as an RFC 6749 §4.1.2 one ("The client MUST NOT
      # use the authorization code more than once ... the authorization
      # server MUST deny the request and SHOULD revoke ... all tokens
      # previously issued based on that authorization code").
      #
      # Flipping this on is a behaviour change that needs a decision, not
      # just a test: RF-05 established that the ts-client boot race
      # double-submits its *refresh* token, and strict reuse-detection there
      # would revoke the family on every SPA boot. If the code exchange
      # races the same way, single-use has to be spend-once-and-return-the
      # same-token (or a short grace window), not revoke-the-family.
      pending "refuses a replayed authorization code and revokes what it issued" do
        user, password = make_user.call
        redirect = "https://au11.example/cb-#{Random.rand(999_999)}"
        app = make_app.call(redirect)
        client_id = app.uid.as(String)
        cookie = Spec.signin!(client, user, password)

        authorized = authorize.call(cookie, {
          "response_type" => "code",
          "client_id"     => client_id,
          "redirect_uri"  => redirect,
          "scope"         => "public",
        })
        authorized.status_code.should eq 302
        code = redirect_params.call(authorized.headers["Location"])["code"]

        exchange = -> {
          form_post.call("/auth/token", {
            "grant_type"   => "authorization_code",
            "client_id"    => client_id,
            "code"         => code,
            "redirect_uri" => redirect,
          })
        }

        first = exchange.call
        first.status_code.should eq 200
        issued = JSON.parse(first.body)["access_token"].as_s

        replay = exchange.call
        replay.status_code.should eq 400
        JSON.parse(replay.body)["error"].as_s.should eq "invalid_grant"
        JSON.parse(replay.body)["access_token"]?.should be_nil

        # RFC 6749 §4.1.2 SHOULD: the token minted from the replayed code's
        # first use is revoked too.
        ::Authly.valid?(issued).should be_false
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    # --- AU-13: cross-client code redemption ---------------------------

    describe "cross-client code redemption (AU-13)" do
      # A code issued to client A must not be redeemable by client B
      # (RFC 6749 §4.1.3). auth.cr enforces this *indirectly*: the code
      # carries `redirect_uri` (not `client_id`), and redemption requires
      # both that the request's redirect_uri equals the code's AND that it
      # is registered to the redeeming client. Distinct clients have
      # distinct redirect URIs, so both escape routes are closed — but the
      # binding is a side effect of the redirect check rather than an
      # explicit client check, which is why both directions are pinned here.

      it "refuses client B redeeming client A's code with A's redirect_uri" do
        user, password = make_user.call
        redirect_a = "https://au13a.example/cb-#{Random.rand(999_999)}"
        redirect_b = "https://au13b.example/cb-#{Random.rand(999_999)}"
        app_a = make_app.call(redirect_a)
        app_b = make_app.call(redirect_b)
        cookie = Spec.signin!(client, user, password)

        authorized = authorize.call(cookie, {
          "response_type" => "code",
          "client_id"     => app_a.uid.as(String),
          "redirect_uri"  => redirect_a,
          "scope"         => "public",
        })
        authorized.status_code.should eq 302
        code = redirect_params.call(authorized.headers["Location"])["code"]

        # B claims A's redirect_uri: rejected because it is not registered
        # to B.
        stolen = form_post.call("/auth/token", {
          "grant_type"   => "authorization_code",
          "client_id"    => app_b.uid.as(String),
          "code"         => code,
          "redirect_uri" => redirect_a,
        })
        # 400 invalid_redirect_uri, NOT 401 unauthorized_client: authly's
        # `validate!` runs `valid_redirect?` before `client_authorized?`
        # (lib/authly/.../grants/authorization_code.cr), so presenting A's URI
        # trips the redirect check first — B never reaches the client check.
        # The security property is identical either way (refused, no token);
        # only which guard fires differs, and it is pinned here so a
        # reordering upstream shows up as a deliberate decision rather than a
        # silent change.
        stolen.status_code.should eq 400
        JSON.parse(stolen.body)["error"].as_s.should eq "invalid_redirect_uri"
        JSON.parse(stolen.body)["access_token"]?.should be_nil

        # The code was still live throughout — A redeems it afterwards. This
        # is what stops the assertions above passing for the wrong reason
        # (an already-expired or malformed code would also be refused).
        legitimate = form_post.call("/auth/token", {
          "grant_type"   => "authorization_code",
          "client_id"    => app_a.uid.as(String),
          "code"         => code,
          "redirect_uri" => redirect_a,
        })
        legitimate.status_code.should eq 200
        JSON.parse(legitimate.body)["access_token"].as_s.should_not be_empty
      ensure
        app_a.try &.destroy
        app_b.try &.destroy
        user.try &.destroy
      end

      it "refuses client B redeeming client A's code with B's own redirect_uri" do
        user, password = make_user.call
        redirect_a = "https://au13c.example/cb-#{Random.rand(999_999)}"
        redirect_b = "https://au13d.example/cb-#{Random.rand(999_999)}"
        app_a = make_app.call(redirect_a)
        app_b = make_app.call(redirect_b)
        cookie = Spec.signin!(client, user, password)

        authorized = authorize.call(cookie, {
          "response_type" => "code",
          "client_id"     => app_a.uid.as(String),
          "redirect_uri"  => redirect_a,
          "scope"         => "public",
        })
        authorized.status_code.should eq 302
        code = redirect_params.call(authorized.headers["Location"])["code"]

        # B presents its own (registered) redirect_uri, so the client check
        # passes — the code's embedded redirect_uri is what refuses it.
        stolen = form_post.call("/auth/token", {
          "grant_type"   => "authorization_code",
          "client_id"    => app_b.uid.as(String),
          "code"         => code,
          "redirect_uri" => redirect_b,
        })
        stolen.status_code.should eq 400
        JSON.parse(stolen.body)["error"].as_s.should eq "invalid_redirect_uri"
        JSON.parse(stolen.body)["access_token"]?.should be_nil

        legitimate = form_post.call("/auth/token", {
          "grant_type"   => "authorization_code",
          "client_id"    => app_a.uid.as(String),
          "code"         => code,
          "redirect_uri" => redirect_a,
        })
        legitimate.status_code.should eq 200
        JSON.parse(legitimate.body)["access_token"].as_s.should_not be_empty
      ensure
        app_a.try &.destroy
        app_b.try &.destroy
        user.try &.destroy
      end

      # KNOWN DIVERGENCE — see the AU-11 note; this documents a gap, it does
      # not pin behaviour.
      #
      # The two cases above hold only because distinct clients have distinct
      # redirect URIs. `redirect_uri` is a whitespace-separated *list*
      # (`AuthlyAdapter::Client#registered_uris`), so a client B registered
      # with `<its own URI> <client A's URI>` satisfies both checks for a
      # code minted to A — and the code carries no `client_id` claim to
      # catch it (`Authly::Code#jwt`). B redeems A's code and receives a
      # token bound to A's user.
      #
      # Exploiting it needs the attacker to register a client, which is an
      # admin action, so this is low severity — but it is a real RFC 6749
      # §4.1.3 gap ("ensure that the authorization code was issued to the
      # authenticated confidential client, or if the client is public,
      # ensure that the code was issued to `client_id` in the request").
      # The fix is one claim: put `client_id` in `Code#jwt` (auth.cr already
      # patches that method) and compare it in `AuthorizationCode#decode_code`.
      pending "refuses a client whose registration merely overlaps the code's redirect_uri" do
        user, password = make_user.call
        redirect_a = "https://au13e.example/cb-#{Random.rand(999_999)}"
        redirect_b = "https://au13f.example/cb-#{Random.rand(999_999)}"
        app_a = make_app.call(redirect_a)
        # B registers its own URI *and* A's.
        app_b = make_app.call("#{redirect_b} #{redirect_a}")
        cookie = Spec.signin!(client, user, password)

        authorized = authorize.call(cookie, {
          "response_type" => "code",
          "client_id"     => app_a.uid.as(String),
          "redirect_uri"  => redirect_a,
          "scope"         => "public",
        })
        authorized.status_code.should eq 302
        code = redirect_params.call(authorized.headers["Location"])["code"]

        stolen = form_post.call("/auth/token", {
          "grant_type"   => "authorization_code",
          "client_id"    => app_b.uid.as(String),
          "code"         => code,
          "redirect_uri" => redirect_a,
        })
        stolen.status_code.should eq 400
        JSON.parse(stolen.body)["error"].as_s.should eq "invalid_grant"
        JSON.parse(stolen.body)["access_token"]?.should be_nil
      ensure
        app_a.try &.destroy
        app_b.try &.destroy
        user.try &.destroy
      end
    end
  end
end
