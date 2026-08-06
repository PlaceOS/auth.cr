require "../helper"

module PlaceOS::Auth
  # Open-redirect prevention across every redirecting endpoint — PPT-2536
  # test-matrix rows SEC-05 and SC-12.
  #
  # The guards existed and were partly asserted, but scattered one case at a
  # time across `sessions_spec` and `authorize_validation_spec`, so no single
  # place said "here is the hostile input set, and here is every endpoint
  # that must survive it". That is what let the backslash bypass below sit
  # unnoticed: each individual spec passed.
  describe Utils::SessionHelper, tags: "open-redirect" do
    # Resolves a `Location` the way a *browser* does, which is not the way
    # `URI.parse` does. WHATWG URL parsing treats `\` exactly like `/` while
    # resolving a special (http/https) URL — "relative slash state": if c is
    # U+002F (/) or U+005C (\), go to special authority ignore slashes state.
    # So `/\evil.example` is scheme-relative and navigates off-site, while
    # `URI.parse("/\\evil.example").host` is nil and reports it as harmless.
    # Asserting through Crystal's parser would have missed the whole bug.
    browser_host = ->(location : String) : String? {
      normalized = location.tr("\\", "/")
      if normalized.starts_with?("//")
        normalized[2..].split(/[\/?#]/).first.presence
      else
        URI.parse(location).host.presence
      end
    }

    # Every one of these must be refused as a redirect target. The first
    # three are the same attack written three ways; only the first was
    # covered before.
    hostile_targets = [
      "//evil.example/x",
      "/\\evil.example/x",
      "/\\/evil.example/x",
      "https://evil.example/x",
      "http://evil.example/x",
      # Suffix trick — `localhost.evil.example` is NOT the authority host,
      # but a `starts_with?`/`includes?` style check would accept it.
      "https://localhost.evil.example/x",
      # Userinfo trick — the real host is `evil.example`.
      "https://localhost@evil.example/x",
    ]

    create_user = ->(password : String) {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      user = ::PlaceOS::Model::Generator.user(authority)
      user.password = password
      user.save!
      user
    }

    # ---- SC-12: the guard itself, through a real endpoint ---------------

    describe "sanitize_continue (SC-12)" do
      it "refuses every hostile continue on signin" do
        password = "ok-password-1234"
        user = create_user.call(password)

        hostile_targets.each do |hostile|
          result = client.post("/auth/signin",
            headers: HTTP::Headers{"Host" => "localhost", "Content-Type" => "application/json"},
            body: {email: user.email.to_s, password: password, continue: hostile}.to_json)

          result.status_code.should eq 303
          location = result.headers["Location"]
          host = browser_host.call(location)
          # Positive invariant: we still got a redirect, and it stays here.
          location.should_not be_empty
          if host
            host.should eq "localhost"
          end
          # Stated the other way round so a future change to `browser_host`
          # can't quietly make this vacuous.
          location.tr("\\", "/").should_not contain "evil.example"
        end
      ensure
        user.try &.destroy
      end

      it "preserves a safe relative continue untouched" do
        password = "ok-password-1234"
        user = create_user.call(password)

        result = client.post("/auth/signin",
          headers: HTTP::Headers{"Host" => "localhost", "Content-Type" => "application/json"},
          body: {email: user.email.to_s, password: password, continue: "/backoffice/#/panel"}.to_json)

        result.status_code.should eq 303
        result.headers["Location"].should eq "/backoffice/#/panel"
      ensure
        user.try &.destroy
      end

      it "allows `//` inside the query string of an otherwise relative continue" do
        # The guard only inspects the part before `?`. A relative path whose
        # *query* carries a URL is legitimate and common (`?next=https://…`),
        # and over-rejecting it would break real links.
        password = "ok-password-1234"
        user = create_user.call(password)

        result = client.post("/auth/signin",
          headers: HTTP::Headers{"Host" => "localhost", "Content-Type" => "application/json"},
          body: {email: user.email.to_s, password: password, continue: "/app?next=https://elsewhere.example/x"}.to_json)

        result.status_code.should eq 303
        result.headers["Location"].should eq "/app?next=https://elsewhere.example/x"
      ensure
        user.try &.destroy
      end

      it "reduces a same-host absolute continue to its path" do
        password = "ok-password-1234"
        user = create_user.call(password)

        result = client.post("/auth/signin",
          headers: HTTP::Headers{"Host" => "localhost", "Content-Type" => "application/json"},
          body: {email: user.email.to_s, password: password, continue: "https://localhost/dashboard?a=1"}.to_json)

        result.status_code.should eq 303
        result.headers["Location"].should eq "/dashboard?a=1"
      ensure
        user.try &.destroy
      end
    end

    # ---- SEC-05: the sweep across redirecting endpoints -----------------

    describe "no redirecting endpoint sends the browser off-host (SEC-05)" do
      it "holds for GET /auth/logout" do
        hostile_targets.each do |hostile|
          result = client.get("/auth/logout?continue=#{URI.encode_www_form(hostile)}",
            headers: HTTP::Headers{"Host" => "localhost"})

          result.status_code.should eq 302
          location = result.headers["Location"]
          # Logout falls back to the authority's own `logout_url` when the
          # continue is refused, so the target may legitimately be absolute
          # — it just must not be the attacker's.
          location.tr("\\", "/").should_not contain "evil.example"
        end
      end

      it "holds for GET /auth/login" do
        hostile_targets.each do |hostile|
          result = client.get("/auth/login?continue=#{URI.encode_www_form(hostile)}",
            headers: HTTP::Headers{"Host" => "localhost"})

          # `continue` is substituted into the authority's `login_url`
          # ({{url}}), so it lands in a query parameter rather than the
          # host — but assert it, because a login_url shaped differently
          # would change that.
          {303, 400}.should contain result.status_code
          if location = result.headers["Location"]?
            host = browser_host.call(location)
            host.should_not eq "evil.example"
            host.should_not eq "localhost.evil.example"
          end
        end
      end

      it "holds for the provider hand-off" do
        # `/auth/login?provider=&id=` calls `set_continue` and bounces to the
        # provider. This asserts only that the *hand-off* Location is local
        # — the continue goes to the session, not to this header, so this
        # case alone would still pass with the guard broken. What the stored
        # value replays to after a full IdP round-trip is asserted in
        # `oauth_provider_flows_spec.cr`, "refuses to land on an off-host
        # continue after the SSO round-trip (SEC-05)", which does fail
        # without the fix.
        hostile_targets.each do |hostile|
          result = client.get(
            "/auth/login?provider=saml&id=x&continue=#{URI.encode_www_form(hostile)}",
            headers: HTTP::Headers{"Host" => "localhost"})

          result.status_code.should eq 303
          location = result.headers["Location"]
          location.should start_with "/auth/saml"
          location.tr("\\", "/").should_not contain "evil.example"
        end
      end

      it "holds for the unauthenticated /auth/authorize bounce" do
        # Bounces to `/auth/login` and stashes `request.resource` — our own
        # path, not caller-controlled — but the redirect itself must still
        # be local.
        result = client.get(
          "/auth/authorize?response_type=code&client_id=x&redirect_uri=#{URI.encode_www_form("https://evil.example/cb")}",
          headers: HTTP::Headers{"Host" => "localhost"})

        result.status_code.should eq 303
        result.headers["Location"].should eq "/auth/login"
      end

      # The authorize *grant* redirect is constrained to a registered
      # redirect_uri, covered exhaustively by `authorize_validation_spec.cr`
      # (AU-03 unregistered → non-redirectable, AU-04 exact match) and the
      # deny path by `authorize_flow_spec.cr`. Not duplicated here.
    end

    # ---- The one place an unsanitised value still reaches Location ------

    describe "login failure reflects the Referer (pinned, not fixed)" do
      it "sends the browser back to whatever Referer it was given" do
        # `login_failure` reloads the referring page so a browser form can
        # retry, and it uses `Referer` verbatim. This is Ruby parity —
        # `dropin-audit.md:22` records the legacy `login_failure ->
        # redirect_to referer` — so it is pinned rather than changed.
        #
        # The exposure is real but narrow: the victim must already be on the
        # attacker's page and submit a login form from it, at which point the
        # attacker can navigate them anywhere anyway. What makes it a
        # judgement call rather than an obvious fix is that the session
        # cookie is deliberately `SameSite=None` for *embedded* login, so a
        # cross-site Referer here can be a legitimate embedder that the retry
        # is supposed to return to. Restricting it to same-host would be a
        # product decision about embedded login, not a pure hardening change.
        password = "ok-password-1234"
        user = create_user.call(password)

        result = client.post("/auth/signin",
          headers: HTTP::Headers{
            "Host" => "localhost", "Content-Type" => "application/json",
            "Referer" => "https://embedder.example/login",
          },
          body: {email: user.email.to_s, password: "wrong-#{password}", continue: "/app"}.to_json)

        result.status_code.should eq 303
        result.headers["Location"].should eq "https://embedder.example/login"
      ensure
        user.try &.destroy
      end

      it "still refuses to leak a 401 into a redirect when there is no continue" do
        # The API contract: no `continue` means a real 401, never a bounce.
        password = "ok-password-1234"
        user = create_user.call(password)

        result = client.post("/auth/signin",
          headers: HTTP::Headers{
            "Host" => "localhost", "Content-Type" => "application/json",
            "Referer" => "https://evil.example/x",
          },
          body: {email: user.email.to_s, password: "wrong-#{password}"}.to_json)

        result.status_code.should eq 401
        result.headers["Location"]?.should be_nil
      ensure
        user.try &.destroy
      end
    end
  end
end
