require "../helper"
require "digest/sha256"
require "base64"

module PlaceOS::Auth
  # Seamless authentication for MCP clients: loopback redirects, client ID
  # metadata documents, dynamic client registration, the consent screen,
  # mandatory PKCE for self registered clients and RFC 8707 resource indicators.
  describe "MCP client authentication", tags: "mcp" do
    host_headers = HTTP::Headers{"Host" => "localhost"}

    make_user = -> {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      user = ::PlaceOS::Model::Generator.user(authority)
      password = "mcp-password-#{Random.rand(999_999)}"
      user.password = password
      user.save!
      {user, password}
    }

    make_app = ->(redirect : String, skip : Bool, owner : String) {
      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "mcp-app-#{Random.rand(999_999)}"
      app.redirect_uri = redirect
      app.scopes = "public"
      app.owner_id = owner
      app.skip_authorization = skip
      app.save!
      app
    }

    challenge_for = ->(verifier : String) {
      Base64.urlsafe_encode(Digest::SHA256.digest(verifier), padding: false)
    }

    authorize_url = ->(client_id : String, redirect : String, extra : Hash(String, String)) {
      params = URI::Params.build do |form|
        form.add "response_type", "code"
        form.add "client_id", client_id
        form.add "redirect_uri", redirect
        form.add "scope", "public"
        extra.each { |key, value| form.add key, value }
      end
      "/auth/authorize?#{params}"
    }

    # the hidden form fields of a consent page
    consent_fields = ->(html : String) {
      fields = {} of String => String
      html.scan(/<input type="hidden" name="([^"]*)" value="([^"]*)">/) do |match|
        fields[HTML.unescape(match[1])] = HTML.unescape(match[2])
      end
      fields
    }

    submit_consent = ->(fields : Hash(String, String), decision : String, cookie : String) {
      body = URI::Params.build do |form|
        fields.each { |key, value| form.add key, value }
        form.add "consent", decision
      end
      client.post("/auth/authorize", headers: HTTP::Headers{
        "Host" => "localhost", "Cookie" => cookie, "Content-Type" => "application/x-www-form-urlencoded",
      }, body: body)
    }

    redeem = ->(client_id : String, code : String, redirect : String, verifier : String, resource : String?) {
      body = URI::Params.build do |form|
        form.add "grant_type", "authorization_code"
        form.add "client_id", client_id
        form.add "code", code
        form.add "redirect_uri", redirect
        form.add "code_verifier", verifier
        form.add "resource", resource if resource
      end
      client.post("/auth/token", headers: HTTP::Headers{
        "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
      }, body: body)
    }

    code_from = ->(response : HTTP::Client::Response) {
      URI::Params.parse(response.headers["Location"].split('?', 2).last)["code"]
    }

    register = ->(payload : String) {
      client.post("/auth/oauth/register", headers: HTTP::Headers{
        "Host" => "localhost", "Content-Type" => "application/json",
      }, body: payload)
    }

    Registrations.limiter = Utils::RateLimiter.new(1_000, 1.hour)

    describe "redirect URIs" do
      it "matches loopback redirects on any port" do
        Utils::RedirectURI.match?("http://127.0.0.1/callback", "http://127.0.0.1:53682/callback").should be_true
        Utils::RedirectURI.match?("http://localhost/callback", "http://localhost:3000/callback").should be_true
        Utils::RedirectURI.match?("http://[::1]:8080/cb", "http://[::1]:9090/cb").should be_true
        Utils::RedirectURI.match?("http://127.0.0.1/callback", "http://127.0.0.1:53682/other").should be_false
        Utils::RedirectURI.match?("http://127.0.0.1/callback", "http://localhost:53682/callback").should be_false
        Utils::RedirectURI.match?("https://example.com/cb", "https://example.com:8443/cb").should be_false
        Utils::RedirectURI.match?("http://example.com/cb", "http://example.com:81/cb").should be_false
      end

      it "only registers safe redirect URIs" do
        Utils::RedirectURI.registrable?("https://app.example.com/cb").should be_true
        Utils::RedirectURI.registrable?("http://127.0.0.1:8080/cb").should be_true
        Utils::RedirectURI.registrable?("com.example.app:/oauth").should be_true
        Utils::RedirectURI.registrable?("http://app.example.com/cb").should be_false
        Utils::RedirectURI.registrable?("javascript:alert(1)").should be_false
        Utils::RedirectURI.registrable?("https://app.example.com/cb#frag").should be_false
        Utils::RedirectURI.registrable?("myapp:/cb").should be_false
      end

      it "authorizes a registered loopback redirect on an ephemeral port" do
        user, password = make_user.call
        app = make_app.call("http://127.0.0.1/callback", true, user.id.as(String))
        cookie = Spec.signin!(client, user, password)

        redirect = "http://127.0.0.1:53682/callback"
        response = client.get(authorize_url.call(app.uid.as(String), redirect, {} of String => String), headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie})
        response.status_code.should eq 302
        response.headers["Location"].should start_with "#{redirect}?code="
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    describe "dynamic client registration" do
      it "registers public clients, reusing identical registrations" do
        name = "Claude Code #{Random.rand(999_999)}"
        response = register.call({client_name: name, redirect_uris: ["http://localhost/callback", "https://app.example.com/cb"], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"]}.to_json)
        response.status_code.should eq 201
        info = JSON.parse(response.body)
        client_id = info["client_id"].as_s
        client_id.should start_with "dcr-"
        info["client_name"].should eq name
        info["token_endpoint_auth_method"].should eq "none"
        info["client_secret"]?.should be_nil

        # every user of a client shares its registration, whatever the redirect order
        same = register.call({client_name: name, redirect_uris: ["https://app.example.com/cb", "http://localhost/callback"]}.to_json)
        same.status_code.should eq 201
        JSON.parse(same.body)["client_id"].should eq client_id
        JSON.parse(same.body)["client_id_issued_at"].should eq info["client_id_issued_at"]

        # a different client is a new registration
        other = register.call({client_name: "#{name} beta", redirect_uris: ["http://localhost/callback", "https://app.example.com/cb"]}.to_json)
        other.status_code.should eq 201
        other_id = JSON.parse(other.body)["client_id"].as_s
        other_id.should_not eq client_id
      ensure
        [client_id, other_id].each do |uid|
          ::PlaceOS::Model::DoorkeeperApplication.where(uid: uid).first?.try(&.destroy) if uid
        end
      end

      it "rejects unsafe registrations" do
        error = ->(response : HTTP::Client::Response) { JSON.parse(response.body)["error"].as_s }

        response = register.call({redirect_uris: ["http://evil.example.com/cb"]}.to_json)
        response.status_code.should eq 400
        error.call(response).should eq "invalid_redirect_uri"

        response = register.call({redirect_uris: [] of String}.to_json)
        error.call(response).should eq "invalid_redirect_uri"

        response = register.call({redirect_uris: ["https://app.example.com/cb"], token_endpoint_auth_method: "client_secret_post"}.to_json)
        error.call(response).should eq "invalid_client_metadata"

        response = register.call({redirect_uris: ["https://app.example.com/cb"], grant_types: ["client_credentials"]}.to_json)
        error.call(response).should eq "invalid_client_metadata"

        response = register.call({redirect_uris: ["https://app.example.com/cb"], scope: "admin"}.to_json)
        error.call(response).should eq "invalid_client_metadata"
      end

      it "limits new registrations, not reused ones" do
        Registrations.limiter = Utils::RateLimiter.new(1, 1.hour)
        name = "Limited #{Random.rand(999_999)}"
        first = register.call({client_name: name, redirect_uris: ["https://limited.example.com/cb"]}.to_json)
        first.status_code.should eq 201

        # the same client again is reused, so isn't limited
        register.call({client_name: name, redirect_uris: ["https://limited.example.com/cb"]}.to_json).status_code.should eq 201

        # a new client identity is limited
        limited = register.call({client_name: "#{name} 2", redirect_uris: ["https://limited.example.com/cb"]}.to_json)
        limited.status_code.should eq 429
        limited.headers["Retry-After"]?.should_not be_nil
      ensure
        Registrations.limiter = Utils::RateLimiter.new(1_000, 1.hour)
        first.try { |resp| ::PlaceOS::Model::DoorkeeperApplication.where(uid: JSON.parse(resp.body)["client_id"].as_s).first?.try(&.destroy) }
      end

      it "runs the full MCP flow: register, PKCE, consent, token" do
        user, password = make_user.call
        cookie = Spec.signin!(client, user, password)
        redirect = "http://127.0.0.1/callback"
        client_id = JSON.parse(register.call({client_name: "MCP Inspector", redirect_uris: [redirect]}.to_json).body)["client_id"].as_s

        verifier = "mcp-verifier-#{Random::Secure.hex(24)}"
        port_redirect = "http://127.0.0.1:61234/callback"
        resource = "https://localhost/mcp"
        pkce = {"code_challenge" => challenge_for.call(verifier), "code_challenge_method" => "S256", "resource" => resource, "state" => "abc"}
        auth_headers = HTTP::Headers{"Host" => "localhost", "Cookie" => cookie}

        # PKCE is mandatory for self registered clients
        response = client.get(authorize_url.call(client_id, port_redirect, {} of String => String), headers: auth_headers)
        response.status_code.should eq 400
        JSON.parse(response.body)["error"].should eq "invalid_request"

        # the consent screen is shown and framing is denied
        response = client.get(authorize_url.call(client_id, port_redirect, pkce), headers: auth_headers)
        response.status_code.should eq 200
        response.headers["X-Frame-Options"].should eq "DENY"
        response.body.should contain "MCP Inspector"
        response.body.should contain "an application on this computer (port 61234)"
        fields = consent_fields.call(response.body)
        fields["consent_token"].should_not be_empty

        # approving issues a code, which redeems with the verifier
        approved = submit_consent.call(fields, "allow", cookie)
        approved.status_code.should eq 302
        approved.headers["Location"].should contain "state=abc"
        token = redeem.call(client_id, code_from.call(approved), port_redirect, verifier, resource)
        token.status_code.should eq 200
        JSON.parse(token.body)["refresh_token"].as_s.should_not be_empty
      ensure
        ::PlaceOS::Model::DoorkeeperApplication.where(uid: client_id).first?.try(&.destroy) if client_id
        user.try &.destroy
      end
    end

    describe "consent" do
      it "redirects with access_denied when the user denies" do
        user, password = make_user.call
        cookie = Spec.signin!(client, user, password)
        app = make_app.call("https://consent.example.com/cb", false, user.id.as(String))
        response = client.get(authorize_url.call(app.uid.as(String), "https://consent.example.com/cb", {"state" => "xyz"}), headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie})
        response.status_code.should eq 200

        denied = submit_consent.call(consent_fields.call(response.body), "deny", cookie)
        denied.status_code.should eq 302
        denied.headers["Location"].should start_with "https://consent.example.com/cb?error=access_denied"
        denied.headers["Location"].should contain "state=xyz"
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "grants apps that skip authorization without asking" do
        user, password = make_user.call
        cookie = Spec.signin!(client, user, password)
        app = make_app.call("https://skip.example.com/cb", true, user.id.as(String))
        response = client.get(authorize_url.call(app.uid.as(String), "https://skip.example.com/cb", {} of String => String), headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie})
        response.status_code.should eq 302
      ensure
        app.try &.destroy
        user.try &.destroy
      end

      it "refuses forged, tampered or replayed approvals" do
        user, password = make_user.call
        cookie = Spec.signin!(client, user, password)
        app = make_app.call("https://tamper.example.com/cb https://tamper.example.com/other", false, user.id.as(String))
        page = client.get(authorize_url.call(app.uid.as(String), "https://tamper.example.com/cb", {} of String => String), headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie})
        fields = consent_fields.call(page.body)

        # a different (but registered) redirect re-renders the consent page
        submit_consent.call(fields.merge({"redirect_uri" => "https://tamper.example.com/other"}), "allow", cookie).status_code.should eq 200
        # a forged token
        submit_consent.call(fields.merge({"consent_token" => "9999999999.deadbeef"}), "allow", cookie).status_code.should eq 200
        # approval must be POSTed
        get_params = URI::Params.encode(fields.merge({"consent" => "allow"}))
        client.get("/auth/authorize?#{get_params}", headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie}).status_code.should eq 200

        # another user's session can't use the token
        other, other_password = make_user.call
        other_cookie = Spec.signin!(client, other, other_password)
        submit_consent.call(fields, "allow", other_cookie).status_code.should eq 200

        # the genuine approval works
        submit_consent.call(fields, "allow", cookie).status_code.should eq 302
      ensure
        app.try &.destroy
        user.try &.destroy
        other.try &.destroy
      end
    end

    describe "client ID metadata documents" do
      metadata_url = "https://client.example.com/oauth/metadata.json"
      metadata = {
        client_id:                  metadata_url,
        client_name:                "Example <MCP> Client",
        redirect_uris:              ["http://127.0.0.1/callback"],
        token_endpoint_auth_method: "none",
      }

      it "validates document URLs" do
        expect_raises(Utils::ClientMetadata::Invalid) { Utils::ClientMetadata.validate_url!("https://127.0.0.1/meta.json") }
        expect_raises(Utils::ClientMetadata::Invalid) { Utils::ClientMetadata.validate_url!("https://localhost/meta.json") }
        expect_raises(Utils::ClientMetadata::Invalid) { Utils::ClientMetadata.validate_url!("https://client.example.com/") }
        expect_raises(Utils::ClientMetadata::Invalid) { Utils::ClientMetadata.validate_url!("http://client.example.com/meta.json") }
        Utils::ClientMetadata.validate_url!(metadata_url).host.should eq "client.example.com"
      end

      it "validates documents" do
        expect_raises(Utils::ClientMetadata::Invalid, /does not match/) do
          Utils::ClientMetadata.parse!("https://other.example.com/meta.json", metadata.to_json)
        end
        expect_raises(Utils::ClientMetadata::Invalid, /client_secret/) do
          Utils::ClientMetadata.parse!(metadata_url, metadata.merge({client_secret: "nope"}).to_json)
        end
        expect_raises(Utils::ClientMetadata::Invalid, /redirect_uri/) do
          Utils::ClientMetadata.parse!(metadata_url, metadata.merge({redirect_uris: ["http://evil.example.com/cb"]}).to_json)
        end
        Utils::ClientMetadata.parse!(metadata_url, metadata.to_json).display_name.should eq "Example <MCP> Client"
      end

      it "authorizes a client identified by its metadata document" do
        user, password = make_user.call
        cookie = Spec.signin!(client, user, password)
        fetches = 0
        Utils::ClientMetadata.clear_cache
        Utils::ClientMetadata.fetcher = ->(uri : URI) {
          fetches += 1
          uri.to_s.should eq metadata_url
          {metadata.to_json, 10.minutes.as(Time::Span?)}
        }

        verifier = "cimd-verifier-#{Random::Secure.hex(24)}"
        redirect = "http://127.0.0.1:41000/callback"
        page = client.get(authorize_url.call(metadata_url, redirect, {"code_challenge" => challenge_for.call(verifier), "code_challenge_method" => "S256"}), headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie})
        page.status_code.should eq 200
        page.body.should contain "Example &lt;MCP&gt; Client"
        page.body.should_not contain "<MCP>"
        page.body.should contain "Identified by client.example.com"

        approved = submit_consent.call(consent_fields.call(page.body), "allow", cookie)
        approved.status_code.should eq 302
        token = redeem.call(metadata_url, code_from.call(approved), redirect, verifier, nil)
        token.status_code.should eq 200

        # the document is cached
        fetches.should eq 1
      ensure
        Utils::ClientMetadata.fetcher = ->(uri : URI) { Utils::ClientMetadata.http_fetch(uri) }
        Utils::ClientMetadata.clear_cache
        user.try &.destroy
      end

      it "refuses documents that can't be used" do
        user, password = make_user.call
        cookie = Spec.signin!(client, user, password)
        Utils::ClientMetadata.clear_cache
        Utils::ClientMetadata.fetcher = ->(_uri : URI) { {metadata.merge({client_id: "https://someone.else/meta.json"}).to_json, nil.as(Time::Span?)} }

        response = client.get(authorize_url.call(metadata_url, "http://127.0.0.1:41000/callback", {"code_challenge" => challenge_for.call("verifier-x" * 5), "code_challenge_method" => "S256"}), headers: HTTP::Headers{"Host" => "localhost", "Cookie" => cookie})
        response.status_code.should eq 401
        JSON.parse(response.body)["error"].should eq "unauthorized_client"
      ensure
        Utils::ClientMetadata.fetcher = ->(uri : URI) { Utils::ClientMetadata.http_fetch(uri) }
        Utils::ClientMetadata.clear_cache
        user.try &.destroy
      end

      it "restricts client hosts when an allow-list is configured" do
        Utils::ClientMetadata.allowed_hosts = ["claude.ai"]
        expect_raises(Utils::ClientMetadata::Invalid, /not an allowed client host/) do
          Utils::ClientMetadata.validate_url!(metadata_url)
        end
        Utils::ClientMetadata.validate_url!("https://claude.ai/oauth/mcp-client.json")
      ensure
        Utils::ClientMetadata.allowed_hosts = nil
      end
    end

    describe "resource indicators" do
      it "only accepts resources on this authority" do
        user, password = make_user.call
        cookie = Spec.signin!(client, user, password)
        app = make_app.call("https://resource.example.com/cb", true, user.id.as(String))
        headers = HTTP::Headers{"Host" => "localhost", "Cookie" => cookie}

        rejected = client.get(authorize_url.call(app.uid.as(String), "https://resource.example.com/cb", {"resource" => "https://evil.example.com/mcp"}), headers: headers)
        rejected.status_code.should eq 400
        JSON.parse(rejected.body)["error"].should eq "invalid_target"

        accepted = client.get(authorize_url.call(app.uid.as(String), "https://resource.example.com/cb", {"resource" => "https://localhost/mcp"}), headers: headers)
        accepted.status_code.should eq 302

        token = redeem.call(app.uid.as(String), code_from.call(accepted), "https://resource.example.com/cb", "", "https://evil.example.com/mcp")
        token.status_code.should eq 400
        JSON.parse(token.body)["error"].should eq "invalid_target"
      ensure
        app.try &.destroy
        user.try &.destroy
      end
    end

    it "serves protected resource metadata for resource servers on this host" do
      response = client.get("/.well-known/oauth-protected-resource/api/engine/v2/mcp", headers: host_headers)
      response.status_code.should eq 200
      response.headers["Access-Control-Allow-Origin"].should eq "*"
      doc = JSON.parse(response.body)
      doc["resource"].should eq "http://localhost/api/engine/v2/mcp"
      doc["authorization_servers"].as_a.should eq ["http://localhost"]
      doc["scopes_supported"].as_a.should eq ["public"]

      # agrees with the authorization server's issuer
      issuer = JSON.parse(client.get("/.well-known/oauth-authorization-server", headers: host_headers).body)["issuer"]
      doc["authorization_servers"][0].should eq issuer

      tenant = HTTP::Headers{"Host" => "localhost", "X-Forwarded-Proto" => "https"}
      JSON.parse(client.get("/.well-known/oauth-protected-resource", headers: tenant).body)["resource"].should eq "https://localhost"
    end

    it "advertises registration in the discovery document" do
      doc = JSON.parse(client.get("/.well-known/oauth-authorization-server", headers: host_headers).body)
      doc["registration_endpoint"].as_s.should end_with "/auth/oauth/register"
      doc["client_id_metadata_document_supported"].should be_true
      doc["code_challenge_methods_supported"].as_a.should eq ["S256"]
    end
  end
end
