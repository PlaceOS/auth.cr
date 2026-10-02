require "../helper"
require "jwt"
require "webmock"

module PlaceOS::Auth
  # RFC 8693 token exchange of Microsoft Entra access tokens
  # (`Utils::EntraTokenExchange`). Entra's discovery documents and JWKS are
  # stubbed with a spec key pair; the rejection cases are the ones that let
  # a forged or misdirected token mint a PlaceOS session if they slip.
  describe OAuth, tags: "token-exchange" do
    tenant = "bc9d5ad8-7518-422b-ac8d-b69429ca4cb9"
    entra_client = "eb5a5522-e090-497e-a789-c5d3cbfce7ac"
    kid = "spec-entra-key"
    fixtures = File.join(__DIR__, "../fixtures/entra")
    signing_key = File.read(File.join(fixtures, "signing_key.pem"))
    attacker_key = File.read(File.join(fixtures, "attacker_key.pem"))
    jwks_uri = "https://login.microsoftonline.com/common/discovery/keys"
    v1_issuer = "https://sts.windows.net/#{tenant}/"
    v2_issuer = "https://login.microsoftonline.com/#{tenant}/v2.0"
    token_url = "https://login.microsoftonline.com/#{tenant}/oauth2/v2.0/token"

    grant = Utils::EntraTokenExchange::GRANT_TYPE
    access_token_type = Utils::EntraTokenExchange::TOKEN_TYPE_ACCESS_TOKEN

    authority = -> { ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil! }

    make_strat = ->(ensure_matching : Hash(String, Array(String))) {
      ::PlaceOS::Model::OAuthAuthentication.where(authority_id: authority.call.id.as(String)).each(&.destroy)
      strat = ::PlaceOS::Model::OAuthAuthentication.new(
        name: "Entra",
        client_id: entra_client,
        client_secret: "entra-secret",
        site: "https://login.microsoftonline.com",
        authorize_url: "/#{tenant}/oauth2/v2.0/authorize",
        token_url: "/#{tenant}/oauth2/v2.0/token",
        scope: "openid email offline_access User.Read",
        info_mappings: {"uid" => "id", "email" => "mail,userPrincipalName", "name" => "displayName"},
        ensure_matching: ensure_matching,
      )
      strat.authority_id = authority.call.id
      strat.save!
    }

    make_app = ->(confidential : Bool) {
      owner = ::PlaceOS::Model::Generator.user(authority.call).tap(&.save!)
      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.name = "outlook-addin-#{Random.rand(999_999)}"
      app.skip_authorization = true
      app.redirect_uri = "https://localhost/addin/#{Random.rand(999_999)}"
      app.scopes = "public"
      app.owner_id = owner.id.as(String)
      app.confidential = confidential
      app.save!
    }

    oid = -> { UUID.random.to_s }

    # A v1 Office add-in SSO token, as Outlook hands it over.
    entra_token = ->(overrides : Hash(String, String | Int64 | Nil), key : String) {
      now = Time.utc.to_unix
      claims = {
        "aud"         => "api://localhost/#{entra_client}",
        "iss"         => v1_issuer,
        "iat"         => now - 60,
        "nbf"         => now - 60,
        "exp"         => now + 3600,
        "ver"         => "1.0",
        "tid"         => tenant,
        "oid"         => "65262d57-be2d-4fd3-8381-90e332d0609a",
        "scp"         => "access_as_user",
        "name"        => "FNU LNU",
        "given_name"  => "FNU",
        "family_name" => "LNU",
        "upn"         => "exchange-user@example.onmicrosoft.com",
      } of String => String | Int64 | Nil
      overrides.each { |claim, value| value.nil? ? claims.delete(claim) : (claims[claim] = value) }
      JWT.encode(claims, key, JWT::Algorithm::RS256, kid: kid, x5t: kid)
    }

    exchange = ->(app : ::PlaceOS::Model::DoorkeeperApplication, subject : String, extra : Hash(String, String)) {
      params = {
        "grant_type"         => grant,
        "client_id"          => app.uid.as(String),
        "subject_token"      => subject,
        "subject_token_type" => access_token_type,
      }.merge(extra)
      client.post("/auth/oauth/token", headers: HTTP::Headers{
        "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
      }, body: URI::Params.encode(params))
    }

    decode = ->(token : String) {
      payload, _ = JWT.decode(token, ::Authly.config.public_key.as(String), JWT::Algorithm::RS256)
      payload
    }

    no_extra = {} of String => String
    no_override = {} of String => String | Int64 | Nil

    before_each do
      WebMock.reset
      WebMock.allow_net_connect = false
      Utils::EntraTokenExchange.jwks = JWT::JWKS.new

      {
        "https://login.microsoftonline.com/#{tenant}"      => v1_issuer,
        "https://login.microsoftonline.com/#{tenant}/v2.0" => v2_issuer,
      }.each do |base, issuer|
        WebMock.stub(:get, "#{base}/.well-known/openid-configuration").to_return(
          status: 200,
          headers: HTTP::Headers{"Content-Type" => "application/json"},
          body: {issuer: issuer, jwks_uri: jwks_uri}.to_json,
        )
      end
      WebMock.stub(:get, jwks_uri).to_return(
        status: 200,
        headers: HTTP::Headers{"Content-Type" => "application/json"},
        body: File.read(File.join(fixtures, "jwks.json")),
      )
    end
    after_each { WebMock.reset }

    describe "accepted subject tokens" do
      it "exchanges an Office add-in token for a PlaceOS token pair" do
        make_strat.call({} of String => Array(String))
        app = make_app.call(false)
        user_oid = oid.call

        result = exchange.call(app, entra_token.call({"oid" => user_oid, "upn" => "#{user_oid}@example.onmicrosoft.com"} of String => String | Int64 | Nil, signing_key), no_extra)
        result.status_code.should eq 200
        result.headers["Cache-Control"].should contain("no-store")

        body = JSON.parse(result.body)
        body["issued_token_type"].as_s.should eq access_token_type
        body["token_type"].as_s.should eq "Bearer"
        body["refresh_token"].as_s.should_not be_empty

        claims = decode.call(body["access_token"].as_s)
        claims["scope"].as_a.map(&.as_s).should eq ["public"]
        claims["u"]["e"].as_s.should eq "#{user_oid}@example.onmicrosoft.com"
        claims["aud"].as_s.should eq "localhost"

        user = ::PlaceOS::Model::User.find!(claims["sub"].as_s)
        user.name.should eq "FNU LNU"
        user.first_name.should eq "FNU"
        user.last_name.should eq "LNU"
        ::PlaceOS::Model::UserAuthLookup.find?("auth-#{authority.call.id}-oauth2-#{user_oid}").should_not be_nil
      end

      it "resolves the same user an interactive SSO login linked" do
        make_strat.call({} of String => Array(String))
        app = make_app.call(false)
        user_oid = oid.call

        existing = ::PlaceOS::Model::Generator.user(authority.call).tap(&.save!)
        lookup = ::PlaceOS::Model::UserAuthLookup.new
        lookup.uid = user_oid
        lookup.provider = "oauth2"
        lookup.authority_id = authority.call.id
        lookup.user_id = existing.id.as(String)
        lookup.save!

        result = exchange.call(app, entra_token.call({"oid" => user_oid} of String => String | Int64 | Nil, signing_key), no_extra)
        result.status_code.should eq 200
        decode.call(JSON.parse(result.body)["access_token"].as_s)["sub"].as_s.should eq existing.id
      end

      it "accepts a v2 token whose audience is the client id" do
        make_strat.call({} of String => Array(String))
        app = make_app.call(false)

        token = entra_token.call({
          "aud" => entra_client, "iss" => v2_issuer, "ver" => "2.0",
          "upn" => nil, "preferred_username" => "v2-user@example.onmicrosoft.com",
        } of String => String | Int64 | Nil, signing_key)
        result = exchange.call(app, token, no_extra)
        result.status_code.should eq 200
        decode.call(JSON.parse(result.body)["access_token"].as_s)["u"]["e"].as_s.should eq "v2-user@example.onmicrosoft.com"
      end

      it "stores a Graph token obtained on behalf of the user" do
        make_strat.call({} of String => Array(String))
        app = make_app.call(false)
        WebMock.stub(:post, token_url).to_return(
          status: 200,
          headers: HTTP::Headers{"Content-Type" => "application/json"},
          body: {access_token: "graph-access", refresh_token: "graph-refresh", token_type: "Bearer", expires_in: 3600}.to_json,
        )

        result = exchange.call(app, entra_token.call({"oid" => oid.call} of String => String | Int64 | Nil, signing_key), no_extra)
        result.status_code.should eq 200
        user = ::PlaceOS::Model::User.find!(decode.call(JSON.parse(result.body)["access_token"].as_s)["sub"].as_s)
        user.access_token.should eq "graph-access"
        user.refresh_token.should eq "graph-refresh"
      end

      it "still succeeds when the on-behalf-of request fails" do
        make_strat.call({} of String => Array(String))
        app = make_app.call(false)
        WebMock.stub(:post, token_url).to_return(status: 400, body: %({"error":"invalid_grant"}))
        result = exchange.call(app, entra_token.call({"oid" => oid.call} of String => String | Int64 | Nil, signing_key), no_extra)
        result.status_code.should eq 200
      end

      it "is advertised in the discovery document" do
        result = client.get("/.well-known/openid-configuration", headers: HTTP::Headers{"Host" => "localhost"})
        JSON.parse(result.body)["grant_types_supported"].as_a.map(&.as_s).should contain(grant)
      end
    end

    describe "refused subject tokens" do
      refused = {
        "signed by a key the tenant does not publish" => {no_override, attacker_key},
        "issued by a look-alike host"                 => { {"iss" => "https://evilmicrosoftonline.com/#{tenant}/"} of String => String | Int64 | Nil, signing_key },
        "issued by another tenant"                    => { {"iss" => "https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/", "tid" => "72f988bf-86f1-41af-91ab-2d7cd011db47"} of String => String | Int64 | Nil, signing_key },
        "whose tid disagrees with the issuer"         => { {"tid" => "72f988bf-86f1-41af-91ab-2d7cd011db47"} of String => String | Int64 | Nil, signing_key },
        "minted for Microsoft Graph"                  => { {"aud" => "00000003-0000-0000-c000-000000000000"} of String => String | Int64 | Nil, signing_key },
        "minted for another host's App ID URI"        => { {"aud" => "api://evil.example.com/#{entra_client}"} of String => String | Int64 | Nil, signing_key },
        "that is app-only (no scp)"                   => { {"scp" => nil, "roles" => "Calendars.ReadWrite"} of String => String | Int64 | Nil, signing_key },
        "that has expired"                            => { {"exp" => Time.utc.to_unix - 600} of String => String | Int64 | Nil, signing_key },
        "that has no exp"                             => { {"exp" => nil} of String => String | Int64 | Nil, signing_key },
      }

      refused.each do |label, (overrides, key)|
        it "refuses a token #{label}" do
          make_strat.call({} of String => Array(String))
          app = make_app.call(false)
          result = exchange.call(app, entra_token.call(overrides, key), no_extra)
          result.status_code.should eq 400
          JSON.parse(result.body)["error"].as_s.should eq "invalid_grant"
        end
      end

      it "refuses a token that is not a JWT" do
        make_strat.call({} of String => Array(String))
        result = exchange.call(make_app.call(false), "not-a-jwt", no_extra)
        result.status_code.should eq 400
        JSON.parse(result.body)["error"].as_s.should eq "invalid_grant"
      end

      it "refuses a multi-tenant strat, which has no tenant to pin" do
        make_strat.call({} of String => Array(String))
        strat = ::PlaceOS::Model::OAuthAuthentication.where(authority_id: authority.call.id.as(String)).first
        strat.token_url = "/common/oauth2/v2.0/token"
        strat.authorize_url = "/common/oauth2/v2.0/authorize"
        strat.save!

        result = exchange.call(make_app.call(false), entra_token.call(no_override, signing_key), no_extra)
        result.status_code.should eq 400
      end

      it "enforces the strat's ensure_matching restriction" do
        make_strat.call({"mail" => ["@placeos\\.com$"]})
        result = exchange.call(make_app.call(false), entra_token.call(no_override, signing_key), no_extra)
        result.status_code.should eq 400
        JSON.parse(result.body)["error"].as_s.should eq "invalid_grant"
      end
    end

    describe "request validation" do
      it "requires a supported subject_token_type" do
        make_strat.call({} of String => Array(String))
        result = exchange.call(make_app.call(false), entra_token.call(no_override, signing_key),
          {"subject_token_type" => "urn:ietf:params:oauth:token-type:saml2"})
        result.status_code.should eq 400
        JSON.parse(result.body)["error"].as_s.should eq "invalid_request"
      end

      it "requires a subject_token" do
        result = exchange.call(make_app.call(false), "", no_extra)
        result.status_code.should eq 400
        JSON.parse(result.body)["error"].as_s.should eq "invalid_request"
      end

      it "refuses a requested audience" do
        make_strat.call({} of String => Array(String))
        result = exchange.call(make_app.call(false), entra_token.call(no_override, signing_key), {"audience" => "https://elsewhere"})
        result.status_code.should eq 400
        JSON.parse(result.body)["error"].as_s.should eq "invalid_target"
      end

      it "authenticates a confidential client" do
        make_strat.call({} of String => Array(String))
        result = exchange.call(make_app.call(true), entra_token.call(no_override, signing_key), {"client_secret" => "wrong"})
        result.status_code.should eq 401
        JSON.parse(result.body)["error"].as_s.should eq "invalid_client"
      end
    end
  end
end
