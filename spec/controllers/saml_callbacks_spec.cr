require "base64"
require "compress/deflate"

require "../helper"

module PlaceOS::Auth
  # Phase 5 — SAML smoke. Covers the kickoff (auth-request generation
  # via `multi_auth_saml`) and the strat-not-found path. The full
  # callback round-trip (SAMLResponse parsing + signature validation)
  # is covered by `multi_auth_saml`'s own spec suite against signed
  # XML fixtures; bringing those fixtures into auth.cr just to retest
  # them here would be redundant. The user-mapping branch — the part
  # that's auth.cr-specific — is shared with the OAuth path and
  # already covered by `provider_callbacks_spec.cr`.
  describe ProviderCallbacks, tags: "saml" do
    create_saml_strat = -> {
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      strat = ::PlaceOS::Model::SamlAuthentication.new
      strat.name = "test-saml-#{Random.rand(99999)}"
      strat.issuer = "https://sp.example.test/metadata"
      strat.idp_sso_target_url = "https://idp.example.test/sso"
      strat.assertion_consumer_service_url = "https://sp.example.test/auth/saml/callback"
      strat.uid_attribute = "email"
      strat.authority_id = authority.id
      strat.save!
      strat
    }

    # The legacy Ruby service registered SAML as the OmniAuth strategy
    # "adfs" (generic_adfs), so external IdP registrations, the
    # `/auth/adfs` kickoff/callback paths, and the `UserAuthLookup` id
    # (`auth-<authority>-adfs-<uid>`) all use "adfs". It also advertised
    # the DB-configured `assertion_consumer_service_url` as the ACS URL.
    # For a drop-in, auth.cr must reproduce all of that exactly.
    describe "SAML drop-in parity", tags: "saml-parity" do
      # A strat whose ACS URL is deliberately NOT what auth.cr would
      # compute from the request host, so we can prove it comes from the
      # DB column and not from `callback_uri`.
      create_adfs_strat = -> {
        authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
        strat = ::PlaceOS::Model::SamlAuthentication.new
        strat.name = "test-adfs-#{Random.rand(99999)}"
        strat.issuer = "https://sp.example.test/metadata-#{Random.rand(99999)}"
        strat.idp_sso_target_url = "https://idp.example.test/sso"
        strat.assertion_consumer_service_url = "https://prod.example.com/auth/adfs/callback?id=preconfigured"
        strat.name_identifier_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        strat.uid_attribute = "email"
        strat.authority_id = authority.id
        strat.save!
        strat
      }

      decode_saml_request = ->(location : String) {
        query = location.split('?', 2).last
        raw = URI::Params.parse(query)["SAMLRequest"]
        deflated = Base64.decode(raw)
        Compress::Deflate::Reader.open(IO::Memory.new(deflated), &.gets_to_end)
      }

      it "serves the SAML kickoff at /auth/adfs (legacy provider name)" do
        strat = create_adfs_strat.call
        result = client.get(
          "/auth/adfs?id=#{URI.encode_www_form(strat.id.as(String))}",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        result.status_code.should eq 303
        result.headers["Location"].should start_with "https://idp.example.test/sso"
      ensure
        strat.try &.destroy
      end

      it "advertises the DB assertion_consumer_service_url as the ACS URL" do
        strat = create_adfs_strat.call
        result = client.get(
          "/auth/adfs?id=#{URI.encode_www_form(strat.id.as(String))}",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        xml = decode_saml_request.call(result.headers["Location"])
        xml.should contain %(AssertionConsumerServiceURL="#{strat.assertion_consumer_service_url}")
        xml.should contain strat.issuer
      ensure
        strat.try &.destroy
      end
    end

    describe "GET /auth/saml (kickoff)" do
      it "redirects to the IdP's SSO URL with a SAMLRequest" do
        strat = create_saml_strat.call

        result = client.get(
          "/auth/saml?id=#{URI.encode_www_form(strat.id.as(String))}",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        result.status_code.should eq 303
        location = result.headers["Location"]
        location.should start_with "https://idp.example.test/sso"
        params = URI::Params.parse(location.split('?', 2).last)
        params["SAMLRequest"].should_not be_empty
        params["RelayState"].should_not be_empty
      ensure
        strat.try &.destroy
      end

      it "404s when the saml strat id is unknown" do
        result = client.get(
          "/auth/saml?id=missing-saml-strat",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        result.status_code.should eq 404
      end
    end

    # The callback's session-state CSRF check is skipped for SAML — the
    # cross-site HTTP-POST binding drops the SameSite=Lax cookie so the stashed
    # state is unavailable, and the signed assertion authenticates instead
    # (PPT-2536). It stays fully enforced for the OAuth2 path.
    describe "callback state check" do
      it "does NOT reject a SAML callback as an 'oauth state mismatch'" do
        strat = create_saml_strat.call
        # No prior kickoff => no stored session state. An OAuth2 callback would
        # 401 "oauth state mismatch" here; a SAML callback must get PAST that
        # check (and instead fail later at signed-assertion validation).
        result = client.post(
          "/auth/saml/callback?id=#{URI.encode_www_form(strat.id.as(String))}",
          headers: HTTP::Headers{
            "Host"         => "localhost",
            "Content-Type" => "application/x-www-form-urlencoded",
          },
          body: "SAMLResponse=#{URI.encode_www_form("not-a-real-assertion")}&RelayState=xyz",
        )
        result.body.should_not contain "oauth state mismatch"
      ensure
        strat.try &.destroy
      end

      it "still enforces the session-state check for an OAuth2 callback" do
        # No stored state => the OAuth2 path rejects with a state mismatch.
        result = client.get(
          "/auth/oauth2/callback?id=whatever&state=whatever",
          headers: HTTP::Headers{"Host" => "localhost"},
        )
        result.status_code.should eq 401
        result.body.should contain "oauth state mismatch"
      end
    end

    # ---- signature enforcement + continue (matrix ID-03, ID-02/SAML) ----
    #
    # The header note above says the callback round-trip is covered by
    # `multi_auth_saml`'s own suite. That holds for the LIBRARY, but not for
    # auth.cr's configuration of it, which is our code and is conditional:
    #
    #   want_assertions_signed:   strat.idp_cert.presence || fingerprint ? true : false
    #   want_signature_validated: strat.idp_cert.presence || fingerprint ? true : false
    #
    # and `crystal-saml`'s validate_signature short-circuits `return true`
    # when the document carries no <ds:Signature> at all. Whether a forged
    # assertion is rejected therefore depends on OUR strat config, so it has
    # to be pinned here. SAML is live for real clients, so this is not
    # theoretical.
    #
    # Assertions are minted fresh by `Spec::SamlFixtures` with current
    # timestamps — the shard's canned fixtures expired years ago and its own
    # specs only use them with a 10-year clock drift that auth.cr (rightly)
    # does not set.

    describe "assertion signature enforcement", tags: "saml-signature" do
      acs = "http://localhost/auth/adfs/callback"

      signed_strat = ->(with_cert : Bool) {
        authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
        strat = ::PlaceOS::Model::SamlAuthentication.new
        strat.name = "sig-saml-#{Random.rand(99999)}"
        strat.issuer = "https://sp.example.test/sig-#{Random.rand(99999)}"
        strat.idp_sso_target_url = "https://idp.example.test/sso"
        strat.assertion_consumer_service_url = acs
        strat.uid_attribute = "email"
        strat.idp_cert = Spec::SamlFixtures.idp_cert_pem if with_cert
        strat.authority_id = authority.id
        strat.save!
        strat
      }

      post_assertion = ->(strat : ::PlaceOS::Model::SamlAuthentication, saml_response : String) {
        client.post(
          "/auth/adfs/callback?id=#{URI.encode_www_form(strat.id.as(String))}",
          headers: HTTP::Headers{
            "Host"         => "localhost",
            "Content-Type" => "application/x-www-form-urlencoded",
          },
          body: "SAMLResponse=#{URI.encode_www_form(saml_response)}&RelayState=#{URI.encode_www_form("/backoffice/")}",
        )
      }

      build = ->(strat : ::PlaceOS::Model::SamlAuthentication, email : String) {
        Spec::SamlFixtures.response_xml(
          acs_url: acs,
          audience: strat.issuer.as(String),
          email: email,
        )
      }

      # A forged assertion must not establish an identity. Rejection may
      # surface as a 4xx or as a redirect to /auth/failure — both are fine.
      # What is NOT fine is a success redirect or a created UserAuthLookup.
      # On failure, report exactly what came back so the result is
      # diagnosable from CI rather than guessed at.
      reject_or_explain = ->(result : HTTP::Client::Response, email : String) {
        lookup = ::PlaceOS::Model::UserAuthLookup.where(uid: email, provider: "adfs").first?
        location = result.headers["Location"]?
        rejected = result.status_code >= 400 || location.try(&.includes?("/auth/failure")) || false

        if lookup || !rejected
          fail "FORGED ASSERTION WAS NOT REJECTED — status=#{result.status_code} " \
               "location=#{location.inspect} lookup_created=#{!lookup.nil?} " \
               "body=#{result.body[0, 200].inspect}"
        end
        lookup.should be_nil
      }

      it "accepts an assertion correctly signed by the configured IdP cert" do
        strat = signed_strat.call(true)
        email = "saml-ok-#{Random.rand(99999)}@localhost"
        xml = Spec::SamlFixtures.signed(build.call(strat, email))

        result = post_assertion.call(strat, Spec::SamlFixtures.encode(xml))

        # a genuine assertion must NOT be bounced to the failure page
        result.headers["Location"]?.try(&.includes?("/auth/failure")).should_not be_true
      ensure
        strat.try &.destroy
      end

      it "REJECTS an assertion signed by a different (attacker) keypair" do
        strat = signed_strat.call(true)
        email = "saml-attacker-#{Random.rand(99999)}@localhost"
        # well-formed XML, cryptographically valid signature — wrong signer
        xml = Spec::SamlFixtures.signed_by_attacker(build.call(strat, email))

        result = post_assertion.call(strat, Spec::SamlFixtures.encode(xml))

        # "Rejected" can legitimately be a 4xx OR a redirect to /auth/failure.
        # The load-bearing invariant is that NO identity was established.
        reject_or_explain.call(result, email)
      ensure
        strat.try &.destroy
      end

      it "REJECTS an entirely unsigned assertion when a cert is configured" do
        strat = signed_strat.call(true)
        email = "saml-unsigned-#{Random.rand(99999)}@localhost"
        # no <ds:Signature> node at all — crystal-saml's validate_signature
        # short-circuits `return true` on a missing signature, so the only
        # thing standing between this and a forged login is want_assertions_signed
        xml = build.call(strat, email)

        result = post_assertion.call(strat, Spec::SamlFixtures.encode(xml))

        reject_or_explain.call(result, email)
      ensure
        strat.try &.destroy
      end
    end
  end
end
