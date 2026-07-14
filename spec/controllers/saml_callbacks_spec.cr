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
  end
end
