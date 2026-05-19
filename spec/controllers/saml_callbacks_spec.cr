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
