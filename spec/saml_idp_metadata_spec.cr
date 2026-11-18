require "./helper"
require "timecop"

module PlaceOS::Auth
  describe Utils::SamlIdpMetadata, tags: "saml" do
    tenant = "1356bcf3-c075-43d5-a54c-ba71df07ff70"
    entra_sso = "https://login.microsoftonline.com/#{tenant}/saml2"
    entra_metadata = "https://login.microsoftonline.com/#{tenant}/federationmetadata/2007-06/federationmetadata.xml"

    fetched = [] of String
    documents = {} of String => String

    before_each do
      fetched.clear
      documents.clear
      Utils::SamlIdpMetadata.clear_cache
      Utils::SamlIdpMetadata.fetcher = ->(uri : URI) {
        fetched << uri.to_s
        documents[uri.to_s]? || raise Utils::SamlIdpMetadata::Invalid.new("unexpected status 404")
      }
    end

    after_each do
      Utils::SamlIdpMetadata.fetcher = ->(uri : URI) { Utils::SamlIdpMetadata.http_fetch(uri) }
      Utils::SamlIdpMetadata.clear_cache
    end

    signed_response = ->(signer : Symbol) {
      xml = Spec::SamlFixtures.response_xml(acs_url: "https://sp.example.test/acs", audience: "sp", email: "a@example.test")
      signer == :idp ? Spec::SamlFixtures.signed(xml) : Spec::SamlFixtures.signed_by_attacker(xml)
    }

    describe ".metadata_urls" do
      it "derives the Entra app metadata from the application id GUID in the entity id" do
        app = "bde88f02-a630-440c-a424-da054e4c4c2b"
        {"spn:#{app}", "api://#{app}", app}.each do |entity_id|
          Utils::SamlIdpMetadata.metadata_urls(entra_sso, entity_id).map(&.to_s).should eq ["#{entra_metadata}?appid=#{app}"]
        end
      end

      # Entra answers a non-GUID appid with a 400
      it "derives the Entra tenant metadata when the entity id has no GUID" do
        Utils::SamlIdpMetadata.metadata_urls(entra_sso, "https://sp.example.test/x").map(&.to_s).should eq [entra_metadata]
      end

      it "derives ADFS metadata from the same host" do
        Utils::SamlIdpMetadata.metadata_urls("https://sts.corp.example/adfs/ls/", "sp").map(&.to_s).should eq [
          "https://sts.corp.example/FederationMetadata/2007-06/FederationMetadata.xml",
        ]
      end

      it "derives Okta app metadata" do
        Utils::SamlIdpMetadata.metadata_urls("https://corp.okta.com/app/corp_placeos_1/exk1abc/sso/saml", "sp").map(&.to_s).should eq [
          "https://corp.okta.com/app/exk1abc/sso/saml/metadata",
        ]
      end

      it "derives nothing for unknown IdPs or non-https URLs" do
        Utils::SamlIdpMetadata.metadata_urls("https://accounts.google.com/o/saml2/idp?idpid=abc", "sp").should be_empty
        Utils::SamlIdpMetadata.metadata_urls("http://login.microsoftonline.com/#{tenant}/saml2", "sp").should be_empty
        Utils::SamlIdpMetadata.metadata_urls("https://login.microsoftonline.com/#{tenant}/oauth2/authorize", "sp").should be_empty
      end
    end

    describe ".parse_signing_certs" do
      it "takes IDPSSODescriptor signing certs only" do
        body = Spec::SamlFixtures.idp_metadata([Spec::SamlFixtures.idp_cert_pem], role_descriptor_cert: Spec::SamlFixtures.attacker_cert_pem)
        certs = Utils::SamlIdpMetadata.parse_signing_certs(body)
        certs.map(&.to_der).should eq [Spec::SamlFixtures.idp_certificate.to_der]
      end
    end

    describe ".trusted_cert" do
      it "returns the response's signing cert when the metadata publishes it" do
        documents[entra_metadata] = Spec::SamlFixtures.idp_metadata([Spec::SamlFixtures.attacker_cert_pem, Spec::SamlFixtures.idp_cert_pem])
        pem = Utils::SamlIdpMetadata.trusted_cert(entra_sso, "sp", signed_response.call(:idp))
        pem.should_not be_nil
        OpenSSL::X509::Certificate.new(pem.not_nil!).to_der.should eq Spec::SamlFixtures.idp_certificate.to_der
      end

      it "returns nil when the response's signing cert is not published" do
        documents[entra_metadata] = Spec::SamlFixtures.idp_metadata([Spec::SamlFixtures.idp_cert_pem])
        Utils::SamlIdpMetadata.trusted_cert(entra_sso, "sp", signed_response.call(:attacker)).should be_nil
      end

      it "returns nil when the metadata can't be fetched" do
        Utils::SamlIdpMetadata.trusted_cert(entra_sso, "sp", signed_response.call(:idp)).should be_nil
      end
    end

    describe ".certs_for" do
      it "caches the metadata" do
        documents[entra_metadata] = Spec::SamlFixtures.idp_metadata([Spec::SamlFixtures.idp_cert_pem])
        3.times { Utils::SamlIdpMetadata.trusted_cert(entra_sso, "sp", signed_response.call(:idp)).should_not be_nil }
        fetched.should eq [entra_metadata]
      end

      it "keeps serving the last good certs when a refetch fails" do
        uri = URI.parse(entra_metadata)
        documents[entra_metadata] = Spec::SamlFixtures.idp_metadata([Spec::SamlFixtures.idp_cert_pem])
        Utils::SamlIdpMetadata.certs_for(uri).size.should eq 1

        documents.clear
        Timecop.travel(2.hours.from_now) do
          Utils::SamlIdpMetadata.certs_for(uri).size.should eq 1
        end
        fetched.size.should eq 2
      end

      it "refetches when the response's cert is unknown, to pick up a rotated key" do
        uri = URI.parse(entra_metadata)
        documents[entra_metadata] = Spec::SamlFixtures.idp_metadata([Spec::SamlFixtures.attacker_cert_pem])
        Utils::SamlIdpMetadata.certs_for(uri).size.should eq 1

        documents[entra_metadata] = Spec::SamlFixtures.idp_metadata([Spec::SamlFixtures.idp_cert_pem])
        # within REFRESH_ON_MISS an unknown cert does not trigger a refetch
        Utils::SamlIdpMetadata.trusted_cert(entra_sso, "sp", signed_response.call(:idp)).should be_nil
        Timecop.travel(6.minutes.from_now) do
          Utils::SamlIdpMetadata.trusted_cert(entra_sso, "sp", signed_response.call(:idp)).should_not be_nil
        end
      end
    end
  end
end
