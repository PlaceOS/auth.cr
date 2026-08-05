require "base64"
require "uuid"
require "openssl"
require "xml"
require "crystal-saml"

module PlaceOS::Auth::Spec
  # Builds SAML Responses that auth.cr's real validation path will accept —
  # or reject for a specific, named reason.
  #
  # Why generate rather than use canned fixtures: `crystal-saml` ships signed
  # sample responses, but their `Conditions/NotOnOrAfter` expired years ago.
  # Its own specs work around that with `allowed_clock_drift: 10 years`, which
  # auth.cr (rightly) does not set — production defaults apply. Loosening
  # production validation to make a test pass would defeat the purpose, so
  # instead we mint a fresh assertion with current timestamps and sign it with
  # a keypair the spec controls.
  #
  # `spec/fixtures/saml/` holds two throwaway self-signed keypairs, generated
  # once with openssl and committed deliberately:
  #   * idp_*      — the "real" IdP; its cert goes on the strat as `idp_cert`
  #   * attacker_* — a DIFFERENT valid keypair, for the wrong-signer case
  #
  # Neither is a secret: they exist only to sign test XML for a disposable
  # local database.
  #
  # SAML matters here because real clients use it (UCLA), and auth.cr only
  # enforces signatures when the strat carries a cert/fingerprint:
  #
  #   want_assertions_signed:   strat.idp_cert.presence || ... ? true : false
  #   want_signature_validated: strat.idp_cert.presence || ... ? true : false
  #
  # so the tests must pin BOTH configurations.
  module SamlFixtures
    extend self

    FIXTURE_DIR = File.join(__DIR__, "..", "fixtures", "saml")

    def idp_cert_pem : String
      @@idp_cert_pem ||= File.read(File.join(FIXTURE_DIR, "idp_cert.pem"))
    end

    def idp_key : OpenSSL::PKey::RSA
      @@idp_key ||= OpenSSL::PKey::RSA.new(File.read(File.join(FIXTURE_DIR, "idp_key.pem")))
    end

    def idp_certificate : OpenSSL::X509::Certificate
      OpenSSL::X509::Certificate.new(idp_cert_pem)
    end

    def attacker_key : OpenSSL::PKey::RSA
      @@attacker_key ||= OpenSSL::PKey::RSA.new(File.read(File.join(FIXTURE_DIR, "attacker_key.pem")))
    end

    def attacker_certificate : OpenSSL::X509::Certificate
      OpenSSL::X509::Certificate.new(File.read(File.join(FIXTURE_DIR, "attacker_cert.pem")))
    end

    # A SAML 2.0 Response with CURRENT timestamps.
    #
    # `audience` must equal the strat's `issuer` (multi_auth_saml passes it as
    # `sp_entity_id`), and `destination` must equal the strat's
    # `assertion_consumer_service_url` — both are validated.
    def response_xml(
      acs_url : String,
      audience : String,
      email : String,
      idp_entity_id : String = "https://idp.example.test/metadata",
      name : String = "SAML Person",
      not_before : Time = 5.minutes.ago,
      not_on_or_after : Time = 30.minutes.from_now,
    ) : String
      resp_id = "_#{UUID.random.hexstring}"
      assertion_id = "_#{UUID.random.hexstring}"
      issued = Time.utc.to_rfc3339
      nb = not_before.to_rfc3339
      noa = not_on_or_after.to_rfc3339

      <<-XML
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="#{resp_id}" Version="2.0" IssueInstant="#{issued}" Destination="#{acs_url}">
        <saml:Issuer>#{idp_entity_id}</saml:Issuer>
        <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="#{assertion_id}" Version="2.0" IssueInstant="#{issued}">
          <saml:Issuer>#{idp_entity_id}</saml:Issuer>
          <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">#{email}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
              <saml:SubjectConfirmationData NotOnOrAfter="#{noa}" Recipient="#{acs_url}"/>
            </saml:SubjectConfirmation>
          </saml:Subject>
          <saml:Conditions NotBefore="#{nb}" NotOnOrAfter="#{noa}">
            <saml:AudienceRestriction><saml:Audience>#{audience}</saml:Audience></saml:AudienceRestriction>
          </saml:Conditions>
          <saml:AuthnStatement AuthnInstant="#{issued}" SessionIndex="#{assertion_id}">
            <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
          </saml:AuthnStatement>
          <saml:AttributeStatement>
            <saml:Attribute Name="email"><saml:AttributeValue>#{email}</saml:AttributeValue></saml:Attribute>
            <saml:Attribute Name="name"><saml:AttributeValue>#{name}</saml:AttributeValue></saml:Attribute>
          </saml:AttributeStatement>
        </saml:Assertion>
      </samlp:Response>
      XML
    end

    # Signs with the IdP key — the happy path.
    #
    # `sign_document`'s fourth argument is written verbatim into
    # `<ds:Reference URI="#...">`, and it digests the whole document, so it
    # MUST be the ID of the document root. This helper used to pass
    # `UUID.random.to_s`, producing a signature whose Reference pointed at an
    # element that does not exist — `verify_digest` could never resolve it, so
    # the "correctly signed assertion" case failed and was written off as a
    # crystal-saml bug. It is not: real callers (`auth_request.cr`,
    # `logout_request.cr`) pass the root's own `ID`. The bug was in this
    # fixture.
    def signed(xml : String, key : OpenSSL::PKey::RSA? = nil,
               certificate : OpenSSL::X509::Certificate? = nil) : String
      ::SAML::XMLSecurity.sign_document(
        xml,
        key || idp_key,
        certificate || idp_certificate,
        root_id(xml),
      )
    end

    # The `ID` of the document root, which is what a signature over the whole
    # Response must reference. Raises rather than falling back to a random
    # value: a fixture that silently signs the wrong reference produces a test
    # that looks like a library failure.
    def root_id(xml : String) : String
      root = ::XML.parse(xml).root
      raise "SAML fixture XML has no root element" if root.nil?
      id = root["ID"]?
      raise "SAML fixture root <#{root.name}> has no ID attribute" if id.nil? || id.empty?
      id
    end

    # Signed by a DIFFERENT, valid keypair. The XML is well-formed and the
    # signature is cryptographically sound — it is simply not the IdP's.
    def signed_by_attacker(xml : String) : String
      signed(xml, attacker_key, attacker_certificate)
    end

    # Ready-to-POST form value.
    def encode(xml : String) : String
      Base64.strict_encode(xml)
    end
  end
end
