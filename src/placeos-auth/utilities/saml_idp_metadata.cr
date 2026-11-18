require "base64"
require "crystal-saml"
require "http/client"
require "openssl"
require "uri"
require "xml"

module PlaceOS::Auth
  # Trust anchor for SAML strats configured without `idp_cert` /
  # `idp_cert_fingerprint`.
  #
  # A SAML response reaches us through the user's browser, so its signature is
  # the only proof that the IdP issued it, and that signature is only worth
  # something if we know the IdP's key independently of the response. The
  # legacy Ruby service, when no cert was configured, trusted whatever cert the
  # response embedded (`generic_adfs.rb` `DEFAULT_CERT_VALIDATOR`), so anyone
  # able to POST to the ACS could sign an assertion with their own key.
  #
  # Instead, the IdP's published SAML metadata is fetched over HTTPS and its
  # signing certs are trusted. The metadata URL is derived from the strat's
  # `idp_sso_target_url` and always lives on the same host, so this trusts
  # nothing an admin has not already trusted by configuring that URL: someone
  # able to change it could equally change `idp_cert`.
  #
  # Supported:
  #   * Microsoft Entra ID  `https://login.microsoftonline.com/<tenant>/saml2`
  #   * ADFS                `https://<host>/adfs/ls/`
  #   * Okta                `https://<host>/app/<name>/<id>/sso/saml`
  #
  # Anything else (Google Workspace publishes no metadata URL, Shibboleth has
  # no conventional path) still needs `idp_cert`, and fails closed without it.
  module Utils::SamlIdpMetadata
    extend self

    Log = ::PlaceOS::Auth::Log.for(self)

    class Invalid < Exception
    end

    # metadata documents are typically 5-100 KiB (Entra tenant metadata with
    # its WS-Fed role descriptors is the largest)
    MAX_BODY        = 1024 * 1024
    TTL             = 1.hour
    NEGATIVE_TTL    = 1.minute
    STALE_LIMIT     = 1.day
    REFRESH_ON_MISS = 5.minutes
    CONNECT_TIMEOUT = 5.seconds
    READ_TIMEOUT    = 10.seconds

    MD_NS   = "urn:oasis:names:tc:SAML:2.0:metadata"
    DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

    GUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i

    ENTRA_HOSTS = {
      "login.microsoftonline.com",
      "login.microsoftonline.us",
      "login.partner.microsoftonline.cn",
      "login.windows.net",
    }

    # fetches a metadata document body. Replaceable in specs.
    alias Fetcher = Proc(URI, String)
    class_property fetcher : Fetcher = ->(uri : URI) { Utils::SamlIdpMetadata.http_fetch(uri) }

    private record Entry,
      certs : Array(OpenSSL::X509::Certificate),
      fetched_at : Time,
      expires_at : Time

    # metadata URL => last fetch result
    @@cache = {} of String => Entry
    @@lock = Mutex.new

    def clear_cache : Nil
      @@lock.synchronize { @@cache.clear }
    end

    # Metadata URLs to try, most specific first. Empty when the SSO URL is not
    # a recognised IdP, in which case there is no trust anchor.
    def metadata_urls(sso_url : String, sp_entity_id : String? = nil) : Array(URI)
      uri = URI.parse(sso_url)
      host = uri.host.try(&.downcase).presence
      return [] of URI unless uri.scheme == "https" && host
      segments = uri.path.split('/').reject(&.empty?)
      base = "https://#{uri.authority}"

      urls = [] of String
      if ENTRA_HOSTS.includes?(host)
        # /<tenant>/saml2. With `?appid=<application id>` Entra lists just the
        # keys that app signs with: its own per-app cert (enterprise SAML
        # apps) or a subset of the tenant keys (e.g. an app registered for
        # OIDC). An unknown appid GUID gets the tenant metadata back, but a
        # non-GUID appid is a 400, so the GUID is pulled out of the entity id
        # (`spn:<guid>`, `api://<guid>`) and the plain tenant metadata used
        # when there is none.
        if (tenant = segments.first?) && segments[1]?.try(&.downcase) == "saml2"
          tenant = URI.encode_path_segment(tenant)
          tenant_metadata = "#{base}/#{tenant}/federationmetadata/2007-06/federationmetadata.xml"
          if appid = sp_entity_id.try(&.[GUID]?)
            urls << "#{tenant_metadata}?appid=#{appid}"
          else
            urls << tenant_metadata
          end
        end
      elsif segments.first?.try(&.downcase) == "adfs"
        urls << "#{base}/FederationMetadata/2007-06/FederationMetadata.xml"
      elsif segments.size == 5 && segments[0] == "app" && segments[3] == "sso" && segments[4] == "saml"
        # Okta: /app/<name>/<id>/sso/saml => /app/<id>/sso/saml/metadata
        urls << "#{base}/app/#{segments[2]}/sso/saml/metadata"
      end
      urls.map { |url| URI.parse(url) }
    rescue URI::Error
      [] of URI
    end

    # The PEM of the cert the IdP's metadata says signs `response_xml`, or nil
    # when there is no metadata trust anchor for it.
    #
    # The cert embedded in the response (`ds:KeyInfo`) only selects which of
    # the published certs to use, it is never trusted on its own. Signature
    # verification then runs against the returned cert as normal.
    def trusted_cert(sso_url : String, sp_entity_id : String?, response_xml : String) : String?
      urls = metadata_urls(sso_url, sp_entity_id)
      return if urls.empty?

      embedded = begin
        ::SAML::Utils.extract_cert_from_signature(XML.parse(response_xml))
      rescue
        nil
      end

      urls.each do |uri|
        certs = certs_for(uri, embedded)
        if embedded
          return embedded.to_pem if certs.any? { |cert| same_cert?(cert, embedded) }
        elsif certs.size == 1
          # no hint in the response, unambiguous only with a single cert
          return certs.first.to_pem
        end
      end

      Log.warn { {
        action:   "saml.metadata",
        message:  embedded ? "response signing cert is not published in the IdP metadata" : "response carries no signing cert and the IdP metadata does not identify a single one",
        metadata: urls.map(&.to_s).join(", "),
      } }
      nil
    end

    # Signing certs published at `uri`, cached. When the response's cert is not
    # among cached certs the document is refetched (at most every
    # `REFRESH_ON_MISS`), so a rotated IdP cert is picked up without waiting
    # out the TTL. A failed fetch keeps serving the last good certs for up to
    # `STALE_LIMIT`.
    def certs_for(uri : URI, embedded : OpenSSL::X509::Certificate? = nil) : Array(OpenSSL::X509::Certificate)
      key = uri.to_s
      now = Time.utc
      cached = @@lock.synchronize { @@cache[key]? }

      if cached
        fresh = cached.expires_at > now
        known = embedded.nil? || cached.certs.any? { |cert| same_cert?(cert, embedded) }
        return cached.certs if fresh && (known || now - cached.fetched_at < REFRESH_ON_MISS)
      end

      entry = begin
        certs = parse_signing_certs(fetcher.call(uri))
        raise Invalid.new("metadata lists no IdP signing certificates") if certs.empty?
        Entry.new(certs, now, now + TTL)
      rescue error
        Log.warn { {action: "saml.metadata", message: "IdP metadata fetch failed", metadata: key, reason: error.message} }
        if cached && !cached.certs.empty? && now - cached.fetched_at < STALE_LIMIT
          Entry.new(cached.certs, cached.fetched_at, now + NEGATIVE_TTL)
        else
          Entry.new([] of OpenSSL::X509::Certificate, now, now + NEGATIVE_TTL)
        end
      end

      @@lock.synchronize { @@cache[key] = entry }
      entry.certs
    end

    # Signing certs of the metadata's `IDPSSODescriptor`. Other role
    # descriptors (e.g. Entra's WS-Fed ones) are ignored.
    def parse_signing_certs(body : String) : Array(OpenSSL::X509::Certificate)
      document = XML.parse(body)
      nodes = document.xpath_nodes(
        "//md:IDPSSODescriptor/md:KeyDescriptor[not(@use) or @use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
        {"md" => MD_NS, "ds" => DSIG_NS},
      )
      certs = nodes.compact_map do |node|
        ::SAML::Utils.build_cert(node.content.gsub(/\s+/, "")) rescue nil
      end
      certs.uniq(&.to_der)
    end

    # :nodoc:
    def http_fetch(uri : URI) : String
      client = HTTP::Client.new(uri)
      client.connect_timeout = CONNECT_TIMEOUT
      client.read_timeout = READ_TIMEOUT

      client.get(uri.request_target, headers: HTTP::Headers{"Accept" => "application/samlmetadata+xml, application/xml, text/xml"}) do |response|
        # redirects are not followed: the trust argument rests on the host
        raise Invalid.new("unexpected status #{response.status_code}") unless response.status.ok?

        buffer = Bytes.new(MAX_BODY + 1)
        size = read_available(response.body_io, buffer)
        raise Invalid.new("metadata exceeds #{MAX_BODY} bytes") if size > MAX_BODY
        String.new(buffer[0, size])
      end
    ensure
      client.try &.close
    end

    private def read_available(io : IO, buffer : Bytes) : Int32
      total = 0
      while total < buffer.size
        read = io.read(buffer[total..])
        break if read.zero?
        total += read
      end
      total
    end

    private def same_cert?(a : OpenSSL::X509::Certificate, b : OpenSSL::X509::Certificate) : Bool
      a.to_der == b.to_der
    end
  end
end
