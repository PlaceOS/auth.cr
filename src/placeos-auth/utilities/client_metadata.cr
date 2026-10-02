require "http/client"
require "json"
require "socket"
require "uri"

require "./redirect_uri"

module PlaceOS::Auth
  # OAuth Client ID Metadata Documents
  # (draft-ietf-oauth-client-id-metadata-document), the client registration
  # method preferred by the MCP authorization spec (2025-11-25).
  #
  # A client identifies itself with an `https://` URL as its `client_id`; the
  # URL serves a JSON document describing the client. No registration step and
  # no database row: the document is fetched on demand and cached.
  #
  # Fetching a client-supplied URL is an SSRF vector, so only https URLs on
  # public hosts are fetched, without following redirects, with short timeouts
  # and a small body cap. `MCP_CLIENT_ID_HOSTS` optionally restricts which hosts
  # may act as clients.
  module Utils::ClientMetadata
    extend self

    # the subset of RFC 7591 client metadata we use
    struct Document
      include JSON::Serializable

      getter client_id : String
      getter client_name : String?
      getter client_uri : String?
      getter logo_uri : String?
      getter redirect_uris : Array(String)
      getter token_endpoint_auth_method : String?

      def initialize(@client_id, @redirect_uris, @client_name = nil, @client_uri = nil, @logo_uri = nil, @token_endpoint_auth_method = nil)
      end

      # human readable name, the document host when unnamed
      def display_name : String
        client_name.presence || URI.parse(client_id).host || client_id
      end
    end

    # raised when a document can't be used, the message is logged
    class Invalid < Exception
    end

    MAX_BODY        = 10 * 1024
    MIN_TTL         = 5.minutes
    MAX_TTL         = 1.hour
    NEGATIVE_TTL    = 1.minute
    CONNECT_TIMEOUT = 3.seconds
    READ_TIMEOUT    = 5.seconds

    # optional allow-list of hosts that may serve client metadata documents
    class_property allowed_hosts : Array(String)? = ENV["MCP_CLIENT_ID_HOSTS"]?.presence.try(&.split(',').map(&.strip.downcase).reject(&.empty?))

    # fetches the document body, returning it and the cache lifetime requested
    # by the server. Replaceable in specs.
    alias Fetcher = Proc(URI, Tuple(String, Time::Span?))
    class_property fetcher : Fetcher = ->(uri : URI) { Utils::ClientMetadata.http_fetch(uri) }

    # client_id => {document (nil when invalid), expiry}
    @@cache = {} of String => Tuple(Document?, Time)
    @@lock = Mutex.new

    # is this client_id a metadata document URL?
    def client_id?(client_id : String) : Bool
      client_id.starts_with?("https://")
    end

    # returns the validated document, or nil if it can't be used
    def fetch(client_id : String) : Document?
      return unless client_id?(client_id)

      now = Time.utc
      cached = @@lock.synchronize { @@cache[client_id]? }
      return cached[0] if cached && cached[1] > now

      document = nil
      ttl = NEGATIVE_TTL
      begin
        uri = validate_url!(client_id)
        body, max_age = fetcher.call(uri)
        document = parse!(client_id, body)
        ttl = (max_age || MIN_TTL).clamp(MIN_TTL, MAX_TTL)
      rescue error
        Log.info { {message: "rejected client metadata document", client_id: client_id, reason: error.message} }
      end

      @@lock.synchronize do
        @@cache.reject! { |_key, entry| entry[1] <= now } if @@cache.size > 1_000
        @@cache[client_id] = {document, now + ttl}
      end
      document
    end

    def clear_cache : Nil
      @@lock.synchronize { @@cache.clear }
    end

    # :nodoc:
    def validate_url!(client_id : String) : URI
      uri = URI.parse(client_id)
      host = uri.host.try(&.downcase).presence
      raise Invalid.new("client_id must be an https URL") unless uri.scheme == "https" && host
      raise Invalid.new("client_id must include a path") if uri.path.empty? || uri.path == "/"
      raise Invalid.new("client_id must not include credentials or a fragment") if uri.user || uri.fragment
      raise Invalid.new("client_id must use a host name") if host == "localhost" || Socket::IPAddress.valid?(host.strip("[]"))

      if allowed = allowed_hosts
        raise Invalid.new("#{host} is not an allowed client host") unless allowed.includes?(host)
      end
      uri
    end

    # :nodoc:
    def parse!(client_id : String, body : String) : Document
      raw = JSON.parse(body).as_h? || raise Invalid.new("document is not a JSON object")
      raise Invalid.new("public clients must not have a client_secret") if raw.has_key?("client_secret")

      document = Document.from_json(body)
      raise Invalid.new("client_id does not match the document URL") unless document.client_id == client_id
      raise Invalid.new("token_endpoint_auth_method must be none") unless document.token_endpoint_auth_method.in?(nil, "none")
      raise Invalid.new("redirect_uris is required") if document.redirect_uris.empty?
      document.redirect_uris.each do |redirect|
        raise Invalid.new("redirect_uri not permitted: #{redirect}") unless Utils::RedirectURI.registrable?(redirect)
      end
      document
    rescue error : JSON::ParseException | JSON::SerializableError
      raise Invalid.new("malformed document: #{error.message}")
    end

    # :nodoc:
    def http_fetch(uri : URI) : Tuple(String, Time::Span?)
      host = uri.host.as(String)
      ensure_public_host!(host)

      client = HTTP::Client.new(uri)
      client.connect_timeout = CONNECT_TIMEOUT
      client.read_timeout = READ_TIMEOUT

      client.get(uri.request_target, headers: HTTP::Headers{"Accept" => "application/json"}) do |response|
        # redirects are not followed
        raise Invalid.new("unexpected status #{response.status_code}") unless response.status.ok?

        buffer = Bytes.new(MAX_BODY + 1)
        size = read_available(response.body_io, buffer)
        raise Invalid.new("document exceeds #{MAX_BODY} bytes") if size > MAX_BODY

        {String.new(buffer[0, size]), max_age(response.headers["Cache-Control"]?)}
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

    # refuses hosts that resolve to private, loopback or link local addresses
    private def ensure_public_host!(host : String) : Nil
      Socket::Addrinfo.resolve(host, 443, type: Socket::Type::STREAM).each do |info|
        ip = info.ip_address
        if ip.loopback? || ip.private? || ip.link_local? || ip.unspecified?
          raise Invalid.new("#{host} resolves to a non-public address")
        end
      end
    end

    private def max_age(cache_control : String?) : Time::Span?
      return unless cache_control
      if match = cache_control.match(/max-age=(\d+)/)
        match[1].to_i64.seconds
      end
    end
  end
end
