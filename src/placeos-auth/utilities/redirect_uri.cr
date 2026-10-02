require "uri"

module PlaceOS::Auth
  # Redirect URI matching and validation for OAuth clients.
  module Utils::RedirectURI
    extend self

    LOOPBACK_HOSTS = {"127.0.0.1", "[::1]", "::1", "localhost"}

    # schemes that must never be accepted as a redirect target
    FORBIDDEN_SCHEMES = {"javascript", "data", "file", "vbscript", "blob", "about"}

    # Does `requested` match the `registered` redirect URI?
    #
    # Exact string match, except that loopback redirects match on any port
    # (RFC 8252 §7.3): native apps, including MCP clients, listen on an
    # ephemeral port chosen at runtime.
    def match?(registered : String, requested : String) : Bool
      return true if registered == requested
      return false unless loopback?(registered) && loopback?(requested)

      expected = URI.parse(registered)
      actual = URI.parse(requested)
      expected.scheme == actual.scheme &&
        expected.host.try(&.downcase) == actual.host.try(&.downcase) &&
        expected.path == actual.path &&
        expected.query == actual.query &&
        actual.fragment.nil? && actual.user.nil?
    rescue URI::Error
      false
    end

    # `http://127.0.0.1`, `http://[::1]` and `http://localhost`, on any port
    def loopback?(uri : String) : Bool
      parsed = URI.parse(uri)
      parsed.scheme == "http" && LOOPBACK_HOSTS.includes?(parsed.host.try(&.downcase))
    rescue URI::Error
      false
    end

    # Can this URI be registered by a client that registers itself (RFC 7591
    # dynamic registration, or a client ID metadata document)?
    #
    # https, loopback http, or a private-use scheme for native apps
    # (RFC 8252 §7.1, e.g. `com.example.app:/callback`). Plain http to a
    # remote host, dangerous schemes and fragments are refused.
    def registrable?(uri : String) : Bool
      return false if uri.empty? || uri.size > 2048
      parsed = URI.parse(uri)
      scheme = parsed.scheme.try(&.downcase)
      return false unless scheme
      return false if parsed.fragment || parsed.user

      case scheme
      when "https" then !parsed.host.presence.nil?
      when "http"  then loopback?(uri)
      else
        # private-use schemes are reverse domain names (contain a dot)
        !FORBIDDEN_SCHEMES.includes?(scheme) && scheme.includes?('.')
      end
    rescue URI::Error
      false
    end
  end
end
