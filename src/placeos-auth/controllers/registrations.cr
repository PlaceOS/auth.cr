require "random/secure"

module PlaceOS::Auth
  # OAuth 2.0 Dynamic Client Registration (RFC 7591).
  #
  # Lets MCP clients (and other native or browser apps) register themselves
  # without an administrator. Only public clients are accepted: they hold no
  # secret, must use PKCE (S256) and every authorization they request is shown
  # to the user on a consent screen. Registrations are rate limited per IP.
  class Registrations < Application
    base "/auth"

    # registrations permitted per client IP per hour
    class_property limiter : Utils::RateLimiter = Utils::RateLimiter.new(10, 1.hour)

    GRANT_TYPES = {"authorization_code", "refresh_token"}

    # RFC 7591 §2 client metadata
    struct ClientMetadata
      include JSON::Serializable

      getter redirect_uris : Array(String)? = nil
      getter client_name : String? = nil
      getter token_endpoint_auth_method : String? = nil
      getter grant_types : Array(String)? = nil
      getter response_types : Array(String)? = nil
      getter scope : String? = nil

      # required by the application's form parser, registration is JSON only (RFC 7591 §3.1)
      def self.from_form(_params : URI::Params) : self
        raise InvalidRegistration.new("invalid_client_metadata", "registration requests must be application/json")
      end
    end

    # RFC 7591 §3.2.1 client information response
    struct ClientInformation
      include JSON::Serializable

      getter client_id : String
      getter client_id_issued_at : Int64
      getter client_name : String
      getter redirect_uris : Array(String)
      getter grant_types : Array(String)
      getter response_types : Array(String) = ["code"]
      getter token_endpoint_auth_method : String = "none"
      getter scope : String

      def initialize(@client_id, @client_name, @redirect_uris, @grant_types, @scope)
        @client_id_issued_at = Time.utc.to_unix
      end
    end

    # RFC 7591 §3.2.2 error response
    struct RegistrationError
      include JSON::Serializable

      getter error : String
      getter error_description : String

      def initialize(@error, @error_description)
      end
    end

    class InvalidRegistration < ::Exception
      getter error_code : String

      def initialize(@error_code, message : String)
        super(message)
      end
    end

    class TooManyRegistrations < ::Exception
    end

    @[AC::Route::Exception(InvalidRegistration, status_code: HTTP::Status::BAD_REQUEST)]
    def invalid_registration(error) : RegistrationError
      RegistrationError.new(error.error_code, error.message.as(String))
    end

    @[AC::Route::Exception(TooManyRegistrations, status_code: HTTP::Status::TOO_MANY_REQUESTS)]
    def too_many_registrations(error) : RegistrationError
      response.headers["Retry-After"] = self.class.limiter.window.total_seconds.to_i.to_s
      RegistrationError.new("too_many_requests", error.message.as(String))
    end

    # Registers a public client.
    @[AC::Route::POST("/register", body: :metadata, status_code: HTTP::Status::CREATED)]
    @[AC::Route::POST("/oauth/register", body: :metadata, status_code: HTTP::Status::CREATED)]
    def register(metadata : ClientMetadata) : ClientInformation
      raise TooManyRegistrations.new("too many client registrations, try again later") unless self.class.limiter.allow?(client_ip)

      redirect_uris = metadata.redirect_uris || [] of String
      raise InvalidRegistration.new("invalid_redirect_uri", "redirect_uris is required") if redirect_uris.empty?
      raise InvalidRegistration.new("invalid_redirect_uri", "too many redirect_uris") if redirect_uris.size > 10
      redirect_uris.each do |redirect|
        unless Utils::RedirectURI.registrable?(redirect)
          raise InvalidRegistration.new("invalid_redirect_uri", "redirect_uri must be https, loopback http or a private-use scheme: #{redirect}")
        end
      end

      unless metadata.token_endpoint_auth_method.in?(nil, "none")
        raise InvalidRegistration.new("invalid_client_metadata", "only public clients (token_endpoint_auth_method: none) may register")
      end

      grant_types = metadata.grant_types || ["authorization_code", "refresh_token"]
      unless grant_types.all?(&.in?(GRANT_TYPES))
        raise InvalidRegistration.new("invalid_client_metadata", "grant_types must be authorization_code and/or refresh_token")
      end
      unless (metadata.response_types || ["code"]).all?(&.==("code"))
        raise InvalidRegistration.new("invalid_client_metadata", "response_types must be code")
      end

      scope = metadata.scope.presence || "public"
      unless scope.split.all?(&.in?(AuthlyAdapter::Client::DEFAULT_SCOPES))
        raise InvalidRegistration.new("invalid_client_metadata", "scope must be a subset of #{AuthlyAdapter::Client::DEFAULT_SCOPES.join(' ')}")
      end

      client_name = metadata.client_name.presence.try(&.strip[0, 100]) || "MCP client"
      uid = "#{AuthlyAdapter::Client::DYNAMIC_PREFIX}#{Random::Secure.hex(16)}"

      app = ::PlaceOS::Model::DoorkeeperApplication.new
      app.uid = uid
      # names and redirect URIs are unique per owner, so each registration
      # owns itself: many users can register the same client
      app.owner_id = uid
      app.name = "#{client_name} (#{uid[-6..]})"
      app.redirect_uri = redirect_uris.join(' ')
      app.scopes = "public"
      app.confidential = false
      app.skip_authorization = false
      app.save!

      Log.info { {message: "registered a dynamic client", client_id: uid, client_name: client_name, redirect_uris: redirect_uris.join(' ')} }
      ClientInformation.new(uid, client_name, redirect_uris, grant_types, scope)
    end
  end
end
