module PlaceOS::Auth
  # Mirrors `Auth::AuthoritiesController#current` from the Ruby service.
  # Doubles as a health probe: when `?health` is set on the query string
  # we always return 200 OK, so upstream load balancers can hit this
  # endpoint regardless of which host header they send.
  class Authorities < Application
    base "/auth"

    # JSON payload returned for a recognised authority. Mirrors the Ruby
    # `authority.as_json(except: [created_at, internals])` plus the
    # `session` / `token_valid` / `production` / `version` decorations.
    struct AuthorityResponse
      include JSON::Serializable

      getter id : String?
      getter name : String
      getter description : String
      getter domain : String
      getter login_url : String
      getter logout_url : String
      getter email_domains : Array(String)
      getter config : Hash(String, JSON::Any)
      getter updated_at : Time?

      getter version : String
      getter production : Bool
      getter session : Bool
      getter token_valid : Bool

      def initialize(
        authority : ::PlaceOS::Model::Authority,
        @session : Bool,
        @token_valid : Bool,
        @production : Bool,
      )
        @id = authority.id
        @name = authority.name
        @description = authority.description
        @domain = authority.domain
        @login_url = authority.login_url
        @logout_url = authority.logout_url
        @email_domains = authority.email_domains
        @config = authority.config
        @updated_at = authority.updated_at
        @version = "v#{VERSION}"
      end
    end

    @[AC::Route::GET("/authority")]
    def current(
      @[AC::Param::Info(description: "respond 200 OK without querying the database; used as a liveness probe")]
      health : String? = nil,
    ) : AuthorityResponse?
      # Liveness short-circuit BEFORE any DB access. `current_authority` runs
      # `Authority.find_by_domain`, which *raises* (not returns nil) when
      # Postgres is unreachable — a transient blip would otherwise 500 the
      # probe and risk a pod-restart storm. A `?health` caller only wants a
      # process-is-up signal, so answer 200 without touching the DB.
      return nil if health

      authority = current_authority
      raise Error::NotFound.new("authority not found for host #{request.hostname}") if authority.nil?

      session = signed_in?
      valid = token_valid?

      # Mirror Ruby `AuthoritiesController#current`: a valid Bearer token /
      # api-key authorises asset access, so (re)issue the nginx-validated
      # `verified` cookie. After `signed_in?` so a stale-session teardown
      # (remove_session → clear_asset_access) can't clobber the fresh one.
      configure_asset_access if valid

      AuthorityResponse.new(
        authority: authority,
        session: session,
        token_valid: valid,
        production: Auth.production?,
      )
    end

    # Whether the request's Bearer token (or X-API-Key) is valid.
    # Catches `Error::Unauthorized` because the Ruby version intentionally
    # treats any failure to validate as `token_valid: false` rather than
    # an error response.
    private def token_valid? : Bool
      !authorize?.nil?
    end
  end
end
