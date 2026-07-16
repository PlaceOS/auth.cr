require "authly"
require "../utilities/jwks"

module PlaceOS::Auth
  # OAuth 2.0 / OpenID Connect server endpoints. Wraps the `authly`
  # shard's library API (we don't mount `Authly::Handler` because we
  # want the legacy `/auth/...` prefix, not `/oauth/...`).
  #
  # Every endpoint is served at both the short `/auth/*` path and the
  # legacy Doorkeeper `/auth/oauth/*` mount point (stacked route
  # annotations), so the service is a drop-in for the Rails auth.
  class OAuth < Application
    base "/auth"

    # --- Response envelopes ----------------------------------------------

    # Standard OAuth token response. We don't serialise Authly's
    # `AccessToken` directly because it leaks the `sub` claim and the
    # `jti` into the public response.
    struct TokenResponse
      include JSON::Serializable

      getter access_token : String
      getter token_type : String = "Bearer"
      getter expires_in : Int64
      @[JSON::Field(emit_null: false)]
      getter refresh_token : String?
      @[JSON::Field(emit_null: false)]
      getter scope : String?
      @[JSON::Field(emit_null: false)]
      getter id_token : String?

      def initialize(at : ::Authly::AccessToken)
        @access_token = at.access_token
        @refresh_token = at.refresh_token.presence
        @id_token = at.id_token
        @scope = at.scope.presence

        # `Authly::AccessToken#expires_in` is an absolute unix timestamp
        # derived from a TTL constant captured at class-load time — before
        # our `configure!` sets the 2-hour access TTL — so it reports the
        # authly default (1 hour) and disagrees with the token's own `exp`
        # claim (which uses the live config). Report the configured TTL so
        # the relative RFC 6749 `expires_in` matches the JWT and the legacy
        # 2-hour service.
        @expires_in = ::Authly.config.access_ttl.total_seconds.to_i64
      end
    end

    # OAuth-standard error envelope (RFC 6749 §5.2). HTTP status is
    # carried separately on the response.
    struct ErrorResponse
      include JSON::Serializable

      getter error : String
      @[JSON::Field(emit_null: false)]
      getter error_description : String?

      def initialize(@error, @error_description = nil)
      end
    end

    # We need two error classes because `@[AC::Route::Exception(...)]`
    # bakes the response status in at compile time (`status_code:`).
    # OAuth's invalid_client/unauthorized_client family wants HTTP 401;
    # everything else wants 400. Two classes => two annotations.
    abstract class OAuthError < ::Exception
      getter error_code : String

      def initialize(@error_code, message : String? = nil)
        super(message || @error_code)
      end
    end

    class OAuthBadRequest < OAuthError
    end

    class OAuthUnauthorized < OAuthError
    end

    @[AC::Route::Exception(OAuthBadRequest, status_code: HTTP::Status::BAD_REQUEST)]
    def oauth_bad_request(error) : ErrorResponse
      ErrorResponse.new(error.error_code, error.message)
    end

    @[AC::Route::Exception(OAuthUnauthorized, status_code: HTTP::Status::UNAUTHORIZED)]
    def oauth_unauthorized(error) : ErrorResponse
      ErrorResponse.new(error.error_code, error.message)
    end

    # Maps an Authly typed error onto our two-variant envelope.
    private def translate_authly_error(ex : ::Authly::Error(400))
      raise OAuthBadRequest.new(ex.type.to_s, ex.message)
    end

    private def translate_authly_error(ex : ::Authly::Error(401))
      raise OAuthUnauthorized.new(ex.type.to_s, ex.message)
    end

    # --- POST /auth/token -------------------------------------------------

    # `/auth/oauth/token` is the legacy Doorkeeper mount point; kept as an
    # alias so clients that hardcode the documented path keep working.
    @[AC::Route::POST("/token")]
    @[AC::Route::POST("/oauth/token")]
    def token(
      grant_type : String,
      client_id : String,
      client_secret : String,
      code : String? = nil,
      redirect_uri : String? = nil,
      refresh_token : String? = nil,
      scope : String? = nil,
      code_verifier : String? = nil,
    ) : TokenResponse
      # Password grant is intentionally disabled (project brief, and
      # because authly's `Client.allowed_grant_type?` also rejects it,
      # but failing fast here gives a clearer error response).
      if grant_type == "password"
        raise OAuthBadRequest.new("unsupported_grant_type", "the password grant has been disabled")
      end

      access_token = case grant_type
                     when "client_credentials"
                       ::Authly.access_token(
                         grant_type: grant_type,
                         client_id: client_id,
                         client_secret: client_secret,
                         scope: scope,
                       )
                     when "authorization_code"
                       raise OAuthBadRequest.new("invalid_request", "missing code") unless code
                       raise OAuthBadRequest.new("invalid_request", "missing redirect_uri") unless redirect_uri
                       ::Authly.access_token(
                         grant_type: grant_type,
                         client_id: client_id,
                         client_secret: client_secret,
                         code: code,
                         redirect_uri: redirect_uri,
                         verifier: code_verifier || "",
                       )
                     when "refresh_token"
                       raise OAuthBadRequest.new("invalid_request", "missing refresh_token") unless refresh_token
                       ::Authly.access_token(
                         grant_type: grant_type,
                         client_id: client_id,
                         client_secret: client_secret,
                         refresh_token: refresh_token,
                       )
                     else
                       raise OAuthBadRequest.new("unsupported_grant_type", "grant_type=#{grant_type}")
                     end

      TokenResponse.new(access_token)
    rescue ex : ::Authly::Error(400)
      translate_authly_error(ex)
    rescue ex : ::Authly::Error(401)
      translate_authly_error(ex)
    end

    # --- GET|POST /auth/authorize -----------------------------------------

    # Authorization endpoint. Requires the user to be signed in via the
    # cookie session. If not, we stash the original URL on the session
    # and bounce through `/auth/login`.
    #
    # The legacy service rendered no consent screen (`skip_authorization`
    # was always true), so Doorkeeper's `POST authorize` (the consent
    # submit) issued the grant exactly as the `GET` did. Both verbs map
    # here for parity.
    @[AC::Route::GET("/authorize")]
    @[AC::Route::GET("/oauth/authorize")]
    @[AC::Route::POST("/authorize")]
    @[AC::Route::POST("/oauth/authorize")]
    def authorize(
      response_type : String,
      client_id : String,
      redirect_uri : String,
      scope : String = "",
      state : String? = nil,
      code_challenge : String? = nil,
      code_challenge_method : String? = nil,
    ) : Nil
      user = session_user
      if user.nil?
        set_continue(request.resource)
        redirect_to "/auth/login", :see_other
        return
      end

      # We only support `code` here. `token` (implicit flow) is
      # deprecated by OAuth 2.1 and the project brief dropped it
      # alongside the password grant.
      if response_type != "code"
        raise OAuthBadRequest.new("unsupported_response_type", "response_type=#{response_type}")
      end

      result = begin
        ::Authly.code(
          response_type,
          client_id,
          redirect_uri,
          scope,
          code_challenge || "",
          code_challenge_method || "",
          user.id.as(String),
        )
      rescue ex : ::Authly::Error(400)
        translate_authly_error(ex)
      rescue ex : ::Authly::Error(401)
        translate_authly_error(ex)
      end

      code = result.as(::Authly::Code).to_s
      target = String.build do |io|
        io << redirect_uri
        io << (redirect_uri.includes?('?') ? '&' : '?')
        io << "code=" << URI.encode_www_form(code)
        if (s = state.presence)
          io << "&state=" << URI.encode_www_form(s)
        end
      end

      redirect_to target, :found
    end

    # --- DELETE /auth/authorize (deny) ------------------------------------

    # The deny half of the authorization endpoint. Doorkeeper redirected
    # back to the client with `error=access_denied`. Requires a session
    # like the grant path.
    @[AC::Route::DELETE("/authorize")]
    @[AC::Route::DELETE("/oauth/authorize")]
    def deny_authorize(
      redirect_uri : String,
      response_type : String? = nil,
      state : String? = nil,
    ) : Nil
      user = session_user
      if user.nil?
        set_continue(request.resource)
        redirect_to "/auth/login", :see_other
        return
      end

      target = String.build do |io|
        io << redirect_uri
        io << (redirect_uri.includes?('?') ? '&' : '?')
        io << "error=access_denied"
        io << "&error_description=" << URI.encode_www_form(
          "The resource owner or authorization server denied the request.")
        if (s = state.presence)
          io << "&state=" << URI.encode_www_form(s)
        end
      end

      redirect_to target, :found
    end

    # --- GET /auth/authorize/native ---------------------------------------

    # Out-of-band code display. When a client's redirect_uri is the OOB
    # URN, the grant redirect lands here and the page shows the code for
    # the user to copy. No OOB clients exist in current deployments, but
    # the route is served for parity. Requires a session.
    @[AC::Route::GET("/authorize/native")]
    @[AC::Route::GET("/oauth/authorize/native")]
    def authorize_native(code : String? = nil) : Nil
      user = session_user
      if user.nil?
        set_continue(request.resource)
        redirect_to "/auth/login", :see_other
        return
      end

      shown = HTML.escape(code || "")
      render html: <<-HTML
      <!doctype html>
      <html lang="en">
      <head><meta charset="utf-8"><title>Authorization code</title></head>
      <body><h1>Authorization code:</h1>
      <code id="authorization_code">#{shown}</code>
      </body></html>
      HTML
    end

    # --- POST /auth/revoke -----------------------------------------------

    # RFC 7009 token revocation. Always responds 200, including when
    # the token is unknown / malformed / already revoked, so the
    # client can't infer state by side channel.
    @[AC::Route::POST("/revoke", status_code: HTTP::Status::OK)]
    @[AC::Route::POST("/oauth/revoke", status_code: HTTP::Status::OK)]
    def revoke(
      token : String,
      token_type_hint : String? = nil,
    ) : Nil
      ::Authly.revoke(token)
    rescue
      # Swallow — RFC says we MUST NOT signal token presence via status.
      Log.debug { {action: "oauth.revoke", message: "ignored failure (RFC 7009)"} }
    end

    # --- POST /auth/introspect (RFC 7662) --------------------------------

    # OAuth2 token introspection. The Ruby service (Doorkeeper) required
    # the *caller* to authenticate — either with client credentials
    # (HTTP Basic or `client_id`/`client_secret` params) or with a
    # different bearer access token — and only revealed a token's state
    # to the client that owns it. We reproduce that: an unauthenticated
    # introspection endpoint would leak token validity to anyone.
    struct IntrospectionResponse
      include JSON::Serializable

      getter active : Bool
      @[JSON::Field(emit_null: false)]
      getter scope : String?
      @[JSON::Field(emit_null: false)]
      getter client_id : String?
      @[JSON::Field(emit_null: false)]
      getter token_type : String?
      @[JSON::Field(emit_null: false)]
      getter iat : Int64?
      @[JSON::Field(emit_null: false)]
      getter exp : Int64?

      def self.inactive : self
        new(false)
      end

      def initialize(@active, @scope = nil, @client_id = nil, @token_type = nil, @iat = nil, @exp = nil)
      end
    end

    @[AC::Route::POST("/introspect")]
    @[AC::Route::POST("/oauth/introspect")]
    def introspect(
      token : String,
      token_type_hint : String? = nil,
    ) : IntrospectionResponse
      # Authenticate the caller; an empty client_id means a bearer-authorized
      # caller (allowed to see any token; Doorkeeper's default policy only
      # restricts client-credential callers to their own tokens).
      caller_client_id = authenticate_introspection_caller

      record = lookup_token_record(token)
      return IntrospectionResponse.inactive unless record

      token_client = record.client_id

      # Cross-client visibility: a client-credential caller may only
      # introspect its own application's tokens.
      if caller_client_id && !caller_client_id.empty? && token_client != caller_client_id
        return IntrospectionResponse.inactive
      end

      IntrospectionResponse.new(
        active: true,
        scope: record.scope.presence,
        client_id: token_client.presence,
        # `record.token_type` is the token category ("access_token"); the
        # OAuth `token_type` field is always "Bearer" here.
        token_type: "Bearer",
        iat: record.issued_at,
        exp: record.expires_at,
      )
    end

    # Looks up the persisted record for a presented access token,
    # returning nil if the token is malformed, unknown, revoked, or
    # expired. The Doorkeeper fields (client_id, resource owner, scope,
    # timestamps) come from this record, not the JWT claims — the JWT's
    # `aud` is the authority domain and it carries no client id.
    private def lookup_token_record(token : String) : ::PlaceOS::Model::OAuthToken?
      payload = begin
        decoded, _header = ::Authly.jwt_decode(token)
        decoded
      rescue
        return nil
      end

      jti = payload["jti"]?.try(&.as_s?)
      return nil unless jti

      record = ::PlaceOS::Model::OAuthToken.where(jti: jti).first?
      return nil unless record
      return nil if record.revoked?
      if (exp = record.expires_at) && Time.utc.to_unix >= exp
        return nil
      end
      record
    end

    # Returns the authenticated caller's client_id (empty string for a
    # bearer-token caller with no client), or raises 401 invalid_client.
    private def authenticate_introspection_caller : String?
      if creds = basic_auth_credentials
        client_id, client_secret = creds
      else
        client_id = params["client_id"]?
        client_secret = params["client_secret"]?
      end

      if client_id && client_secret
        unless ::Authly.clients.authorized?(client_id, client_secret)
          raise OAuthUnauthorized.new("invalid_client", "client authentication failed")
        end
        return client_id
      end

      # Fall back to bearer-token authorization of the caller.
      if bearer = acquire_token
        return "" if ::Authly.valid?(bearer)
      end

      raise OAuthUnauthorized.new("invalid_client", "client authentication failed")
    end

    private def basic_auth_credentials : {String, String}?
      header = request.headers["Authorization"]?
      return unless header && header.starts_with?("Basic ")
      decoded = begin
        Base64.decode_string(header.lchop("Basic ").strip)
      rescue
        return
      end
      client_id, _, client_secret = decoded.partition(':')
      return if client_id.empty?
      {client_id, client_secret}
    end

    private def introspection_scope_string(value : JSON::Any?) : String
      return "" unless value
      if arr = value.as_a?
        arr.map(&.as_s).join(' ')
      else
        value.as_s? || value.to_s
      end
    end

    # --- GET /auth/token/info --------------------------------------------

    # Returns metadata about the presented bearer access token, matching
    # Doorkeeper's `token_info#show` shape.
    struct TokenInfoResponse
      include JSON::Serializable

      getter resource_owner_id : String
      getter scope : Array(String)
      getter expires_in : Int64
      getter application : Application
      getter created_at : Int64

      struct Application
        include JSON::Serializable
        @[JSON::Field(emit_null: false)]
        getter uid : String?

        def initialize(@uid)
        end
      end

      def initialize(@resource_owner_id, @scope, @expires_in, uid : String?, @created_at)
        @application = Application.new(uid)
      end
    end

    @[AC::Route::GET("/token/info")]
    @[AC::Route::GET("/oauth/token/info")]
    def token_info : TokenInfoResponse
      bearer = acquire_token
      raise OAuthUnauthorized.new("invalid_token", "The access token is invalid") unless bearer

      record = lookup_token_record(bearer)
      raise OAuthUnauthorized.new("invalid_token", "The access token is invalid") unless record

      exp = record.expires_at || 0_i64
      remaining = exp - Time.utc.to_unix

      TokenInfoResponse.new(
        resource_owner_id: record.sub || "",
        scope: (record.scope || "").split(' ', remove_empty: true),
        expires_in: remaining,
        uid: record.client_id.presence,
        created_at: record.issued_at || 0_i64,
      )
    end

    # --- GET|POST /auth/userinfo -------------------------------------------

    # OIDC `userinfo`. The Bearer token's `sub` claim points at the
    # `User` row; we surface the same claim set the ID token would
    # have (see `AuthlyAdapter::Owner#id_token`).
    #
    # OIDC Core §5.3 requires both GET and POST; Doorkeeper mounted both
    # verbs, so both are served for wire parity (PPT-2536).
    @[AC::Route::GET("/userinfo")]
    @[AC::Route::GET("/oauth/userinfo")]
    @[AC::Route::POST("/userinfo")]
    @[AC::Route::POST("/oauth/userinfo")]
    def userinfo : Hash(String, String | Int64)
      user_token = authorize!
      claims = AuthlyAdapter::Owner.new.id_token(user_token.id)
      raise Error::Unauthorized.new("unknown subject") if claims.empty?
      claims
    end
  end

  # OIDC discovery document. Spec requires this lives at the root,
  # so it can't be a route on `OAuth` (which is mounted at `/auth`).
  class Discovery < Application
    base "/"

    # See `OAuth` for the rest of the OAuth2/OIDC surface area.
    struct Response
      include JSON::Serializable

      getter issuer : String
      getter authorization_endpoint : String
      getter token_endpoint : String
      getter userinfo_endpoint : String
      getter revocation_endpoint : String
      getter end_session_endpoint : String?
      getter scopes_supported : Array(String)
      getter response_types_supported : Array(String)
      getter grant_types_supported : Array(String)
      getter subject_types_supported : Array(String)
      getter id_token_signing_alg_values_supported : Array(String)
      getter token_endpoint_auth_methods_supported : Array(String)
      getter code_challenge_methods_supported : Array(String)
      getter claims_supported : Array(String)

      getter jwks_uri : String
      getter introspection_endpoint : String

      def initialize(issuer : String, logout : String? = nil)
        base = issuer.rstrip('/')
        @issuer = base
        # Advertise the legacy Doorkeeper mount points — external relying
        # parties configured against the Rails service discovered these
        # paths (all are served, the short `/auth/*` forms as aliases).
        @authorization_endpoint = "#{base}/auth/oauth/authorize"
        @token_endpoint = "#{base}/auth/oauth/token"
        @userinfo_endpoint = "#{base}/auth/oauth/userinfo"
        @revocation_endpoint = "#{base}/auth/oauth/revoke"
        @jwks_uri = "#{base}/auth/oauth/discovery/keys"
        @introspection_endpoint = "#{base}/auth/oauth/introspect"
        @end_session_endpoint = logout
        @scopes_supported = ["openid", "profile", "email", "offline_access", "public"]
        # `implicit` and `password` are intentionally absent.
        @response_types_supported = ["code"]
        @grant_types_supported = ["authorization_code", "client_credentials", "refresh_token"]
        @subject_types_supported = ["public"]
        @id_token_signing_alg_values_supported = ["RS256"]
        @token_endpoint_auth_methods_supported = ["client_secret_post"]
        @code_challenge_methods_supported = ["S256"]
        @claims_supported = ["sub", "iss", "aud", "exp", "iat", "email", "full_name", "given_name", "family_name", "nickname", "phone_number", "preferred_username"]
      end
    end

    # Rails mounted the discovery document at four paths: the two spec
    # locations at the domain root, plus `/auth/.well-known/*` variants
    # from Doorkeeper's `scope :auth` mount (RFC 8414 also aliases the
    # OIDC document as `oauth-authorization-server`). All four serve the
    # identical document for wire parity (PPT-2536).
    #
    # NOTE: at the Ruby service's locked gem versions (doorkeeper-
    # openid_connect 1.10.1) these endpoints 500 due to an issuer-block
    # arity regression; this implements the *intended* behaviour.
    @[AC::Route::GET("/.well-known/openid-configuration")]
    @[AC::Route::GET("/.well-known/oauth-authorization-server")]
    @[AC::Route::GET("/auth/.well-known/openid-configuration")]
    @[AC::Route::GET("/auth/.well-known/oauth-authorization-server")]
    def openid_configuration : Response
      authority = current_authority
      Response.new(issuer: request_issuer, logout: authority.try(&.logout_url))
    end

    # OIDC discovery §2: WebFinger. The legacy service echoed the
    # `resource` parameter back untouched with a single issuer link;
    # requests without `resource` fail with 400.
    struct WebFingerLink
      include JSON::Serializable

      getter rel : String = "http://openid.net/specs/connect/1.0/issuer"
      getter href : String

      def initialize(@href)
      end
    end

    struct WebFingerResponse
      include JSON::Serializable

      getter subject : String
      getter links : Array(WebFingerLink)

      def initialize(@subject, issuer : String)
        @links = [WebFingerLink.new(issuer)]
      end
    end

    # `resource` is taken as optional then validated by hand: the router
    # maps missing required params to 422, but Rails' ParameterMissing
    # responded 400 — parity wins (PPT-2536).
    @[AC::Route::GET("/.well-known/webfinger")]
    @[AC::Route::GET("/auth/.well-known/webfinger")]
    def webfinger(resource : String? = nil) : WebFingerResponse
      resource = resource.presence
      raise Error::BadRequest.new("param is missing or the value is empty: resource") unless resource
      WebFingerResponse.new(resource, request_issuer)
    end

    # JWKS (RFC 7517) — the verification key for our RS256 tokens, at
    # Doorkeeper-openid_connect's mount point. Derived from the same key
    # `JWT_SECRET` configures for signing.
    struct KeysResponse
      include JSON::Serializable

      getter keys : Array(JWKS::Key)

      def initialize(@keys)
      end
    end

    @[AC::Route::GET("/auth/oauth/discovery/keys")]
    def keys : KeysResponse
      KeysResponse.new([JWKS.key_for(::Authly.config.public_key)])
    end

    # Issuer per the legacy initializer's intent: scheme + request host.
    private def request_issuer : String
      scheme = request.headers["X-Forwarded-Proto"]? || (PlaceOS::Auth.production? ? "https" : "http")
      host = request.hostname || "localhost"
      "#{scheme}://#{host}"
    end
  end
end
