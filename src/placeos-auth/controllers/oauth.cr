require "authly"

module PlaceOS::Auth
  # OAuth 2.0 / OpenID Connect server endpoints. Wraps the `authly`
  # shard's library API (we don't mount `Authly::Handler` because we
  # want the legacy `/auth/...` prefix, not `/oauth/...`).
  #
  # Endpoints in this controller:
  #   * POST `/auth/token`      — token endpoint (3 grants)
  #   * GET  `/auth/authorize`  — authorization endpoint (code flow)
  #
  # Revoke / userinfo / `.well-known/openid-configuration` land in
  # Phase 3d.
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

        # `Authly::AccessToken#expires_in` is initialised to an
        # absolute unix timestamp, not the relative `expires_in` of
        # RFC 6749. Convert.
        @expires_in = (at.expires_in - Time.utc.to_unix).clamp(0_i64, Int64::MAX)
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

    @[AC::Route::POST("/token")]
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

    # --- GET /auth/authorize ----------------------------------------------

    # Authorization endpoint. Requires the user to be signed in via the
    # cookie session. If not, we stash the original URL on the session
    # and bounce through `/auth/login`.
    @[AC::Route::GET("/authorize")]
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

    # --- POST /auth/revoke -----------------------------------------------

    # RFC 7009 token revocation. Always responds 200, including when
    # the token is unknown / malformed / already revoked, so the
    # client can't infer state by side channel.
    @[AC::Route::POST("/revoke", status_code: HTTP::Status::OK)]
    def revoke(
      token : String,
      token_type_hint : String? = nil,
    ) : Nil
      ::Authly.revoke(token)
    rescue
      # Swallow — RFC says we MUST NOT signal token presence via status.
      Log.debug { {action: "oauth.revoke", message: "ignored failure (RFC 7009)"} }
    end

    # --- GET /auth/userinfo ----------------------------------------------

    # OIDC `userinfo`. The Bearer token's `sub` claim points at the
    # `User` row; we surface the same claim set the ID token would
    # have (see `AuthlyAdapter::Owner#id_token`).
    @[AC::Route::GET("/userinfo")]
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

      def initialize(issuer : String, logout : String? = nil)
        base = issuer.rstrip('/')
        @issuer = base
        @authorization_endpoint = "#{base}/auth/authorize"
        @token_endpoint = "#{base}/auth/token"
        @userinfo_endpoint = "#{base}/auth/userinfo"
        @revocation_endpoint = "#{base}/auth/revoke"
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

    @[AC::Route::GET("/.well-known/openid-configuration")]
    def openid_configuration : Response
      authority = current_authority
      scheme = request.headers["X-Forwarded-Proto"]? || (PlaceOS::Auth.production? ? "https" : "http")
      host = request.hostname || "localhost"
      issuer = "#{scheme}://#{host}"
      Response.new(issuer: issuer, logout: authority.try(&.logout_url))
    end
  end
end
