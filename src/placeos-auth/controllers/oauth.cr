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

    # Sends an unauthenticated caller to the login page with the request it
    # was making carried in `continue`, and stashed in the session for the
    # SSO callback, which does not see the query.
    private def bounce_to_login : Nil
      resource = request.resource
      set_continue(resource)
      redirect_to "/auth/login?continue=#{URI.encode_www_form(resource)}", :see_other
    end

    # --- Response envelopes ----------------------------------------------

    # Standard OAuth token response. We don't serialise Authly's
    # `AccessToken` directly because it leaks the `sub` claim and the
    # `jti` into the public response.
    struct TokenResponse
      include JSON::Serializable

      getter access_token : String
      getter token_type : String = "Bearer"
      getter expires_in : Int64
      # Unix time the token was issued. Doorkeeper sent it, and clients
      # compute expiry as `created_at + expires_in`.
      getter created_at : Int64
      @[JSON::Field(emit_null: false)]
      getter refresh_token : String?
      @[JSON::Field(emit_null: false)]
      getter scope : String?
      @[JSON::Field(emit_null: false)]
      getter id_token : String?
      # RFC 8693 §2.2.1: REQUIRED on a token-exchange response, absent otherwise.
      @[JSON::Field(emit_null: false)]
      getter issued_token_type : String?

      def initialize(at : ::Authly::AccessToken, @issued_token_type : String? = nil)
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
        @created_at = Time.utc.to_unix
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

    # RFC 6749 §5.1 / Doorkeeper's `OAuth::TokenResponse#headers`, verbatim.
    # Applied to token responses and to the OAuth error envelopes (an error
    # body can carry a `error_description` naming why a credential failed).
    protected def no_store! : Nil
      response.headers["Cache-Control"] = "no-store, no-cache"
      response.headers["Pragma"] = "no-cache"
    end

    @[AC::Route::Exception(OAuthBadRequest, status_code: HTTP::Status::BAD_REQUEST)]
    def oauth_bad_request(error) : ErrorResponse
      no_store!
      ErrorResponse.new(error.error_code, error.message)
    end

    @[AC::Route::Exception(OAuthUnauthorized, status_code: HTTP::Status::UNAUTHORIZED)]
    def oauth_unauthorized(error) : ErrorResponse
      # RFC 6750 §3 auth challenge, as Doorkeeper emitted on its 401s.
      response.headers["WWW-Authenticate"] = %(Bearer realm="Doorkeeper", error="#{error.error_code}")
      no_store!
      ErrorResponse.new(error.error_code, error.message)
    end

    # Maps an Authly typed error onto our two-variant envelope.
    private def translate_authly_error(ex : ::Authly::Error(400))
      raise OAuthBadRequest.new(ex.type.to_s, ex.message)
    end

    private def translate_authly_error(ex : ::Authly::Error(401))
      raise OAuthUnauthorized.new(ex.type.to_s, ex.message)
    end

    # RFC 7636 clients (ts-client / Backoffice, most OAuth SDKs) send the
    # S256 `code_challenge` as base64url. authly validates it against
    # Crystal's `Digest::SHA256.base64digest`, which is *standard* base64
    # (`+`/`/`, padded) — so a real browser handshake never matches and
    # every PKCE login fails with `unauthorized_client`. Normalize the
    # url-safe alphabet back to standard base64 and pad to a multiple of 4
    # so both padded and unpadded base64url challenges validate. Only S256
    # is transformed; `plain` challenges are the verifier verbatim (whose
    # RFC charset legitimately includes `-`/`_`) and must not be touched.
    private def normalize_code_challenge(challenge : String?, method : String?) : String
      value = challenge || ""
      return value unless method.try(&.upcase) == "S256"
      return value if value.empty?

      standard = value.tr("-_", "+/")
      if (remainder = standard.size % 4) != 0
        standard += "=" * (4 - remainder)
      end
      standard
    end

    # --- POST /auth/token -------------------------------------------------

    # `/auth/oauth/token` is the legacy Doorkeeper mount point; kept as an
    # alias so clients that hardcode the documented path keep working.
    @[AC::Route::POST("/token")]
    @[AC::Route::POST("/oauth/token")]
    def token(
      grant_type : String,
      client_id : String,
      # Public clients (SPAs / native apps registered with
      # `confidential: false`) cannot hold a secret — they authenticate
      # via PKCE. Doorkeeper made `client_secret` optional for them, so a
      # required param here would 422 every Backoffice token exchange
      # before any OAuth logic ran. The client adapter enforces the secret
      # only for confidential clients (see `AuthlyAdapter::Client`).
      client_secret : String? = nil,
      code : String? = nil,
      redirect_uri : String? = nil,
      refresh_token : String? = nil,
      scope : String? = nil,
      code_verifier : String? = nil,
      # RFC 8693 token exchange
      subject_token : String? = nil,
      subject_token_type : String? = nil,
      requested_token_type : String? = nil,
      audience : String? = nil,
      resource : String? = nil,
    ) : TokenResponse
      # Password grant is intentionally disabled (project brief, and
      # because authly's `Client.allowed_grant_type?` also rejects it,
      # but failing fast here gives a clearer error response).
      if grant_type == "password"
        raise OAuthBadRequest.new("unsupported_grant_type", "the password grant has been disabled")
      end

      if grant_type == Utils::EntraTokenExchange::GRANT_TYPE
        return token_exchange(client_id, client_secret, scope, subject_token, subject_token_type, requested_token_type, audience || resource)
      end

      access_token = case grant_type
                     when "client_credentials"
                       ::Authly.access_token(
                         grant_type: grant_type,
                         client_id: client_id,
                         client_secret: client_secret || "",
                         scope: scope,
                       )
                     when "authorization_code"
                       raise OAuthBadRequest.new("invalid_request", "missing code") unless code
                       raise OAuthBadRequest.new("invalid_request", "missing redirect_uri") unless redirect_uri
                       validate_resource!(resource)
                       ::Authly.access_token(
                         grant_type: grant_type,
                         client_id: client_id,
                         client_secret: client_secret || "",
                         code: code,
                         redirect_uri: redirect_uri,
                         verifier: code_verifier || "",
                       )
                     when "refresh_token"
                       raise OAuthBadRequest.new("invalid_request", "missing refresh_token") unless refresh_token
                       validate_resource!(resource)
                       ::Authly.access_token(
                         grant_type: grant_type,
                         client_id: client_id,
                         client_secret: client_secret || "",
                         refresh_token: refresh_token,
                       )
                     else
                       raise OAuthBadRequest.new("unsupported_grant_type", "grant_type=#{grant_type}")
                     end

      # RFC 6749 §5.1: a response carrying tokens MUST be `Cache-Control:
      # no-store` + `Pragma: no-cache`. Doorkeeper set both on every token
      # response (`OAuth::TokenResponse#headers` — "no-store, no-cache" and
      # "no-cache"); we set them on the OAuth *error* paths but not here, on
      # the one response that actually contains the credentials. Anything
      # between auth and the client — a corporate proxy, a service worker,
      # the browser's own back/forward cache — was free to retain a live
      # access + refresh token pair.
      no_store!
      TokenResponse.new(access_token)
    rescue ex : ::Authly::Error(400)
      translate_authly_error(ex)
    rescue ex : ::Authly::Error(401)
      translate_authly_error(ex)
    rescue ex : ::JWT::Error
      # authly decodes the submitted `code` as a JWT with no guard around it
      # (`Grant#scope` -> `auth_code` -> `jwt_decode`, and `validate_scope!`
      # runs before `authorized?` gets to reject anything), so any `code`
      # that is not a currently-valid token signed by us raised straight out
      # of the controller instead of becoming an OAuth error.
      #
      # Three ways real traffic lands here: scanner junk on the documented
      # `/auth/oauth/token` path; a code past its 10-minute expiry, which is
      # simply a user who left the tab and came back; and — the one that
      # matters for the cutover — a browser mid-login across the swap
      # posting a *Doorkeeper* code, which is an opaque random string and
      # not a JWT at all.
      #
      # Unhandled, that reached `ActionController::ErrorHandler` as a 500
      # with a stack trace attached (`SG_ENV` is unset in the real deploy,
      # so backtraces are on — CFG-02). Doorkeeper answered 400
      # `invalid_grant`, which is also what RFC 6749 §5.2 specifies for a
      # code that is invalid, expired, or was issued to another client.
      Log.info(exception: ex) { {message: "rejected an undecodable grant", action: "token", grant_type: grant_type} }
      raise OAuthBadRequest.new("invalid_grant", "the grant is invalid, expired, or was not issued by this server")
    end

    # RFC 8693 token exchange: trade a Microsoft Entra access token for a
    # PlaceOS token pair. See `Utils::EntraTokenExchange` for how the subject
    # token is verified.
    #
    # The calling `client_id` is the PlaceOS application the issued token is
    # for; it authenticates like any other grant (public clients without a
    # secret), and the user is resolved exactly as a browser SSO login
    # through the matching `oauth_strat` would resolve them.
    private def token_exchange(
      client_id : String,
      client_secret : String?,
      scope : String?,
      subject_token : String?,
      subject_token_type : String?,
      requested_token_type : String?,
      target : String?,
    ) : TokenResponse
      subject = subject_token.presence || raise OAuthBadRequest.new("invalid_request", "missing subject_token")
      unless subject_token_type.in?(Utils::EntraTokenExchange::SUBJECT_TOKEN_TYPES)
        raise OAuthBadRequest.new("invalid_request", "unsupported subject_token_type")
      end
      if requested_token_type && requested_token_type != Utils::EntraTokenExchange::TOKEN_TYPE_ACCESS_TOKEN
        raise OAuthBadRequest.new("invalid_request", "unsupported requested_token_type")
      end
      # Tokens are always issued for this authority; a different target is
      # not something we can honour.
      raise OAuthBadRequest.new("invalid_target", "audience and resource are not supported") if target

      clients = ::Authly.clients
      unless clients.authorized?(client_id, client_secret || "")
        raise OAuthUnauthorized.new("invalid_client", "client authentication failed")
      end
      unless clients.as(AuthlyAdapter::Client).allowed_grant_type?(client_id, Utils::EntraTokenExchange::GRANT_TYPE)
        raise OAuthBadRequest.new("unauthorized_client", "client may not use token exchange")
      end
      # Doorkeeper's default scope, as for every other user grant.
      granted_scope = scope.presence || "public"
      raise OAuthBadRequest.new("invalid_scope", "scope=#{granted_scope}") unless clients.allowed_scopes?(client_id, granted_scope)

      authority = current_authority
      raise OAuthBadRequest.new("invalid_request", "unknown authority") unless authority

      verified = Utils::EntraTokenExchange.verify(authority, subject)
      oauth_user = Utils::EntraTokenExchange.oauth_user(verified)

      # The strat's hosted-domain / attribute restriction applies here just
      # as it does on the browser callback.
      unless ExternalProviders.ensure_matching?(verified.strat.id, oauth_user.raw_json)
        raise Utils::EntraTokenExchange::Rejected.new("ensure_matching restriction rejected the user")
      end

      user = Utils::OAuthUserMapper.map(authority: authority, oauth_user: oauth_user).user
      Utils::EntraTokenExchange.ensure_graph_token(verified, user, subject)
      LoginEvents.record_login(user, oauth_user.provider)

      Log.info { {action: "token_exchange", message: "exchanged an Entra token", user_id: user.id, client_id: client_id, strat: verified.strat.id} }

      no_store!
      access_token = ::Authly::AccessToken.new(client_id, granted_scope, user_id: user.id.as(String))
      TokenResponse.new(access_token, issued_token_type: Utils::EntraTokenExchange::TOKEN_TYPE_ACCESS_TOKEN)
    rescue ex : Utils::EntraTokenExchange::Rejected
      Log.info { {action: "token_exchange", message: "refused a subject token", reason: ex.message, client_id: client_id} }
      raise OAuthBadRequest.new("invalid_grant", "the subject token is invalid, expired, or not accepted by this authority")
    end

    # --- GET|POST /auth/authorize -----------------------------------------

    # Authorization endpoint. Requires the user to be signed in via the
    # cookie session. If not, we stash the original URL on the session
    # and bounce through `/auth/login`.
    #
    # Clients that require consent (self registered MCP clients, and apps
    # without `skip_authorization`) are shown a consent screen; its form
    # posts back here with `consent` and a `consent_token`. Apps that skip
    # authorization are granted immediately, as the legacy service did, and
    # Doorkeeper's `POST authorize` (the consent submit) still grants for
    # them exactly as the `GET` does.
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
      # RFC 8707 resource indicator, MCP clients name the MCP server here
      resource : String? = nil,
      # consent screen submission: "allow" or "deny"
      consent : String? = nil,
      consent_token : String? = nil,
    ) : Nil
      user = session_user
      if user.nil?
        bounce_to_login
        return
      end

      # We only support `code` here. `token` (implicit flow) is
      # deprecated by OAuth 2.1 and the project brief dropped it
      # alongside the password grant.
      if response_type != "code"
        raise OAuthBadRequest.new("unsupported_response_type", "response_type=#{response_type}")
      end

      # the consent form posts every field, empty values are absent
      resource = resource.presence
      code_challenge = code_challenge.presence
      code_challenge_method = code_challenge_method.presence

      # An unknown client or unregistered redirect URI falls through to
      # `Authly.code`, which rejects it, so a consent screen is never shown
      # for (and nothing redirects to) an unverified client.
      client = ::Authly.clients.as(AuthlyAdapter::Client).client_info(client_id)
      client = nil unless client.try(&.valid_redirect?(redirect_uri))

      validate_resource!(resource) if client

      # Self registered clients are public: PKCE is the only thing standing
      # between an intercepted code and a token, so S256 is mandatory.
      if client && client.pkce_required? && !(code_challenge && code_challenge_method.try(&.upcase) == "S256")
        raise OAuthBadRequest.new("invalid_request", "this client must use PKCE with code_challenge_method=S256")
      end

      if client && client.consent_required?
        approval = {client_id, redirect_uri, scope, state || "", code_challenge || "", code_challenge_method || "", resource || ""}.to_a
        session_iat = session[Utils::SessionHelper::SESSION_IAT_KEY]?.to_s
        user_id = user.id.as(String)

        approved = request.method == "POST" && consent.in?("allow", "deny") &&
                   consent_token && Utils::Consent.valid?(consent_token, user_id, session_iat, approval)
        unless approved
          render_consent(client, user, scope, redirect_uri, {
            "response_type"         => response_type,
            "client_id"             => client_id,
            "redirect_uri"          => redirect_uri,
            "scope"                 => scope,
            "state"                 => state || "",
            "code_challenge"        => code_challenge || "",
            "code_challenge_method" => code_challenge_method || "",
            "resource"              => resource || "",
            "consent_token"         => Utils::Consent.token(user_id, session_iat, approval),
          })
          return
        end

        if consent == "deny"
          Log.info { {action: "authorize", message: "user denied consent", client_id: client_id} }
          redirect_to access_denied_url(redirect_uri, state), :found
          return
        end
        Log.info { {action: "authorize", message: "user granted consent", client_id: client_id} }
      end

      result = begin
        ::Authly.code(
          response_type,
          client_id,
          redirect_uri,
          scope,
          normalize_code_challenge(code_challenge, code_challenge_method),
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
      client_id : String,
      response_type : String? = nil,
      state : String? = nil,
    ) : Nil
      user = session_user
      if user.nil?
        bounce_to_login
        return
      end

      # Never redirect to an unregistered URI — validate it against the
      # client exactly as the grant path does, so deny can't be abused as
      # an open redirect.
      unless ::Authly.clients.valid_redirect?(client_id, redirect_uri)
        raise OAuthBadRequest.new("invalid_request", "redirect_uri is not registered for this client")
      end

      redirect_to access_denied_url(redirect_uri, state), :found
    end

    private def access_denied_url(redirect_uri : String, state : String?) : String
      String.build do |io|
        io << redirect_uri
        io << (redirect_uri.includes?('?') ? '&' : '?')
        io << "error=access_denied"
        io << "&error_description=" << URI.encode_www_form(
          "The resource owner or authorization server denied the request.")
        if (s = state.presence)
          io << "&state=" << URI.encode_www_form(s)
        end
      end
    end

    # RFC 8707: the resource must be on this authority, as every token is
    # issued for it (the token `aud` is the authority domain).
    private def validate_resource!(resource : String?) : Nil
      return unless resource = resource.presence
      uri = URI.parse(resource)
      host = uri.host.try(&.downcase)
      valid = uri.scheme.in?("https", "http") && host && host == request.hostname.try(&.downcase) && uri.fragment.nil?
      raise OAuthBadRequest.new("invalid_target", "resource must be a URL on #{request.hostname}") unless valid
    rescue URI::Error
      raise OAuthBadRequest.new("invalid_target", "resource must be a URL on #{request.hostname}")
    end

    private def render_consent(client : AuthlyAdapter::ClientInfo, user : ::PlaceOS::Model::User, scope : String, redirect_uri : String, fields : Hash(String, String)) : Nil
      client_detail = if client.metadata_document?
                        "Identified by #{URI.parse(client.client_id).host}"
                      elsif client.dynamic?
                        "Registered itself with this service"
                      else
                        "Registered by an administrator"
                      end
      scopes = scope.split.reject(&.empty?)
      scopes = ["public"] if scopes.empty?
      authority = current_authority

      response.headers["X-Frame-Options"] = "DENY"
      response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
      response.headers["Referrer-Policy"] = "no-referrer"
      no_store!
      render html: Utils::Consent.page(
        client_name: client.name,
        client_detail: client_detail,
        redirect_detail: Utils::Consent.redirect_detail(redirect_uri),
        scopes: scopes,
        account: user.email.to_s,
        tenant: authority.try(&.name) || request.hostname.to_s,
        fields: fields,
      )
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
        bounce_to_login
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

    # Identifies the authenticated introspection caller. A bearer caller
    # additionally carries its own application + token so we can reproduce
    # Doorkeeper's same-application restriction and self-introspection block.
    struct IntrospectionCaller
      getter client_id : String?
      getter bearer_jti : String?

      def initialize(@client_id, @bearer_jti = nil)
      end
    end

    @[AC::Route::POST("/introspect")]
    @[AC::Route::POST("/oauth/introspect")]
    def introspect(
      token : String,
      token_type_hint : String? = nil,
    ) : IntrospectionResponse
      introspector = authenticate_introspection_caller

      record = lookup_token_record(token)
      return IntrospectionResponse.inactive unless record

      if bearer_jti = introspector.bearer_jti
        # A bearer caller may only introspect its own application's tokens,
        # and never the token it authenticated with (Doorkeeper → 401).
        if bearer_jti == record.jti || record.client_id != introspector.client_id
          raise OAuthUnauthorized.new("invalid_token", "The access token is invalid")
        end
      elsif (caller_client = introspector.client_id) && record.client_id != caller_client
        # A client-credential caller sees another application's token as inactive.
        return IntrospectionResponse.inactive
      end

      IntrospectionResponse.new(
        active: true,
        scope: record.scope.presence,
        client_id: record.client_id.presence,
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

    # Authenticates the introspection caller (RFC 7662 §2.1): client
    # credentials via HTTP Basic or params, or a bearer access token.
    # Raises 401 invalid_client / invalid_token on bad credentials, and
    # 400 invalid_request when the request carries no credentials at all
    # (matching Doorkeeper).
    private def authenticate_introspection_caller : IntrospectionCaller
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
        return IntrospectionCaller.new(client_id)
      end

      # Bearer-token caller: identify its own application and token so the
      # same-application restriction applies to it too.
      if bearer = acquire_token
        if bearer_record = lookup_token_record(bearer)
          return IntrospectionCaller.new(bearer_record.client_id, bearer_record.jti)
        end
        raise OAuthUnauthorized.new("invalid_token", "The access token is invalid")
      end

      raise OAuthBadRequest.new("invalid_request",
        "Request needs to be authorized. Required parameter for authorizing the request is missing or invalid.")
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

      # Doorkeeper floors expires_in at 0 (a non-expiring token reports 0).
      remaining = record.expires_at.try { |exp| Math.max(0_i64, exp - Time.utc.to_unix) } || 0_i64

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

      # RFC 7591 dynamic client registration
      getter registration_endpoint : String

      # OAuth client ID metadata documents, see `Utils::ClientMetadata`
      getter client_id_metadata_document_supported : Bool = true

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
        @registration_endpoint = "#{base}/auth/oauth/register"
        @end_session_endpoint = logout
        @scopes_supported = ["openid", "profile", "email", "offline_access", "public"]
        # `implicit` and `password` are intentionally absent.
        @response_types_supported = ["code"]
        @grant_types_supported = ["authorization_code", "client_credentials", "refresh_token", Utils::EntraTokenExchange::GRANT_TYPE]
        @subject_types_supported = ["public"]
        @id_token_signing_alg_values_supported = ["RS256"]
        # `none` advertises that public clients may authenticate the token
        # endpoint with PKCE alone (no client_secret) — see the token action.
        @token_endpoint_auth_methods_supported = ["client_secret_post", "none"]
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
