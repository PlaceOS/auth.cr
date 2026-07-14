require "multi_auth"
require "placeos-models"

require "../external_providers"

module PlaceOS::Auth
  # External-IdP round-trip handlers. Two routes per provider:
  #
  #   * GET  `/auth/:provider`            — kickoff: build redirect_uri,
  #                                         look up the strat, store the
  #                                         CSRF state, redirect to the IdP.
  #   * GET  `/auth/:provider/callback`   — consume: validate state, ask
  #                                         multi_auth to exchange code
  #                                         for user, map to a local row,
  #                                         set session, redirect home.
  #
  # The path-style alias `/auth/:provider/callback/:strategy` (used by
  # OAuth providers that don't preserve query strings) just rewrites
  # `:strategy` into the `id` param before delegating to the canonical
  # action.
  class ProviderCallbacks < Application
    base "/auth"

    SESSION_OAUTH_STATE = "oauth_state"

    @[AC::Route::Exception(::MultiAuth::Exception, status_code: HTTP::Status::BAD_REQUEST)]
    def multi_auth_error(error) : NamedTuple(error: String, error_description: String?)
      Log.warn(exception: error) { {action: "provider_callbacks", message: "multi_auth raised"} }
      {error: "invalid_request", error_description: error.message}
    end

    # ---- GET /auth/:provider ------------------------------------------

    @[AC::Route::GET("/:provider")]
    def initiate(
      provider : String,
      @[AC::Param::Info(description: "OAuth strategy id (oauth_strat primary key)")]
      id : String? = nil,
    ) : Nil
      raise Error::NotFound.new("authority not found") if current_authority.nil?

      provider_id = id
      redirect_uri = callback_uri(provider, provider_id)

      # Validate provider + strat exist before redirecting out. If the
      # caller invented a strat id we'd rather 404 here than after the
      # round-trip.
      engine = begin
        ::MultiAuth.make(provider, redirect_uri, provider_id)
      rescue ex : ::MultiAuth::Exception
        raise Error::NotFound.new(ex.message || "unknown provider")
      end

      # CSRF: random state stored on the session, echoed in the
      # authorize URL, validated on callback.
      state = Random::Secure.hex(16)
      session[SESSION_OAUTH_STATE] = "#{provider}|#{provider_id || ""}|#{state}"

      redirect_to rewrite_b2clogin_redirect(engine.authorize_uri(state: state)), :see_other
    end

    # ---- GET/POST /auth/:provider/callback ----------------------------

    @[AC::Route::GET("/:provider/callback")]
    @[AC::Route::POST("/:provider/callback")]
    def callback(
      provider : String,
      @[AC::Param::Info(description: "OAuth strategy id (oauth_strat primary key)")]
      id : String? = nil,
      state : String? = nil,
    ) : Nil
      authority = current_authority
      raise Error::NotFound.new("authority not found") if authority.nil?

      expect_state, expect_provider, expect_id = consume_stored_state
      if expect_state.nil? || state != expect_state || expect_provider != provider || expect_id != (id || "")
        Log.warn { {action: "provider_callbacks.callback", message: "state mismatch", provider: provider} }
        raise Error::Unauthorized.new("oauth state mismatch")
      end

      redirect_uri = callback_uri(provider, id)
      engine = ::MultiAuth.make(provider, redirect_uri, id)

      # `request.query_params` is `URI::Params` (Enumerable of
      # `{String, String}`) — exactly what multi_auth wants. For POST
      # callbacks (e.g. some Azure flows) we also fold in the form body.
      params = callback_params
      oauth_user = engine.user(params)

      session_user_for_link = session_user
      result = Utils::OAuthUserMapper.map(
        authority: authority,
        oauth_user: oauth_user,
        current_session_user: session_user_for_link,
      )

      # Sign in (or refresh the cookie) for branches that didn't bring
      # one in. For the "link" branch we keep the existing session.
      remove_session
      new_session(result.user)

      LoginEvents.record_login(result.user, oauth_user.provider)

      target = consume_continue || "/"
      redirect_to target.gsub(' ', "%20"), :see_other
    end

    # ---- GET/POST /auth/:provider/callback/:strategy ------------------

    # Path-style alias used by IdPs that don't preserve query strings on
    # the callback (Azure B2C in particular). Just folds `:strategy`
    # into the `id` argument before delegating.
    @[AC::Route::GET("/:provider/callback/:strategy")]
    @[AC::Route::POST("/:provider/callback/:strategy")]
    def callback_alias(
      provider : String,
      strategy : String,
      state : String? = nil,
    ) : Nil
      callback(provider: provider, id: strategy, state: state)
    end

    # ---- private helpers -----------------------------------------------

    # Builds the OAuth/SAML callback `redirect_uri`. The strategy id is
    # carried as an `?id=<id>` query param — byte-for-byte what the legacy
    # Ruby service sent (`generic_oauth#callback_url`) so the value stays
    # identical to what external IdPs already have registered, and so the
    # id round-trips back to `#callback`.
    private def callback_uri(provider : String, id : String? = nil) : String
      scheme = request.headers["X-Forwarded-Proto"]? || (PlaceOS::Auth.production? ? "https" : "http")
      host = request.hostname || "localhost"
      uri = "#{scheme}://#{host}/auth/#{provider}/callback"
      uri += "?id=#{id}" if id && !id.empty?
      uri
    end

    # Mirror the legacy `RewriteRedirectResponse` middleware. Azure AD B2C
    # won't round-trip a query string on `redirect_uri`, so the strategy
    # id is carried as a path segment instead. When the outbound authorize
    # redirect targets a `*.b2clogin.com` host, rewrite the encoded
    # `.../callback?id=<id>` to `.../callback/<id>` (the inbound path form
    # is accepted by `callback_alias`). Only the authorize redirect is
    # rewritten; the token-exchange `redirect_uri` stays in `?id=` form,
    # exactly as the Ruby service behaved.
    private def rewrite_b2clogin_redirect(authorize_uri : String) : String
      host = URI.parse(authorize_uri).host
      return authorize_uri unless host && host.ends_with?(".b2clogin.com")
      authorize_uri.gsub("%3Fid%3D", "%2F").gsub("?id=", "/")
    end

    private def consume_stored_state : Tuple(String?, String?, String?)
      raw = session.delete(SESSION_OAUTH_STATE)
      return {nil, nil, nil} unless raw.is_a?(String)
      parts = raw.split('|', 3)
      return {nil, nil, nil} unless parts.size == 3
      {parts[2], parts[0], parts[1]}
    end

    private def callback_params : URI::Params
      qp = request.query_params
      # POST callbacks: fold the form body into params (multi_auth
      # treats them the same).
      if request.method == "POST"
        params.each do |key, value|
          qp.set_all(key, params.fetch_all(key) || [value])
        end
      end
      qp
    end
  end
end
