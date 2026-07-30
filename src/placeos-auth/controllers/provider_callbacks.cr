require "multi_auth"
require "oauth2"
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

      authorize_uri = append_authorize_params(engine.authorize_uri(state: state), provider_id)
      redirect_to rewrite_b2clogin_redirect(authorize_uri), :see_other
    end

    # Merges an OAuth strategy's configured `authorize_params` into the
    # outbound authorize URL — e.g. Google `access_type=offline` +
    # `prompt=consent` (required to receive a refresh token) or Azure
    # `domain_hint`. multi_auth's `GenericOAuth2` has no concept of the
    # column, so the legacy Ruby service's merge is restored here (auth.cr
    # already builds + rewrites this URL). The authorize URL always carries a
    # query string (`client_id`/`redirect_uri`/`response_type` are always
    # present), so a plain `&`-append keeps the embedded `redirect_uri`
    # untouched — important because `rewrite_b2clogin_redirect` later matches
    # on it. Non-OAuth (SAML) providers have no such strat, so this no-ops.
    private def append_authorize_params(authorize_uri : String, provider_id : String?) : String
      strat = ExternalProviders.find_oauth_strat(provider_id)
      return authorize_uri if strat.nil?

      params = strat.authorize_params
      return authorize_uri if params.empty?

      extra = URI::Params.build do |form|
        params.each { |key, value| form.add(key, value) }
      end
      "#{authorize_uri}&#{extra}"
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

      # Recover the strategy id from the stored session state when the IdP
      # dropped the `?id=` query param on the callback redirect (some OAuth
      # providers don't round-trip query params on `redirect_uri`). The exact
      # id was stashed in `#initiate`, so use it rather than 401 — more precise
      # than the legacy Ruby guess (first strat / authority callback URI). A
      # present-but-mismatched id is left alone, so the state check below still
      # rejects it as CSRF.
      if (id.nil? || id.empty?) && (recovered_id = expect_id.presence)
        id = recovered_id
      end

      # SAML (adfs) uses the HTTP-POST binding and echoes our CSRF value back as
      # `RelayState`, not `state`, so the session-state check below can never
      # match a SAML callback (the `state` param is absent). The legacy Ruby
      # service (omniauth-saml) likewise never did session-state CSRF for SAML;
      # the callback was authenticated purely by the signed assertion (idp_cert
      # / idp_cert_fingerprint, want_assertions_signed). Mirror that: skip the
      # session-state check for SAML and let `engine.user` validate the
      # signature. The OAuth2 path keeps full `state` validation.
      unless saml_provider?(provider)
        if expect_state.nil? || state != expect_state || expect_provider != provider || expect_id != (id || "")
          Log.warn { {action: "provider_callbacks.callback", message: "state mismatch", provider: provider} }
          raise Error::Unauthorized.new("oauth state mismatch")
        end
      end

      # Pop the pre-login `continue` target NOW: `session_user` below can tear
      # down a stale session, and `remove_session`/`new_session` deliberately
      # clear the session store — all of which used to wipe the target stashed
      # by `/auth/login` before it was read, so every SSO login landed on "/"
      # instead of returning to the app that started it. Ruby preserved
      # `continue` across the provider round-trip; consuming it early here
      # restores that.
      continue_target = consume_continue

      redirect_uri = callback_uri(provider, id)
      engine = ::MultiAuth.make(provider, redirect_uri, id)

      # `request.query_params` is `URI::Params` (Enumerable of
      # `{String, String}`) — exactly what multi_auth wants. For POST
      # callbacks (e.g. some Azure flows) we also fold in the form body.
      params = callback_params

      # SAML assertions authenticate the callback entirely on their own, so a
      # response we cannot verify must never establish an identity.
      if saml_provider?(provider) && !saml_assertion_verifiable?(id, params)
        redirect_to "/auth/failure", :found
        return
      end

      # The provider round-trip (code->token exchange + userinfo fetch)
      # can fail for reasons outside our control: the IdP rejects the
      # code (`OAuth2::Error`), returns a non-JSON body
      # (`JSON::ParseException`), or the network drops (`IO::Error`).
      # OmniAuth bounced all of these to `/auth/failure`, so mirror that
      # rather than surfacing a 500/400 to the browser.
      begin
        oauth_user = engine.user(params)
      rescue ex : ::OAuth2::Error | JSON::ParseException | IO::Error
        Log.warn(exception: ex) { {action: "provider_callbacks.callback", message: "provider round-trip failed", provider: provider} }
        redirect_to "/auth/failure", :found
        return
      end

      # Enforce the OAuth strategy's hosted-domain / attribute restriction
      # (`ensure_matching`) against the userinfo we just fetched. The legacy
      # Ruby strategy did this in `generic_oauth#raw_info`, raising
      # "Invalid Hosted Domain" which OmniAuth turned into a `/auth/failure`
      # redirect. Without this, an authority that restricted OAuth logins to
      # a corporate domain would admit any account from the provider. SAML
      # flows share this action but have no oauth strat, so gate on the
      # oauth2 provider.
      if provider == ExternalProviders::OAUTH2_PROVIDER &&
         !ExternalProviders.ensure_matching?(id, oauth_user.raw_json)
        Log.warn { {action: "provider_callbacks.callback", message: "ensure_matching restriction rejected login", provider: provider} }
        redirect_to "/auth/failure", :found
        return
      end

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

      target = continue_target || "/"
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

    # SAML callbacks arrive on the `adfs`/`saml` provider names registered by
    # `ExternalProviders`. They cannot participate in session-state CSRF — the
    # IdP echoes the CSRF value as `RelayState`, not `state` — and are
    # authenticated by the signed assertion instead.
    private def saml_provider?(provider : String) : Bool
      provider == ExternalProviders::SAML_PROVIDER ||
        provider == ExternalProviders::SAML_PROVIDER_ALIAS
    end

    # Refuse any SAML response we cannot actually verify.
    #
    # Neither the shard stack nor our settings enforce this on their own:
    #
    #   * `crystal-saml`'s `validate_signature` does `return true` when the
    #     document contains no `<ds:Signature>` at all — an unsigned response
    #     validates.
    #   * `want_assertions_signed` is stored on the settings and used ONLY to
    #     advertise `WantAssertionsSigned="true"` in our SP metadata. Nothing
    #     reads it during response validation.
    #   * `want_signature_validated` gates the cryptographic comparison, but
    #     that code is only reached once a signature node exists, and we set it
    #     from `idp_cert.presence || idp_cert_fingerprint.presence` — so a
    #     strat with neither disables verification entirely.
    #
    # Together that meant an attacker who could POST to the ACS with a
    # self-authored, unsigned assertion was logged in as whoever they named,
    # and the user was auto-provisioned.
    #
    # The legacy Ruby service never had this hole: `ruby-saml`'s
    # `validate_signed_elements` rejects a response with zero signature nodes
    # unconditionally (`!signed_elements.empty?`), independently of
    # `want_assertions_signed`, and separately requires the *Assertion* to be
    # signed when the SP asks for it. This mirrors that, so auth.cr is at
    # least as strict as what it replaces.
    private def saml_assertion_verifiable?(provider_id : String?, params) : Bool
      strat = ExternalProviders.find_saml_strat(provider_id)
      if strat.nil?
        Log.warn { {action: "saml.verify", message: "unknown saml strategy", id: provider_id} }
        return false
      end

      # (1) Fail CLOSED with no trust anchor. Without a cert or fingerprint
      # there is nothing to check a signature against, so "accept" would mean
      # "trust anyone who can reach the ACS". Ruby's check does not depend on
      # cert presence, so refusing here keeps us no weaker than it.
      if strat.idp_cert.presence.nil? && strat.idp_cert_fingerprint.presence.nil?
        Log.warn { {action: "saml.verify", message: "saml strategy has no idp_cert or idp_cert_fingerprint — refusing to authenticate an unverifiable assertion", strat: strat.id} }
        return false
      end

      raw = params.find { |key, _| key == "SAMLResponse" }.try(&.[1])
      if raw.nil? || raw.empty?
        Log.warn { {action: "saml.verify", message: "callback carried no SAMLResponse", strat: strat.id} }
        return false
      end

      xml = begin
        String.new(Base64.decode(raw))
      rescue
        Log.warn { {action: "saml.verify", message: "SAMLResponse was not valid base64", strat: strat.id} }
        return false
      end

      document = begin
        XML.parse(xml)
      rescue
        Log.warn { {action: "saml.verify", message: "SAMLResponse was not valid XML", strat: strat.id} }
        return false
      end

      # (2) A signature must be PRESENT, and must sign the Response or the
      # Assertion — not some nested element an attacker chose. Mirrors
      # ruby-saml's `validate_signed_elements`, including its cap of at most
      # two signature nodes (Response + Assertion).
      nodes = document.xpath_nodes("//ds:Signature", {"ds" => "http://www.w3.org/2000/09/xmldsig#"})
      if nodes.empty?
        Log.warn { {action: "saml.verify", message: "SAMLResponse carried no signature — rejected", strat: strat.id} }
        return false
      end
      if nodes.size > 2
        Log.warn { {action: "saml.verify", message: "unexpected number of signature elements", count: nodes.size, strat: strat.id} }
        return false
      end
      unless nodes.all? { |node| {"Response", "Assertion"}.includes?(node.parent.try(&.name)) }
        Log.warn { {action: "saml.verify", message: "signature does not cover the Response or Assertion", strat: strat.id} }
        return false
      end

      # The cryptographic check itself still happens in `engine.user`, which
      # now genuinely runs because `want_signature_validated` is true whenever
      # we get this far (a cert or fingerprint is guaranteed present above).
      true
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
