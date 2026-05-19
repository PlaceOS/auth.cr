require "crypto/bcrypt/password"
require "placeos-models/api_key"
require "placeos-models/authority"
require "placeos-models/user"

module PlaceOS::Auth
  # Local + OAuth/SAML callback session lifecycle.
  #
  # OAuth and SAML callbacks (the `:provider/callback` routes) are
  # implemented in Phase 4 alongside the `multi_auth` + `multi_auth_saml`
  # wiring; this file currently covers `signin`, `destroy`, and `new`.
  class Sessions < Application
    base "/auth"

    # ---------- POST /auth/signin ----------------------------------------

    # Local password login. Accepts either a JSON body or
    # `application/x-www-form-urlencoded` form post — action-controller
    # picks the right parser based on `Content-Type`.
    @[AC::Route::POST("/signin", body: :body)]
    def signin(
      body : SigninBody,
    ) : Nil
      authority = current_authority
      raise Error::Unauthorized.new("authority not found") if authority.nil?

      email = body.email.strip.downcase
      user = ::PlaceOS::Model::User.find_by_email(authority.id.as(String), email)
      if user.nil?
        Log.debug { {action: "signin", reason: "user not found", authority_id: authority.id, email: email} }
        raise Error::Unauthorized.new
      end
      if user.deleted
        Log.debug { {action: "signin", reason: "user soft-deleted", user_id: user.id} }
        raise Error::Unauthorized.new
      end

      digest = user.password_digest
      if digest.nil? || digest.empty?
        Log.debug { {action: "signin", reason: "user has no password set (OAuth-only account)", user_id: user.id} }
        raise Error::Unauthorized.new
      end

      # NB: We don't go through `user.password` because the active-model
      # `attribute password : String?` macro shadows the custom
      # `def password : Password` in placeos-models — `user.password`
      # ends up returning the transient `@password` (always nil after
      # save) instead of a `Bcrypt::Password`. Reconstruct from the
      # digest directly. Bcrypt also lacks an `==(String)` overload in
      # the Crystal stdlib, so we call `verify` explicitly.
      unless Crypto::Bcrypt::Password.new(digest).verify(body.password)
        Log.debug { {action: "signin", reason: "password mismatch", user_id: user.id} }
        raise Error::Unauthorized.new
      end

      remove_session
      new_session(user)

      LoginEvents.publish(user, "internal")

      if (continue = body.continue.presence)
        target = sanitize_continue(continue) || "/"
        redirect_to target.gsub(' ', "%20"), :see_other
      else
        head :accepted
      end
    end

    struct SigninBody
      include JSON::Serializable

      getter email : String
      getter password : String
      getter continue : String? = nil

      # Build from `application/x-www-form-urlencoded` bodies too. The
      # legacy auth service is hit by browser-side login forms that
      # POST as form-encoded, not JSON.
      def self.from_form(form : URI::Params) : self
        email = form["email"]? || raise AC::Route::Param::MissingError.new("Missing required parameter", "email", "String")
        password = form["password"]? || raise AC::Route::Param::MissingError.new("Missing required parameter", "password", "String")
        new(email: email, password: password, continue: form["continue"]?)
      end

      def initialize(@email, @password, @continue = nil)
      end
    end

    # ---------- GET /auth/logout -----------------------------------------

    @[AC::Route::GET("/logout")]
    def destroy(
      @[AC::Param::Info(description: "post-logout redirect target")]
      continue : String? = nil,
    ) : Nil
      authority = current_authority
      raise Error::NotFound.new("authority not found") if authority.nil?

      if (user = session_user)
        user.logged_out_at = Time.utc
        user.save
      end
      remove_session

      # If the caller presented a Bearer JWT, revoke it through authly
      # so the JTI is marked revoked. Errors are intentionally swallowed
      # — RFC 7009 forbids leaking presence/state info.
      if (bearer = acquire_token)
        begin
          ::Authly.revoke(bearer)
        rescue ex
          Log.debug(exception: ex) { {action: "logout.revoke", message: "ignored failure (RFC 7009)"} }
        end
      end

      target = if continue && (safe = sanitize_continue(continue))
                 safe
               else
                 authority_logout_target(authority)
               end
      redirect_to target.gsub(' ', "%20"), :see_other
    end

    # ---------- GET /auth/login ------------------------------------------

    # Inline login dispatcher. Behaviour mirrors the Ruby service:
    #
    #   * if `continue` points at a non-html asset, 400 (assets must
    #     not be reached via the auth redirect dance);
    #   * if `continue` carries an `api-key` query/fragment param and
    #     the key validates, fall through to the continue target
    #     directly (asset-access cookie deferred to Phase 6);
    #   * otherwise redirect to `/auth/:provider?id=...` (when
    #     `provider` given) or to the authority's configured login URL.
    @[AC::Route::GET("/login")]
    def new(
      continue : String? = nil,
      provider : String? = nil,
      id : String? = nil,
    ) : Nil
      authority = current_authority
      raise Error::NotFound.new("authority not found") if authority.nil?

      if continue
        ext = ::File.extname(URI.parse(continue).path)
        raise Error::BadRequest.new("non-html assets must not pass through /auth/login") if !ext.empty? && ext.downcase != ".html"

        if inline_api_key_valid?(continue)
          redirect_to continue.gsub(' ', "%20"), :see_other
          return
        end
      end

      remove_session

      if (p = provider.presence) && (i = id.presence)
        set_continue(continue)
        redirect_to "/auth/#{p}?id=#{URI.encode_www_form(i)}", :see_other
        return
      end

      target = authority.login_url
      target = target.gsub("{{url}}", continue || "")
      redirect_to target.gsub(' ', "%20"), :see_other
    end

    # ---------------------------------------------------------------------

    # If the authority's `logout_url` carries a `continue=...` parameter
    # the Ruby service uses the decoded value as the *actual* redirect
    # target. Preserves that behaviour so logout pages that themselves
    # redirect onwards keep working.
    private def authority_logout_target(authority : ::PlaceOS::Model::Authority) : String
      uri = authority.logout_url
      idx = uri.index("continue=")
      return uri if idx.nil?
      raw = uri[(idx + "continue=".size)..]
      URI.decode_www_form(raw)
    end

    # Looks for `api-key` (or `x-api-key`) in `continue`'s query string
    # or fragment-as-querystring and validates it. Mirrors the Ruby
    # `new` action's inline-API-key dance.
    private def inline_api_key_valid?(continue : String) : Bool
      parsed = URI.parse(continue)

      candidates = [] of String
      if (q = parsed.query)
        candidates << q
      end
      if (frag = parsed.fragment) && (idx = frag.index('?'))
        candidates << frag[(idx + 1)..]
      end

      candidates.any? do |raw|
        params = URI::Params.parse(raw)
        token = params["api-key"]? || params["x-api-key"]?
        next false if token.nil? || token.empty?
        begin
          ::PlaceOS::Model::ApiKey.find_key!(token)
          true
        rescue
          false
        end
      end
    end
  end
end
