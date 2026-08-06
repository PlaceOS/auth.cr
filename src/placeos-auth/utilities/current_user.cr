require "uri"

require "placeos-models/api_key"
require "placeos-models/authority"
require "placeos-models/user"
require "placeos-models/user_jwt"

module PlaceOS::Auth
  # Resolves the request's authority + authenticated principal.
  #
  # Unlike `rest-api` we don't wire `authorize!` as a global `before_action`
  # — most auth.cr routes are intentionally unauthenticated (login forms,
  # OAuth callbacks, the OIDC `.well-known` documents). Controllers that
  # require auth call `authorize!` explicitly in a `before_action`.
  module Utils::CurrentUser
    # Returns the validated JWT for the current request.
    #
    # Precedence (mirrors the Ruby service):
    #   1. `X-API-Key` header / `api-key` query param / `api-key` cookie
    #   2. `Authorization: Bearer <jwt>` / `bearer_token` param / `bearer_token` cookie
    #
    # Raises `Error::Unauthorized` on missing or invalid credentials.
    def authorize! : ::PlaceOS::Model::UserJWT
      if token = @user_token
        return token
      end

      if api_key_token = extract_api_key
        begin
          api_key = ::PlaceOS::Model::ApiKey.find_key!(api_key_token)
          # `find_key!` only proves the secret matches the digest — it never
          # looks at `expires_at`. Without this check an expired key still
          # authenticated, and `build_jwt` stamps `exp: 1.hour.from_now`
          # unconditionally, so every call renewed itself: the expiry a
          # `ttl` was created to enforce never arrived. rest-api rejects the
          # same key here (`current-user.cr`), so the two services disagreed
          # about whether a credential was still live.
          raise Error::Unauthorized.new "API key has expired" if api_key.expired?
          user_token = api_key.build_jwt
          Log.context.set(api_key_id: api_key.id, api_key_name: api_key.name)
          ensure_matching_domain(user_token)
          @user_token = user_token
          @current_user = ::PlaceOS::Model::User.find(user_token.id)
          return user_token
        rescue e : Error::Unauthorized
          # The expiry check and `ensure_matching_domain` already raise with
          # the precise reason; the catch-all below would flatten both into
          # "unknown X-API-Key" and misdirect whoever reads the log.
          raise e
        rescue e
          Log.warn(exception: e) { {message: "bad or unknown X-API-Key", action: "authorize!"} }
          raise Error::Unauthorized.new "unknown X-API-Key"
        end
      end

      token = acquire_token
      raise Error::Unauthorized.new unless token

      begin
        user_token = ::PlaceOS::Model::UserJWT.decode(token)
        unless user_token.guest_scope?
          if (user_model = ::PlaceOS::Model::User.find(user_token.id))
            logged_out_at = user_model.logged_out_at
            raise JWT::Error.new("logged out") if logged_out_at && logged_out_at >= user_token.iat
            @current_user = user_model
          end
        end
        @user_token = user_token
      rescue e : JWT::Error
        Log.warn(exception: e) { {message: "bearer invalid", action: "authorize!"} }
        raise Error::Unauthorized.new(e.message || "bearer invalid")
      end

      ensure_matching_domain(user_token)
      user_token
    rescue e
      # leave user_token nil if anything failed so retries don't see a
      # half-populated state from this request
      @user_token = nil
      raise e
    end

    # Returns the JWT iff the request already carries valid credentials,
    # otherwise `nil`. Useful for endpoints that adapt their response
    # based on whether the caller is signed in but don't require it.
    def authorize? : ::PlaceOS::Model::UserJWT?
      authorize!
    rescue Error::Unauthorized
      nil
    end

    protected def ensure_matching_domain(user_token) : Nil
      unless authority = current_authority
        Log.warn { {message: "authority not found", action: "authorize!", host: request.hostname} }
        raise Error::Unauthorized.new "authority not found"
      end

      token_host = URI.parse(user_token.domain).host || user_token.domain
      auth_host = URI.parse(authority.domain.as(String)).host || authority.domain
      unless token_host == auth_host
        Log.warn { {message: "authority domain does not match token's", action: "authorize!", token_domain: user_token.domain, authority_domain: authority.domain} }
        raise Error::Unauthorized.new "authority domain does not match token's"
      end
    end

    @current_user : ::PlaceOS::Model::User? = nil

    # The `User` row referenced by `user_token`. Lazily loaded.
    def current_user : ::PlaceOS::Model::User
      user = @current_user
      return user if user
      @user_token || authorize!
      @current_user.as(::PlaceOS::Model::User)
    end

    # Returns the user if signed in, or `nil` (does not raise).
    def current_user? : ::PlaceOS::Model::User?
      authorize?
      @current_user
    end

    # `Authority` resolved from `request.hostname`. Lazily loaded.
    getter current_authority : ::PlaceOS::Model::Authority? do
      hostname = request.hostname
      hostname ? ::PlaceOS::Model::Authority.find_by_domain(hostname) : nil
    end

    # The validated JWT, raising if not present.
    getter user_token : ::PlaceOS::Model::UserJWT { authorize! }

    def check_admin : Nil
      raise Error::Forbidden.new unless user_admin?
    end

    def check_support : Nil
      raise Error::Forbidden.new unless user_support?
    end

    def user_admin? : Bool
      user_token.is_admin?
    end

    def user_support? : Bool
      token = user_token
      token.is_support? || token.is_admin?
    end

    # Pulls a Bearer JWT from the standard locations.
    protected def acquire_token : String?
      if header = request.headers["Authorization"]?
        token = header.lchop("Bearer ").lchop("Token ").rstrip
        return token unless token.empty?
      end
      if token = params["bearer_token"]?
        return token.strip
      end
      cookies["bearer_token"]?.try(&.value).try(&.strip)
    end

    # Pulls an `X-API-Key` from header / query / cookie.
    protected def extract_api_key : String?
      request.headers["X-API-Key"]? || params["api-key"]? || cookies["api-key"]?.try(&.value)
    end
  end
end
