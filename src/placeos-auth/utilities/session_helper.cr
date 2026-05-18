require "uri"

require "placeos-models/user"

module PlaceOS::Auth
  # Cookie-session helpers for the local login flows (`/auth/signin`,
  # `/auth/logout`, `/auth/login`, and the OAuth callback).
  #
  # The session is a single encrypted cookie (`_coauth_session` at path
  # `/auth`, configured in `src/config.cr`). The flat key/value store
  # holds:
  #
  #   * `uid` — `User#id`
  #   * `exp` — unix timestamp (s) when the session is no longer valid
  #   * `iat` — issued-at in microseconds, compared against
  #             `User#logged_out_at` so a logout invalidates any cookie
  #             issued before it
  #   * `continue` — pre-login redirect target, set by `/auth/login`
  #                  and consumed by `signin` / OAuth callback
  module Utils::SessionHelper
    SESSION_UID_KEY      = "uid"
    SESSION_EXP_KEY      = "exp"
    SESSION_IAT_KEY      = "iat"
    SESSION_CONTINUE_KEY = "continue"

    # Returns the user referenced by the current session cookie, or
    # `nil` if there is no session, the session has expired, the user
    # has been deleted, or the user has logged out since the session
    # was issued. Clears the cookie in all of those negative cases.
    def session_user : ::PlaceOS::Model::User?
      sess = session
      uid = sess[SESSION_UID_KEY]?
      return nil if uid.nil?
      return remove_session_then_nil unless uid.is_a?(String)

      expires = sess[SESSION_EXP_KEY]?
      return remove_session_then_nil unless expires.is_a?(Int64)
      return remove_session_then_nil if Time.utc.to_unix > expires

      user = ::PlaceOS::Model::User.find?(uid)
      return remove_session_then_nil if user.nil?

      if (last_logout = user.logged_out_at)
        iat_usec = sess[SESSION_IAT_KEY]?
        return remove_session_then_nil unless iat_usec.is_a?(Int64)
        session_created = Time.unix_ms(iat_usec // 1000)
        return remove_session_then_nil if session_created < last_logout
      end

      user
    end

    # Has the request supplied a session cookie that resolves to a
    # valid, non-logged-out, non-deleted user?
    def signed_in? : Bool
      !session_user.nil?
    end

    # Establishes a new session for `user`. Clears any prior session
    # state first so an attacker who somehow planted stale keys can't
    # ride along.
    def new_session(user : ::PlaceOS::Model::User) : Nil
      authority = current_authority
      timeout_min = authority_session_timeout(authority)

      now = Time.utc
      iat_usec = now.to_unix * 1_000_000_i64 + (now.nanosecond // 1000).to_i64
      expires_at = (now + timeout_min.minutes).to_unix

      sess = session
      sess.clear
      sess[SESSION_UID_KEY] = user.id.as(String)
      sess[SESSION_EXP_KEY] = expires_at
      sess[SESSION_IAT_KEY] = iat_usec
    end

    # Tears down the current session and clears any cached `current_user`.
    def remove_session : Nil
      session.clear
      @current_user = nil
    end

    # Saves the (sanitised) `continue` path on the session so the
    # provider callback can redirect the user back to where they
    # started. Silently no-ops on `nil` to keep call sites tidy.
    def set_continue(path : String?) : Nil
      return if path.nil?
      session[SESSION_CONTINUE_KEY] = sanitize_continue(path)
    end

    # Pops the stored `continue` path off the session and returns it.
    def consume_continue : String?
      sess = session
      stored = sess.delete(SESSION_CONTINUE_KEY)
      stored.is_a?(String) ? stored : nil
    end

    # Strips external-URL components from a `continue` target so we
    # only ever redirect within the current authority's host.
    #
    # Mirrors the Ruby `redirect_continue` open-redirect guard:
    #
    #   * relative path (starts with `/`, no `//`) → returned as-is
    #   * absolute URL matching the authority's host → reduced to
    #     `path?query#fragment`
    #   * anything else → `nil`, leaving the caller free to pick a
    #     fallback (typically `authority.logout_url` or `"/"`)
    def sanitize_continue(path : String) : String?
      check_path = path.split('?', 2)[0]
      return path if check_path.starts_with?('/') && !check_path.includes?("//")

      uri = URI.parse(path)
      authority_host = current_authority.try(&.domain)
      return nil unless uri.host && authority_host && uri.host == authority_host

      String.build do |io|
        io << (uri.path.empty? ? "/" : uri.path)
        io << '?' << uri.query if uri.query
        io << '#' << uri.fragment if uri.fragment
      end
    end

    # `Authority#internals["session_timeout"]` overrides the default
    # `SESSION_TIMEOUT_MINUTES` from the env.
    private def authority_session_timeout(authority : ::PlaceOS::Model::Authority?) : Int32
      override = authority.try(&.internals["session_timeout"]?)
      return SESSION_TIMEOUT_MINUTES if override.nil?
      case raw = override.raw
      when Int64, Int32 then raw.to_i
      when String       then raw.to_i? || SESSION_TIMEOUT_MINUTES
      else                   SESSION_TIMEOUT_MINUTES
      end
    end

    private def remove_session_then_nil : Nil
      remove_session
      nil
    end
  end
end
