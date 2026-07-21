require "action-controller/session"

# ---------------------------------------------------------------------------
# Session cookie cross-site policy: SameSite=None; Secure (legacy-Ruby parity)
# ---------------------------------------------------------------------------
#
# action-controller hard-codes the encrypted session cookie to `SameSite=Lax`
# with `Secure` gated on `settings.secure`
# (lib/action-controller/src/action-controller/session.cr:88-97). That breaks
# PlaceOS's *embedded / cross-site* login.
#
# The auth UI is routinely driven from a third-party context — a portal on a
# different domain embeds the login, or an app on another origin posts to
# `/auth/signin` (see the nginx CORS allow-list for portal(-dev).placeos.run).
# In a third-party context the browser silently DROPS a `SameSite=Lax` cookie
# while keeping a `SameSite=None; Secure` one. So after a successful sign-in
# the nginx-gate `verified` cookie (already SameSite=None) survives but
# `_coauth_session` vanishes, and `GET /auth/authority` reports
# `session:false` — the SPA then bounces to SSO. First-party login is
# unaffected (Lax is satisfied), which is why it only shows up when embedded.
#
# The legacy Ruby service issued its identity cookie (`cookies.encrypted[:user]`)
# — and every other auth cookie — as `same_site: :none` precisely to support
# this topology. We restore that parity: reissue the session cookie as
# `SameSite=None; Secure`.
#
# `Secure` is mandatory for `SameSite=None` and is safe here — auth always
# runs behind HTTPS, exactly as the `verified` cookie's unconditional
# `secure: true` already assumes. The CSRF surface `Lax` would otherwise
# guard (the session-consuming OAuth `authorize`/`logout` endpoints) is
# covered by the OAuth `state` parameter + PKCE, which is why `:none` was and
# is safe for this service.
class ActionController::Session
  def encode(cookies)
    previous_def(cookies)
    if cookie = cookies[settings.key]?
      cookie.extension = nil # drop the shard's hard-coded "SameSite=Lax"
      cookie.samesite = HTTP::Cookie::SameSite::None
      cookie.secure = true # SameSite=None is invalid without Secure
    end
  end
end
