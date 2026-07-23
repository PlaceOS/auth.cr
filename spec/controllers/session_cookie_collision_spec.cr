require "../helper"

module PlaceOS::Auth
  # Regression for the dev-cutover lockout (PPT-2536, reported by Alex/lynner).
  #
  # The session cookie used to share the name `_coauth_session` with the legacy
  # Rails auth service, but the wire formats are incompatible (Rails
  # MessageEncryptor vs action-controller). So a Ruby-issued `_coauth_session`
  # was `InvalidSignature` to auth.cr — which (a) made `/auth/authority` report
  # no session ("No user session on authority request") and (b) stripped the
  # in-session OAuth `state`, so the SSO re-login 401'd with "oauth state
  # mismatch". And because Rails set the cookie at `Path=/` while auth.cr uses
  # `Path=/auth`, the two same-named cookies coexisted and auth.cr could never
  # overwrite the stale one — a permanent lockout, not a one-time re-prompt.
  #
  # A distinct cookie name means a stale `_coauth_session` is simply ignored
  # instead of shadowing our session. Both reported symptoms share one
  # mechanism — our session cookie being shadowed by the stale same-named one —
  # so exercising `/auth/authority` (the "no user session" symptom) covers it.
  describe "session cookie / legacy Rails collision", tags: "session-collision" do
    it "does not reuse the legacy Rails cookie name `_coauth_session`" do
      SESSION_COOKIE_NAME.should_not eq "_coauth_session"
    end

    it "recognises the session when a stale foreign `_coauth_session` is also sent" do
      authority = ::PlaceOS::Model::Authority.find_by_domain("localhost").not_nil!
      user = ::PlaceOS::Model::Generator.user(authority).tap do |u|
        u.name = "Collision User"
        u.save!
      end
      password = "collision-pw-#{Random.rand(99999)}"
      user.password = password
      user.save!

      session_cookie = Spec.signin!(client, user, password)

      # Baseline: our session cookie alone is recognised.
      base = client.get("/auth/authority", headers: HTTP::Headers{
        "Host" => "localhost", "Cookie" => session_cookie,
      })
      JSON.parse(base.body)["session"].as_bool.should be_true

      # The fix: a stale Rails `_coauth_session` (opaque to us, so it fails our
      # decode exactly like a real one) sent alongside must not break our
      # session. With a distinct name the stale cookie is a different key and is
      # ignored outright.
      #
      # NOTE: the real-world lockout came from the browser holding TWO cookies
      # named `_coauth_session` at DIFFERENT paths (Rails `/`, ours `/auth`) and
      # sending both — which a single crafted `Cookie:` header can't faithfully
      # model (the HTTP layer collapses duplicate names). That dual-path
      # scenario is verified end-to-end in a real browser on the target env;
      # this spec guards the cookie-name distinctness that makes it impossible.
      stale = "_coauth_session=BAh7CEkiD3Nlc3Npb25faWQGOgZFVEkiJWRlYWRiZWVm--stalerailssig"
      contaminated = client.get("/auth/authority", headers: HTTP::Headers{
        "Host" => "localhost", "Cookie" => "#{stale}; #{session_cookie}",
      })
      JSON.parse(contaminated.body)["session"].as_bool.should be_true
    ensure
      user.try &.destroy
    end
  end
end
