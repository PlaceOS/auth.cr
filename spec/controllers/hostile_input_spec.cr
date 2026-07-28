require "../helper"

module PlaceOS::Auth
  # Hostile / malformed input (PPT-2536 test-matrix SEC-01).
  #
  # `/auth/*` is internet-facing and continuously scanned — the dev nginx logs
  # show a steady trickle of probes against `/auth/authority.php`, `.env`,
  # `.bak` and friends, riding on a REAL route prefix rather than a random
  # path (so `not_found_spec.cr`'s unmatched-path cases don't cover them).
  #
  # The bar here is deliberately low and absolute: never a 5xx, never a
  # backtrace, never a secret. A 5xx on a scanner probe is both an availability
  # signal and an information leak — and auth.cr suppresses backtraces only
  # when `SG_ENV=production`, which the delivered config does NOT set
  # (see tasks/PPT-2536/config-parity). So these must hold in dev mode too.
  describe "hostile input", tags: "security" do
    headers = HTTP::Headers{"Host" => "localhost"}
    form = HTTP::Headers{
      "Host" => "localhost", "Content-Type" => "application/x-www-form-urlencoded",
    }

    # Anything that would only ever appear in an error page / stack trace, or
    # that would be a genuine credential leak.
    leaks = ->(body : String) {
      haystack = body.downcase
      %w(
        secret_key_base cookie_session_secret jwt_secret pg_password
        password_digest backtrace /app/src/ .cr:
      ).any? { |needle| haystack.includes?(needle) }
    }

    it "survives scanner probes riding on a real route prefix" do
      # suffixes observed against /auth/authority in the dev nginx logs
      {".php", ".env", ".bak", ".json", ".old", ".txt", ".zip", ".config",
       ".aspx", "~", "%00", ".git/config", ".aws/credentials"}.each do |suffix|
        response = client.get("/auth/authority#{suffix}", headers: headers)
        response.status_code.should be < 500
        leaks.call(response.body).should be_false
      end
    end

    it "survives traversal and encoding tricks in the path" do
      {
        "/auth/../../etc/passwd",
        "/auth/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/auth/authority/../../../",
        "/auth/%00",
        "/auth/authority%0d%0aSet-Cookie:%20x=1",
      }.each do |path|
        response = client.get(path, headers: headers)
        response.status_code.should be < 500
        leaks.call(response.body).should be_false
      end
    end

    it "rejects malformed token requests with a 4xx, never a 5xx" do
      {
        "",                                      # no params at all
        "grant_type=refresh_token",              # nothing else
        "grant_type=&client_id=&refresh_token=", # empty everything
        "grant_type=wat&client_id=x",            # unknown grant
        "grant_type=refresh_token&client_id=x&refresh_token=not-a-jwt",
        "grant_type=refresh_token&client_id=x&refresh_token=a.b.c", # JWT-shaped, junk
        "grant_type=authorization_code&code=#{"A" * 8000}",         # oversized
        "grant_type[]=refresh_token&client_id[]=x",                 # array params
      }.each do |body|
        response = client.post("/auth/token", headers: form, body: body)
        response.status_code.should be >= 400
        response.status_code.should be < 500
        leaks.call(response.body).should be_false
      end
    end

    it "tolerates a wrong content-type on the token endpoint" do
      json = HTTP::Headers{"Host" => "localhost", "Content-Type" => "application/json"}
      response = client.post("/auth/token", headers: json, body: "this is not json {{{")
      response.status_code.should be < 500
      leaks.call(response.body).should be_false
    end

    it "survives junk in the authorize query string" do
      {
        "response_type=code", # no client_id
        "response_type=code&client_id=nope&redirect_uri=javascript:alert(1)",
        "response_type=&client_id=&redirect_uri=",
        "response_type=code&client_id=x&code_challenge_method=WAT&code_challenge=y",
      }.each do |query|
        response = client.get("/auth/authorize?#{query}", headers: headers)
        response.status_code.should be < 500
        leaks.call(response.body).should be_false
      end
    end

    it "never echoes a hostile redirect_uri back as a redirect target" do
      # open-redirect guard: an unregistered/hostile redirect_uri must produce
      # a non-redirectable error, never a Location pointing at the attacker.
      response = client.get(
        "/auth/authorize?response_type=code&client_id=x&redirect_uri=https://evil.example/steal",
        headers: headers)
      response.status_code.should be < 500
      response.headers["Location"]?.try(&.includes?("evil.example")).should_not be_true
    end

    it "survives a garbage bearer token on the token-introspection surfaces" do
      {"/auth/token/info", "/auth/userinfo"}.each do |path|
        response = client.get(path, headers: HTTP::Headers{
          "Host" => "localhost", "Authorization" => "Bearer not.a.real.token",
        })
        response.status_code.should be < 500
        leaks.call(response.body).should be_false
      end
    end
  end
end
