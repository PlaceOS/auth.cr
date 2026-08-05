require "./helper"

module PlaceOS::Auth
  # CFG-06 — nothing sensitive reaches stdout.
  #
  # These drive `ActionController::LogHandler` directly rather than going
  # through the spec's `client`, because the spec harness dispatches straight
  # into `route_handler` and never runs the `ActionController::Server.before`
  # middleware stack — so a request made the usual way would prove nothing
  # about logging at all.
  #
  # The handler redacts only the query string of `request.resource` (see
  # `filter_path`), and matches keys by EXACT equality. Form bodies are never
  # logged, so they are not a leak path; query keys are, and each one needs
  # its own filter entry.
  describe "request log redaction (CFG-06)" do
    # Runs one request through the real handler, configured with the real
    # filter list, and returns the `path` field it logged.
    logged_path = ->(resource : String) {
      backend = ::Log::MemoryBackend.new
      ::Log.setup do |c|
        c.bind "*", :info, backend
      end

      handler = ActionController::LogHandler.new(LOG_FILTERS, ms: true)
      handler.next = ->(_ctx : HTTP::Server::Context) { }

      request = HTTP::Request.new("POST", resource)
      response = HTTP::Server::Response.new(IO::Memory.new)
      handler.call(HTTP::Server::Context.new(request, response))

      entry = backend.entries.find { |e| e.data[:event]?.to_s == "response" }
      entry.should_not be_nil
      entry.not_nil!.data[:path].to_s
    }

    it "redacts every credential-bearing query parameter" do
      secret = "SUPER-SECRET-VALUE-#{Random.rand(999_999)}"

      {
        "bearer_token", "secret", "password", "api-key", "client_secret",
        "code", "code_verifier", "token", "access_token", "refresh_token",
        "id_token", "assertion", "SAMLResponse",
      }.each do |key|
        path = logged_path.call("/auth/token?client_id=abc&#{key}=#{secret}")

        # Positive invariant: the key is still present and its value replaced.
        # Asserting only "does not include the secret" would pass if the whole
        # query string were dropped, or if the request never logged at all.
        path.should contain("#{key}=[FILTERED]")
        path.should_not contain(secret)
      end
    end

    # The regression that prompted this: `code` was filtered but
    # `code_verifier` was not, because matching is by exact key. Dev's log held
    # 37 verifiers in plaintext next to their redacted codes.
    it "redacts code_verifier alongside code, not just code" do
      path = logged_path.call(
        "/auth/oauth/token?client_id=abc&code=THE-CODE&grant_type=authorization_code&code_verifier=THE-VERIFIER"
      )

      path.should contain("code=[FILTERED]")
      path.should contain("code_verifier=[FILTERED]")
      path.should_not contain("THE-CODE")
      path.should_not contain("THE-VERIFIER")
    end

    # ts-client's `revokeToken()` issues `POST ${token_uri}?token=${token()}`,
    # so an unfiltered `token` key would write a live access token to stdout on
    # every logout.
    it "redacts the access token ts-client sends on logout" do
      path = logged_path.call("/auth/revoke?token=eyJhbGciOiJSUzI1NiJ9.LIVE-ACCESS-TOKEN.sig")

      path.should contain("token=[FILTERED]")
      path.should_not contain("LIVE-ACCESS-TOKEN")
    end

    # Redaction must not swallow the fields that make a log line useful.
    it "leaves non-sensitive parameters readable" do
      path = logged_path.call(
        "/auth/oauth/token?client_id=20e70b2a&grant_type=refresh_token&redirect_uri=https%3A%2F%2Fx.example%2Fcb&password=hunter2"
      )

      path.should contain("client_id=20e70b2a")
      path.should contain("grant_type=refresh_token")
      path.should contain("password=[FILTERED]")
      path.should_not contain("hunter2")
    end
  end
end
