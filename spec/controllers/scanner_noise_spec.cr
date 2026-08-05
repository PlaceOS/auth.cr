require "../helper"

module PlaceOS::Auth
  # SEC-01 — hostile/scanner traffic must answer 4xx, never 5xx, and never
  # disclose anything.
  #
  # The paths below are NOT invented. They are the real request lines the dev
  # server's nginx recorded over 30 days, taken verbatim (`docker logs nginx`,
  # counts as observed):
  #
  #     100  /.env
  #      40  /wp-content/plugins/hellopress/wp_filemanager.php
  #      37  /this_is_a_new_hello_world.php
  #      32  /1.php          30  /222.php        26  /file5.php
  #      26  /8.php          23  /ops.php        22  /media.php
  #      22  /.git/config    19  /wp-ws68.php?p=
  #      19  /classwithtostring.php?p=
  #
  # Two invariants matter, and they are different:
  #
  #   * **Never 5xx.** A 500 on hostile input means an unhandled exception
  #     reached the router, which is both a liveness risk under sustained
  #     scanning and an information leak (auth.cr runs `ErrorHandler` in
  #     verbose mode whenever SG_ENV is not "production" — and CFG-03 found
  #     SG_ENV is delivered by no surface, so that is the live configuration).
  #   * **Never disclose.** No backtrace, no source path, no framework
  #     version, no environment variable, no SQL.
  describe "scanner noise (SEC-01)", tags: "security" do
    headers = HTTP::Headers{"Host" => "localhost"}

    # Verbatim from the nginx log, plus the /auth-prefixed variants — auth.cr
    # only ever sees paths nginx routes to it, so both shapes are fair game.
    observed = [
      "/.env",
      "/.git/config",
      "/1.php",
      "/222.php",
      "/8.php",
      "/file5.php",
      "/ops.php",
      "/media.php",
      "/mac.php",
      "/images.php",
      "/this_is_a_new_hello_world.php",
      "/wp-content/plugins/hellopress/wp_filemanager.php",
      "/wp-content/uploads/",
      "/wp-ws68.php?p=",
      "/classwithtostring.php?p=",
      "/auth/.env",
      "/auth/.git/config",
      "/auth/authority.php",
      "/auth/authority.json",
      "/auth/authority.bak",
      "/auth/does-not-exist",
    ]

    # Strings that must never appear in a response to any of the above.
    # `.cr:` catches a Crystal backtrace frame; `/app/` and `/usr/share/`
    # catch source paths baked into the image.
    leaks = [
      ".cr:",
      "/app/",
      "/usr/share/crystal",
      "Traceback",
      "JWT_SECRET",
      "SECRET_KEY_BASE",
      "PG_DATABASE_URL",
      "postgresql://",
      "SELECT ",
    ]

    it "answers every observed scanner path with a 4xx and no disclosure" do
      observed.each do |path|
        result = client.get(path, headers: headers)

        # Positive invariant, stated as a range rather than "not 500" so a
        # 2xx (which would mean we SERVED something) fails too.
        unless (400..499).includes?(result.status_code)
          fail "#{path} answered #{result.status_code} — expected 4xx (5xx = unhandled exception, 2xx = disclosure)"
        end

        body = result.body
        leaks.each do |needle|
          if body.includes?(needle)
            fail "#{path} leaked #{needle.inspect} in its body: #{body[0, 300].inspect}"
          end
        end
      end
    end

    # Same table, non-GET. Scanners probe with POST for upload endpoints, and
    # an unmatched verb is a different code path through the router.
    it "answers scanner paths on write verbs with a 4xx too" do
      observed.first(8).each do |path|
        {client.post(path, headers: headers),
         client.put(path, headers: headers),
         client.delete(path, headers: headers)}.each do |result|
          unless (400..499).includes?(result.status_code)
            fail "#{path} answered #{result.status_code} on a write verb — expected 4xx"
          end
        end
      end
    end

    # Traversal and encoded-traversal, which is what the `.env` probes escalate
    # to. These must not reach the filesystem or produce a 5xx.
    it "refuses path traversal without leaking or crashing" do
      {
        "/auth/../../etc/passwd",
        "/auth/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/auth/....//....//etc/passwd",
        "/auth/authority?id=../../etc/passwd",
      }.each do |path|
        result = client.get(path, headers: headers)
        result.status_code.should be < 500
        result.body.should_not contain "root:"
        result.body.should_not contain "/bin/bash"
      end
    end

    # A scanner sending a garbage Host must not 5xx either. Authority lookup
    # is Host-driven (MT-01), so this is the one hostile header that reaches
    # a DB query.
    it "survives a hostile Host header" do
      {
        "'; DROP TABLE authorities; --",
        "../../etc/passwd",
        "%00",
        "a" * 512,
      }.each do |host|
        result = client.get("/auth/authority", headers: HTTP::Headers{"Host" => host})
        unless result.status_code < 500
          fail "Host #{host.inspect} produced #{result.status_code} — a hostile Host must never 5xx"
        end
        leaks.each { |needle| result.body.should_not contain needle }
      end
    end
  end
end
