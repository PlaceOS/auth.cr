module PlaceOS::Auth
  # OAuth / SAML callback failure landing page. OmniAuth (Ruby) and
  # `multi_auth` (Crystal) bounce here when a provider rejects the
  # authentication round-trip; the page just tells the user it didn't
  # work and lets the front-end's framing decide what to do next.
  class Failures < Application
    base "/auth"

    # NB: 200 OK, not 401 — matches the Ruby service so any client
    # automation that hard-codes `if response.status == 200` keeps
    # working at cutover. The status doesn't carry semantics for any
    # caller; the body content is what counts.
    @[AC::Route::GET("/failure", content_type: "text/html")]
    def show : String
      <<-HTML
      <!doctype html>
      <html lang="en">
      <head><meta charset="utf-8"><title>Authentication failed</title></head>
      <body><h1>Authentication failed</h1>
      <p>We couldn't complete sign-in with that provider. Please try again.</p>
      </body></html>
      HTML
    end
  end
end
