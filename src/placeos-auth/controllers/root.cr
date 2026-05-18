module PlaceOS::Auth
  # Liveness/readiness probe. Auth-specific endpoints land in their own
  # controllers; this exists only to give the server a route to bind to
  # while the rest of the controllers are being ported.
  class Root < Application
    base "/auth"

    @[AC::Route::GET("/healthz")]
    def healthz : NamedTuple(status: String, app: String, version: String)
      {status: "ok", app: APP_NAME, version: VERSION}
    end
  end
end
