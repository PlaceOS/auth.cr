require "placeos-models/doorkeeper_application"

module PlaceOS::Auth
  # OAuth application management, matching Doorkeeper's
  # `/auth/oauth/applications` admin surface (PPT-2536). In the platform
  # these records are normally managed through rest-api's `/oauth_apps`
  # + Backoffice; this controller exists for drop-in parity with the
  # legacy service.
  #
  # Every action is gated on a signed-in sys_admin (Doorkeeper's
  # `admin_authenticator`); non-admins get 404, exactly as the legacy
  # service intended — the resource is invisible rather than forbidden.
  class Applications < Application
    base "/auth/oauth/applications"

    before_action :require_admin

    # Raised for a rejected create/update. A dedicated type is required
    # because action-controller resolves exception handlers ancestors-
    # first and won't let a subclass override the base RecordInvalid
    # handler — so we translate save failures into this type, which only
    # this controller handles, to reproduce Doorkeeper's `{"errors":[…]}`
    # 422 body.
    class InvalidApplication < ::Exception
      getter messages : Array(String)

      def initialize(@messages : Array(String))
        super("application invalid")
      end
    end

    @[AC::Route::Exception(InvalidApplication, status_code: HTTP::Status::UNPROCESSABLE_ENTITY)]
    def application_invalid(error) : NamedTuple(errors: Array(String))
      {errors: error.messages}
    end

    # Full record — the owner view Doorkeeper serialised for show/create/
    # update, including the plaintext secret (application secrets are not
    # hashed at rest).
    struct Record
      include JSON::Serializable

      getter id : Int64
      getter name : String
      getter uid : String
      getter secret : String
      getter redirect_uri : String
      getter scopes : String
      getter confidential : Bool

      def initialize(app : ::PlaceOS::Model::DoorkeeperApplication)
        @id = app.id.as(Int64)
        @name = app.name
        @uid = app.uid.as(String)
        @secret = app.secret
        @redirect_uri = app.redirect_uri
        @scopes = app.scopes
        @confidential = app.confidential
      end
    end

    # GET /auth/oauth/applications
    #
    # Doorkeeper served an HTML table here and, for JSON, `head
    # :no_content`. We reproduce the JSON behaviour: 204, empty body.
    @[AC::Route::GET("")]
    def index : Nil
      render :no_content
    end

    # GET /auth/oauth/applications/new — HTML form in the legacy admin UI.
    @[AC::Route::GET("/new")]
    def new : Nil
      render html: form_page("New application", "/auth/oauth/applications", "post")
    end

    # GET /auth/oauth/applications/:id/edit — HTML form in the admin UI.
    @[AC::Route::GET("/:id/edit")]
    def edit(id : String) : Nil
      app = find_app(id)
      render html: form_page("Edit application", "/auth/oauth/applications/#{app.id}", "patch")
    end

    # GET /auth/oauth/applications/:id
    @[AC::Route::GET("/:id")]
    def show(id : String) : Record
      Record.new(find_app(id))
    end

    # POST /auth/oauth/applications
    @[AC::Route::POST("")]
    def create : Record
      app = ::PlaceOS::Model::DoorkeeperApplication.new
      # Doorkeeper apps default to confidential; the model default is
      # false, so set it here and let an explicit param override.
      app.confidential = true
      assign_attributes(app)
      app.owner_id = (session_user.try(&.id)).as(String)
      persist!(app)
      Record.new(app)
    end

    # PATCH|PUT /auth/oauth/applications/:id
    @[AC::Route::PATCH("/:id")]
    @[AC::Route::PUT("/:id")]
    def update(id : String) : Record
      app = find_app(id)
      assign_attributes(app)
      persist!(app)
      Record.new(app)
    end

    # DELETE /auth/oauth/applications/:id
    @[AC::Route::DELETE("/:id")]
    def destroy(id : String) : Nil
      find_app(id).destroy
      render :no_content
    end

    # --- helpers ----------------------------------------------------------

    private def require_admin : Nil
      user = session_user
      raise Error::NotFound.new unless user && user.sys_admin
    end

    # CSRF defence for the state-changing admin actions. These are gated only
    # by the ambient session cookie (`require_admin`); because `_coauth_session`
    # is `SameSite=None` (needed for embedded login) the browser now attaches it
    # to cross-site requests, so a cross-site form POST could otherwise ride a
    # signed-in sys_admin's session to mint an OAuth client — `create` is a
    # "simple request" that skips the CORS preflight that already guards the
    # PATCH/DELETE verbs. The legitimate admin form is served same-origin by
    # this controller (`/new`, `/:id/edit`), so we require the mutation to be
    # same-origin. Non-browser API clients send neither `Sec-Fetch-Site` nor
    # `Origin`, so they are unaffected — they cannot be a browser CSRF vector.
    @[AC::Route::Filter(:before_action, only: [:create, :update, :destroy])]
    private def reject_cross_site_writes : Nil
      if (site = request.headers["Sec-Fetch-Site"]?) && !site.in?("same-origin", "none")
        raise Error::Forbidden.new("cross-site request rejected")
      end
      if (origin = request.headers["Origin"]?) && !same_origin_request?(origin)
        raise Error::Forbidden.new("cross-origin request rejected")
      end
    end

    private def same_origin_request?(origin : String) : Bool
      URI.parse(origin).host == request.hostname
    rescue
      false
    end

    private def find_app(id : String) : ::PlaceOS::Model::DoorkeeperApplication
      key = id.to_i64? || raise Error::NotFound.new
      ::PlaceOS::Model::DoorkeeperApplication.find!(key)
    end

    private def persist!(app : ::PlaceOS::Model::DoorkeeperApplication) : Nil
      app.save!
    rescue ex : PgORM::Error::RecordInvalid
      raise InvalidApplication.new(ex.errors.map { |e| "#{e[:field]} #{e[:message]}" })
    rescue ex : PgORM::Error::RecordNotSaved
      raise InvalidApplication.new([ex.message || "record could not be saved"])
    end

    private def assign_attributes(app : ::PlaceOS::Model::DoorkeeperApplication) : Nil
      if (name = app_param("name"))
        app.name = name
      end
      if (redirect_uri = app_param("redirect_uri"))
        app.redirect_uri = redirect_uri
      end
      if (scopes = app_param("scopes"))
        app.scopes = scopes
      end
      if (confidential = app_param("confidential"))
        app.confidential = confidential.in?("true", "1", "on")
      end
    end

    # Reads a create/update field. Doorkeeper nested the form params under
    # `doorkeeper_application[...]` and (via Rails wrap_parameters) also
    # accepted flat and JSON bodies, so we accept form params (nested or
    # flat) as well as a JSON body in either shape.
    private def app_param(key : String) : String?
      if value = params["doorkeeper_application[#{key}]"]? || params[key]?
        return value
      end
      json_param(key)
    end

    @json_body : JSON::Any? = nil
    @json_body_parsed = false

    private def json_param(key : String) : String?
      body = json_body
      return unless body
      nested = body["doorkeeper_application"]?
      value = (nested && nested[key]?) || body[key]?
      return unless value
      value.as_s? || value.to_s
    end

    private def json_body : JSON::Any?
      return @json_body if @json_body_parsed
      @json_body_parsed = true
      content_type = request.headers["Content-Type"]?
      return unless content_type && content_type.includes?("application/json")
      if raw = request.body.try(&.gets_to_end).presence
        @json_body = JSON.parse(raw) rescue nil
      end
      @json_body
    end

    private def form_page(title : String, action : String, method : String) : String
      <<-HTML
      <!doctype html>
      <html lang="en">
      <head><meta charset="utf-8"><title>#{HTML.escape(title)}</title></head>
      <body>
        <h1>#{HTML.escape(title)}</h1>
        <form action="#{HTML.escape(action)}" method="post" accept-charset="UTF-8">
          <input type="hidden" name="_method" value="#{HTML.escape(method)}">
          <label>Name <input type="text" name="doorkeeper_application[name]"></label>
          <label>Redirect URI <input type="text" name="doorkeeper_application[redirect_uri]"></label>
          <label>Scopes <input type="text" name="doorkeeper_application[scopes]"></label>
          <button type="submit">Save</button>
        </form>
      </body></html>
      HTML
    end
  end
end
