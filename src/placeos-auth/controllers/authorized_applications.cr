require "placeos-models/doorkeeper_application"
require "placeos-models/oauth_token"

module PlaceOS::Auth
  # The signed-in user's own authorized applications, matching
  # Doorkeeper's `/auth/oauth/authorized_applications` (PPT-2536): the
  # apps they hold live tokens for, and the ability to revoke an app's
  # access. Session-gated (the resource owner), not admin-gated.
  class AuthorizedApplications < Application
    base "/auth/oauth/authorized_applications"

    # Public application shape — the non-owner view (id, name, created_at,
    # plus uid for non-confidential apps).
    struct Summary
      include JSON::Serializable

      getter id : Int64
      getter name : String
      @[JSON::Field(emit_null: false)]
      getter uid : String?

      def initialize(app : ::PlaceOS::Model::DoorkeeperApplication)
        @id = app.id.as(Int64)
        @name = app.name
        @uid = app.confidential ? nil : app.uid
      end
    end

    # GET /auth/oauth/authorized_applications
    @[AC::Route::GET("")]
    def index : Array(Summary)
      user = require_session_user
      authorized_apps(user.id.as(String)).map { |app| Summary.new(app) }
    end

    # DELETE /auth/oauth/authorized_applications/:id
    #
    # `:id` is the application id. Revokes every live token the current
    # user holds for that application.
    @[AC::Route::DELETE("/:id")]
    def destroy(id : String) : Nil
      user = require_session_user
      key = id.to_i64? || raise Error::NotFound.new
      app = ::PlaceOS::Model::DoorkeeperApplication.find!(key)

      ::PlaceOS::Model::OAuthToken
        .where(sub: user.id.as(String), client_id: app.uid.as(String))
        .each(&.revoke!)

      render :no_content
    end

    # --- helpers ----------------------------------------------------------

    # These are JSON endpoints, so an unauthenticated caller gets 401
    # rather than Doorkeeper's browser redirect to the login page (noted
    # as an accepted divergence in auth_migration/parity_matrix.md).
    private def require_session_user : ::PlaceOS::Model::User
      session_user || raise Error::Unauthorized.new
    end

    # Applications the user holds an unexpired, unrevoked token for.
    private def authorized_apps(user_id : String) : Array(::PlaceOS::Model::DoorkeeperApplication)
      now = Time.utc.to_unix
      client_ids = ::PlaceOS::Model::OAuthToken
        .where(sub: user_id)
        .reject { |token| token.revoked? || ((exp = token.expires_at) && exp <= now) }
        .compact_map(&.client_id)
        .uniq!

      return [] of ::PlaceOS::Model::DoorkeeperApplication if client_ids.empty?
      ::PlaceOS::Model::DoorkeeperApplication.where(uid: client_ids).to_a
    end
  end
end
