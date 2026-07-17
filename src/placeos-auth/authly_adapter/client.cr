require "authly"
require "placeos-models"

module PlaceOS::Auth::AuthlyAdapter
  # `Authly::AuthorizableClient` impl backed by the legacy
  # `oauth_applications` table (Crystal model:
  # `::PlaceOS::Model::DoorkeeperApplication`). The OAuth `client_id`
  # maps onto the model's `uid` column.
  class Client
    include ::Authly::AuthorizableClient
    # Authly's `device_authorization_handler` and `client_store` lookups
    # iterate `Authly.clients` via Enumerable (`any?`, `find`). We don't
    # mount that handler, but the code still has to type-check. A no-op
    # `each` keeps the compiler happy and makes those device-flow paths
    # behave as "no matching client" if anyone ever wires the handler up
    # — which is the safe default for a flow we're not supporting.
    include Enumerable(::Authly::Client)

    def each(& : ::Authly::Client ->) : Nil
      # intentionally no-op
    end

    # Authorisation server scope vocabulary. Locked to a small, safe set
    # for the port; the legacy Ruby service had a sprawling 100+-scope
    # list driven by Doorkeeper config. Tightening this in the port is
    # deliberate — extend the list when a real use case shows up.
    DEFAULT_SCOPES = Set{
      "public",
      "openid",
      "profile",
      "email",
      "offline_access",
    }

    # Grant types we permit. `password` is intentionally absent — the
    # OAuth 2.1 RFC deprecates it and the project brief explicitly
    # dropped it. Authly's `Grant` machinery calls
    # `Authly.clients.allowed_grant_type?` during token issuance, so
    # returning `false` here is the canonical rejection.
    ALLOWED_GRANT_TYPES = Set{
      "authorization_code",
      "client_credentials",
      "refresh_token",
    }

    def valid_redirect?(client_id : String, redirect_uri : String) : Bool
      app = find_app(client_id)
      return false unless app
      registered_uris(app).includes?(redirect_uri)
    end

    def authorized?(client_id : String, client_secret : String) : Bool
      app = find_app(client_id)
      return false unless app
      # Public clients (SPAs / native apps, `confidential: false`) don't
      # authenticate with a secret — they use PKCE. Doorkeeper skipped
      # client-secret validation for them, so we do too; `client_credentials`
      # is still denied to public clients in `allowed_grant_type?` below, so
      # this bypass can't be used to mint tokens without proof of possession.
      return true unless app.confidential
      Crypto::Subtle.constant_time_compare(app.secret, client_secret)
    end

    def allowed_scopes?(client_id : String, scopes : String) : Bool
      app = find_app(client_id)
      return false unless app
      requested = scopes.split.reject(&.empty?)
      return true if requested.empty?

      client_scopes = app.scopes.split.reject(&.empty?).to_set
      requested.all? do |scope|
        DEFAULT_SCOPES.includes?(scope) || client_scopes.includes?(scope)
      end
    end

    # Called by authly's Grant strategies. Not part of the abstract
    # interface but called dynamically; concrete classes assigned to
    # `Authly.config.clients` must implement it.
    def allowed_grant_type?(client_id : String, grant_type : String) : Bool
      return false unless ALLOWED_GRANT_TYPES.includes?(grant_type)
      app = find_app(client_id)
      return false unless app
      # `client_credentials` authenticates purely by secret, so it is only
      # ever valid for a confidential client. A public client that reached
      # `authorized?` via the secret bypass above must not be able to fall
      # through to a client-credentials grant.
      return false if grant_type == "client_credentials" && !app.confidential
      true
    end

    # Returns the owning user's ID for use as the `sub` claim of
    # client_credentials tokens. The default authly behaviour assigns a
    # random hex; we want a stable id so downstream services that
    # treat the token's `sub` as a principal don't see different users
    # per request.
    def owner_id(client_id : String) : String?
      find_app(client_id).try(&.owner_id)
    end

    private def find_app(client_id : String) : ::PlaceOS::Model::DoorkeeperApplication?
      return nil if client_id.empty?
      ::PlaceOS::Model::DoorkeeperApplication.where(uid: client_id).first?
    end

    # Doorkeeper convention stores multiple redirect URIs as a
    # whitespace-separated string in a single column.
    private def registered_uris(app : ::PlaceOS::Model::DoorkeeperApplication) : Array(String)
      app.redirect_uri.split.reject(&.empty?)
    end
  end
end
