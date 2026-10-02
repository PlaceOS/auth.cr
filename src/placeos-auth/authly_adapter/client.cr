require "authly"
require "placeos-models"

require "../utilities/client_metadata"
require "../utilities/redirect_uri"

module PlaceOS::Auth::AuthlyAdapter
  # A client resolved from the `oauth_applications` table, or from a client
  # ID metadata document (see `Utils::ClientMetadata`).
  struct ClientInfo
    getter client_id : String
    getter name : String
    getter redirect_uris : Array(String)
    getter scopes : Set(String)
    getter? confidential : Bool
    getter secret : String?
    getter owner_id : String?
    getter? skip_authorization : Bool

    # registered by the client itself (dynamic registration or a metadata
    # document) rather than by an administrator
    getter? dynamic : Bool

    def initialize(@client_id, @name, @redirect_uris, @scopes, @confidential, @secret, @owner_id, @skip_authorization, @dynamic)
    end

    # self registered clients must be approved by the user, as must
    # administrator registered apps that don't skip authorization
    def consent_required? : Bool
      dynamic? || !skip_authorization?
    end

    # self registered clients must use PKCE with S256
    def pkce_required? : Bool
      dynamic?
    end

    # the client_id is the URL of a client metadata document
    def metadata_document? : Bool
      Utils::ClientMetadata.client_id?(client_id)
    end

    def valid_redirect?(redirect_uri : String) : Bool
      redirect_uris.any? { |registered| Utils::RedirectURI.match?(registered, redirect_uri) }
    end
  end

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
      # RFC 8693, Entra subject tokens only — see `Utils::EntraTokenExchange`.
      "urn:ietf:params:oauth:grant-type:token-exchange",
    }

    # `client_id` prefix of clients created by dynamic registration (RFC 7591)
    DYNAMIC_PREFIX = "dcr-"

    # grants available to self registered clients
    DYNAMIC_GRANT_TYPES = Set{"authorization_code", "refresh_token"}

    # loopback redirects match on any port, see `Utils::RedirectURI.match?`
    def valid_redirect?(client_id : String, redirect_uri : String) : Bool
      client_info(client_id).try(&.valid_redirect?(redirect_uri)) || false
    end

    def authorized?(client_id : String, client_secret : String) : Bool
      app = client_info(client_id)
      return false unless app
      # Public clients (SPAs / native apps, `confidential: false`) don't
      # authenticate with a secret — they use PKCE. Doorkeeper skipped
      # client-secret validation for them, so we do too; `client_credentials`
      # is still denied to public clients in `allowed_grant_type?` below, so
      # this bypass can't be used to mint tokens without proof of possession.
      return true unless app.confidential?
      Crypto::Subtle.constant_time_compare(app.secret || "", client_secret)
    end

    def allowed_scopes?(client_id : String, scopes : String) : Bool
      app = client_info(client_id)
      return false unless app
      requested = scopes.split.reject(&.empty?)
      return true if requested.empty?

      requested.all? do |scope|
        DEFAULT_SCOPES.includes?(scope) || app.scopes.includes?(scope)
      end
    end

    # Called by authly's Grant strategies. Not part of the abstract
    # interface but called dynamically; concrete classes assigned to
    # `Authly.config.clients` must implement it.
    def allowed_grant_type?(client_id : String, grant_type : String) : Bool
      return false unless ALLOWED_GRANT_TYPES.includes?(grant_type)
      app = client_info(client_id)
      return false unless app
      return false if app.dynamic? && !DYNAMIC_GRANT_TYPES.includes?(grant_type)
      # `client_credentials` authenticates purely by secret, so it is only
      # ever valid for a confidential client. A public client that reached
      # `authorized?` via the secret bypass above must not be able to fall
      # through to a client-credentials grant.
      return false if grant_type == "client_credentials" && !app.confidential?
      true
    end

    # Returns the owning user's ID for use as the `sub` claim of
    # client_credentials tokens. The default authly behaviour assigns a
    # random hex; we want a stable id so downstream services that
    # treat the token's `sub` as a principal don't see different users
    # per request.
    def owner_id(client_id : String) : String?
      client_info(client_id).try(&.owner_id)
    end

    # Resolves the client from its metadata document (an `https://` client_id)
    # or the `oauth_applications` table.
    def client_info(client_id : String) : ClientInfo?
      return if client_id.empty?

      if Utils::ClientMetadata.client_id?(client_id)
        document = Utils::ClientMetadata.fetch(client_id)
        return unless document
        return ClientInfo.new(
          client_id: client_id,
          name: document.display_name,
          redirect_uris: document.redirect_uris,
          scopes: Set{"public"},
          confidential: false,
          secret: nil,
          owner_id: nil,
          skip_authorization: false,
          dynamic: true,
        )
      end

      app = ::PlaceOS::Model::DoorkeeperApplication.where(uid: client_id).first?
      return unless app
      ClientInfo.new(
        client_id: client_id,
        name: app.name,
        # Doorkeeper convention stores multiple redirect URIs as a
        # whitespace-separated string in a single column.
        redirect_uris: app.redirect_uri.split.reject(&.empty?),
        scopes: app.scopes.split.reject(&.empty?).to_set,
        confidential: app.confidential,
        secret: app.secret,
        owner_id: app.owner_id,
        skip_authorization: app.skip_authorization,
        dynamic: client_id.starts_with?(DYNAMIC_PREFIX),
      )
    end
  end
end
