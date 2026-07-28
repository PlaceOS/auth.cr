require "digest/sha256"
require "pg-orm"
require "placeos-models"

module PlaceOS::Auth::AuthlyAdapter
  # Bridge for refresh tokens issued by the legacy Ruby (Doorkeeper) auth
  # service, so clients mid-session at cutover can refresh against auth.cr
  # without being forced through an interactive re-login (PPT-2536).
  #
  # Doorkeeper refresh tokens are opaque random strings; with
  # `hash_token_secrets` enabled (the Ruby config) the DB stores their
  # SHA256 hex digest in `oauth_access_tokens.refresh_token`. They carry no
  # expiry of their own — they are valid until `revoked_at` is set.
  #
  # auth.cr refresh tokens are JWTs, so `Authly.jwt_decode` rejects a legacy
  # token outright. The grant patches in `authly_adapter.cr` fall back to
  # this module: look the digest up, validate the redeeming client owns the
  # row, then mint native auth.cr tokens (the re-minted refresh token is an
  # auth.cr JWT, so the chain migrates off Doorkeeper after one refresh) and
  # revoke the Doorkeeper row.
  module LegacyRefresh
    Log = ::PlaceOS::Auth::Log.for(self)

    record Token,
      id : Int64,
      application_id : Int64,
      resource_owner_id : String?,
      scopes : String?

    # Doorkeeper `hash_token_secrets` => unsalted SHA256 hex digest
    # (Doorkeeper::SecretStoring::Sha256Hash).
    def self.digest(refresh_token : String) : String
      Digest::SHA256.hexdigest(refresh_token)
    end

    # Finds an unrevoked Doorkeeper row for the presented refresh token.
    # auth.cr JWT refresh tokens always contain '.', legacy opaque tokens
    # never do — cheap pre-filter to keep the hot (native) path DB-free.
    def self.lookup(refresh_token : String) : Token?
      return nil if refresh_token.empty? || refresh_token.includes?('.')

      row = ::PgORM::Database.connection do |db|
        db.query_one?(<<-SQL, digest(refresh_token), as: {Int64, Int64, String?, String?})
          SELECT id, application_id, resource_owner_id, scopes
            FROM oauth_access_tokens
           WHERE refresh_token = $1 AND revoked_at IS NULL
           LIMIT 1
          SQL
      end
      return nil unless row
      Token.new(row[0], row[1], row[2], row[3])
    rescue e
      # A missing table (deployment that never ran Ruby auth) or DB hiccup
      # must degrade to "not a legacy token", not break the token endpoint.
      Log.warn(exception: e) { "legacy refresh-token lookup failed" }
      nil
    end

    # The redeeming client must own the Doorkeeper row (Rails
    # `oauth_applications.id` referenced by `application_id`; the OAuth
    # `client_id` is the model's `uid`).
    def self.client_matches?(token : Token, client_id : String) : Bool
      app = ::PlaceOS::Model::DoorkeeperApplication.where(uid: client_id).first?
      return false unless app
      app.id == token.application_id
    end

    # Doorkeeper rotation semantics: a redeemed refresh token is revoked.
    def self.revoke!(token : Token) : Nil
      ::PgORM::Database.connection do |db|
        db.exec("UPDATE oauth_access_tokens SET revoked_at = now() WHERE id = $1", token.id)
      end
    rescue e
      Log.warn(exception: e) { "failed revoking legacy refresh token id=#{token.id}" }
    end
  end
end
