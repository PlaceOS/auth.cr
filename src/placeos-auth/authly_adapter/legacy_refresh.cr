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

      # NB: bind the parameter via the `args:` Array overload rather than the
      # varargs splat. A row-returning `db.query*` with splatted args crashes
      # the Crystal compiler — "BUG: ... Tuple#each MacroFor ... should have
      # been expanded" (tuple.cr:367). How far it reaches is toolchain
      # dependent: on CI's compiler only the `--release`/`--static` image build
      # failed while `crystal spec` passed, so the first PR #10 CI run went
      # green on tests and red on Build; on Crystal 1.16.3 the spec build ICEs
      # too. `db.exec` with splatted args is unaffected.
      found = nil
      ::PgORM::Database.connection do |db|
        db.query(<<-SQL, args: [digest(refresh_token)] of ::DB::Any) do |rs|
          SELECT id, application_id, resource_owner_id, scopes
            FROM oauth_access_tokens
           WHERE refresh_token = $1 AND revoked_at IS NULL
           LIMIT 1
          SQL
          rs.each do
            found = Token.new(
              rs.read(Int64),
              rs.read(Int64),
              rs.read(String?),
              rs.read(String?),
            )
          end
        end
      end
      found
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
