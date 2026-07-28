require "digest/sha256"

module PlaceOS::Auth::Spec
  # Fixtures for credentials auth.cr did NOT mint.
  #
  # Every auth.cr refresh failure so far (PPT-2536) was a credential that
  # predates the running code: tokens issued by the Ruby service, or by an
  # earlier auth.cr build. Specs that only exercise freshly-minted tokens
  # cannot see those, which is exactly why the 2026-07-25 dev revert happened
  # with a green suite. These builders reproduce the older wire formats so the
  # suite can assert on them directly.
  #
  # Shapes are taken from the dev-server forensics (tasks/PPT-2536):
  #   * 7,401 Ruby Doorkeeper access tokens, 100% `scopes = 'public'`,
  #     100% carrying a refresh token — the whole install base at cutover.
  #   * `hash_token_secrets` is on in the Ruby config, so the DB stores the
  #     SHA256 hex digest of the token, never the token itself.
  module LegacyFixtures
    extend self

    # ---- Ruby / Doorkeeper (opaque) -------------------------------------

    # Seeds a Doorkeeper-era `oauth_access_tokens` row and returns the PLAIN
    # refresh token a client would present. Only the digest is stored, so the
    # plain value cannot be read back out of the DB — hold on to the return.
    def doorkeeper_row(
      application_id : Int64,
      resource_owner_id : String?,
      scopes : String? = "public",
      revoked : Bool = false,
    ) : String
      plain = Random::Secure.hex(32)
      sql = <<-SQL
        INSERT INTO oauth_access_tokens
          (id, refresh_token, token, application_id, resource_owner_id, scopes, revoked_at, created_at, previous_refresh_token)
        VALUES
          ((SELECT COALESCE(MAX(id), 0) + 1 FROM oauth_access_tokens),
           $1, $2, $3, $4, $5,
           CASE WHEN $6 THEN now() ELSE NULL END, now(), '')
        SQL
      ::PgORM::Database.connection do |db|
        db.exec(sql, args: [
          AuthlyAdapter::LegacyRefresh.digest(plain),
          # the access token is hashed the same way; its value is irrelevant
          # here, but the column is NOT NULL and unique in the Ruby schema.
          Digest::SHA256.hexdigest(Random::Secure.hex(32)),
          application_id, resource_owner_id, scopes, revoked,
        ] of ::DB::Any)
      end
      plain
    end

    # nil when no row matches (e.g. it was never seeded).
    def doorkeeper_row_revoked?(plain : String) : Bool?
      ::PgORM::Database.connection do |db|
        # `args:` Array rather than a varargs splat: a row-returning query with
        # splatted args crashes the compiler. See legacy_refresh.cr.
        db.query_one?(
          "SELECT revoked_at IS NOT NULL FROM oauth_access_tokens WHERE refresh_token = $1",
          args: [AuthlyAdapter::LegacyRefresh.digest(plain)] of ::DB::Any, as: Bool)
      end
    end

    # `clear_tables` doesn't touch the Ruby-era table (it isn't a PgORM model),
    # so seeded rows outlive a spec run unless a spec cleans up after itself.
    def clear_doorkeeper_rows
      ::PgORM::Database.connection(&.exec("DELETE FROM oauth_access_tokens"))
    rescue
      # table absent on a stack that never ran Ruby auth — nothing to clear
    end

    # ---- auth.cr, earlier builds ----------------------------------------

    # Pre-scope-fix (pre-PR #8) auth.cr refresh token: embeds the resource
    # owner but NOT the granted scope. Recovery finds nothing, so without the
    # heal the refreshed access token gets `scope: []`, every rest-api call
    # 403s, and each refresh re-embeds "" — the chain is stuck permanently.
    def pre_scope_fix_refresh_token(client_uid : String, user_id : String) : String
      refresh_jwt({"sub" => client_uid, "user_id" => user_id})
    end

    # Current-format auth.cr refresh token: user AND scope embedded.
    def current_refresh_token(client_uid : String, user_id : String, scope : String = "public") : String
      refresh_jwt({"sub" => client_uid, "user_id" => user_id, "scope" => scope})
    end

    # Client-credentials style: no resource owner at all. Nothing should ever
    # heal this to `public` — machine grants must not gain a user's scope.
    def ownerless_refresh_token(client_uid : String) : String
      refresh_jwt({"sub" => client_uid})
    end

    private def refresh_jwt(claims : Hash(String, String)) : String
      payload = {
        "jti"  => Random::Secure.hex(32),
        "name" => "refresh token",
        "iat"  => Time.utc.to_unix,
        "iss"  => ::Authly.config.issuer,
        "exp"  => 30.days.from_now.to_unix,
      } of String => JSON::Any::Type
      claims.each { |k, v| payload[k] = v }
      ::Authly.jwt_encode(payload)
    end
  end
end
