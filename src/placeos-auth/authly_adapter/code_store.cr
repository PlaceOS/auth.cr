require "pg-orm"
require "placeos-models"

module PlaceOS::Auth::AuthlyAdapter
  # Single-use enforcement for authorization codes (RFC 6749 §4.1.2).
  #
  # auth.cr's authorization code is a *stateless* JWT (`Authly::Code#jwt`), and
  # redemption (`Authly::AuthorizationCode#authorized?`) verifies only the
  # signature, the embedded redirect_uri, the client and the PKCE challenge.
  # Nothing recorded that a code had been spent, so one code minted a fresh
  # access+refresh pair on every presentation for its full 10-minute TTL.
  #
  # RFC 6749 §4.1.2: "The client MUST NOT use the authorization code more than
  # once. If an authorization code is used more than once, the authorization
  # server MUST deny the request". Ruby Doorkeeper enforced this by revoking
  # the grant row on first use, so this is a parity break as well.
  #
  # STRICTNESS: unlike the refresh path (which needs a grace window because the
  # ts-client boot race genuinely double-submits the same refresh token —
  # RF-05), codes are spent exactly once with no tolerance. Two independent
  # checks justify that:
  #
  #   1. ts-client destroys both halves of the exchange at URL-construction
  #      time — `sessionStorage.removeItem(<client>_challenge)` and
  #      `_code = ''` in `createRefreshURL` — so it *cannot* resubmit a code
  #      even on retry; each boot cycle runs a fresh authorize and gets a new
  #      code and verifier.
  #   2. Dev's auth log carries 19 authorization-code exchanges with 19
  #      distinct verifiers, zero repeats, and zero non-200 responses.
  #
  # Marker rows live in `oauth_tokens` beside real token metadata, but under a
  # prefixed `jti` so they can neither collide with nor be mistaken for an
  # actual token: every other lookup in this service keys off the `jti` claim
  # of a presented JWT, which is 64 hex chars (`Random::Secure.hex(32)`) and
  # can never carry this prefix.
  module CodeStore
    Log = ::PlaceOS::Auth::Log.for(self)

    # Namespaces a code's jti away from the token jti keyspace.
    PREFIX = "authz-code:"

    # Recorded in `token_type` so a marker row is self-describing in the DB.
    TOKEN_TYPE = "authorization_code"

    def self.key(code_jti : String) : String
      "#{PREFIX}#{code_jti}"
    end

    # Atomically record that `code_jti` has been redeemed.
    #
    # Returns `true` if THIS call claimed it (first use), `false` if it had
    # already been spent. Atomicity comes from the unique index on
    # `oauth_tokens.jti`: concurrent redemptions of the same code both attempt
    # the insert, exactly one wins, and `ON CONFLICT DO NOTHING` turns the
    # loser into an empty result set rather than an exception. Doing this as a
    # SELECT-then-INSERT would leave a race wide enough to drive two token
    # pairs through.
    #
    # `expires_at` carries the code's own `exp` so the row is prunable on the
    # same schedule as expired token metadata (there is an index on it).
    def self.claim(
      code_jti : String,
      client_id : String?,
      sub : String?,
      scope : String?,
      expires_at : Int64?,
    ) : Bool
      now = Time.utc
      claimed = false

      # NB: `args:` Array overload, not the varargs splat — a row-returning
      # `db.query*` with splatted args crashes the Crystal compiler
      # ("BUG: ... Tuple#each MacroFor ... should have been expanded",
      # tuple.cr:367). See the same note in `legacy_refresh.cr`.
      bindings = [
        key(code_jti), TOKEN_TYPE, client_id, sub, scope,
        now.to_unix, expires_at, now.to_unix, now, now,
      ] of ::DB::Any

      ::PgORM::Database.connection do |db|
        db.query(<<-SQL, args: bindings) do |rs|
          INSERT INTO oauth_tokens
                 (jti, token_type, client_id, sub, scope,
                  issued_at, expires_at, revoked_at, created_at, updated_at)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
          ON CONFLICT (jti) DO NOTHING
          RETURNING id
          SQL
          rs.each { claimed = true }
        end
      end

      claimed
    end
  end
end
