require "authly"
require "placeos-models"

module PlaceOS::Auth::AuthlyAdapter
  # `Authly::TokenStore` backed by `PlaceOS::Model::OAuthToken`. We use
  # the JWT token strategy (`Authly.config.token_strategy = :jwt`),
  # which means:
  #
  #   * The token itself is a self-validating JWT — `fetch` is only
  #     used by the opaque strategy / introspection, not by the
  #     hot path.
  #   * `store(jti, payload)` is called from
  #     `JWTTokenGenerator#store_token_metadata` whenever
  #     `Authly.config.persist_jwt_tokens?` is true (we set it on so
  #     revocation works).
  #   * `revoke(jti)` is called from `/auth/revoke` and from
  #     `/auth/logout` (Phase 3d) — we flip `revoked_at`. If we've
  #     never seen the jti (e.g. revoking a JWT-stateless refresh
  #     token), we insert a minimal marker row so future presentations
  #     of that token get rejected.
  #   * `revoked?(jti)` is called on every Bearer validation that
  #     reaches `Authly.valid?`.
  class TokenStore
    include ::Authly::TokenStore

    # Marks a refresh token revoked because it was ROTATED (i.e. redeemed and
    # replaced), as opposed to deliberately revoked via `/auth/revoke` or
    # `/auth/logout`. The refresh path grants a brief grace window to the
    # former and none at all to the latter — see `RefreshToken#validate_code!`.
    # Recorded in `token_type` because revocation-marker rows never carry one.
    ROTATED_MARKER = "refresh_rotated"

    # Revoke a refresh token that has just been rotated.
    #
    # Deliberately distinct from `revoke`: a rotated token must stay briefly
    # redeemable so the ts-client boot race (which submits the same refresh
    # token twice within milliseconds) does not log the SPA out, whereas an
    # explicitly revoked token must stop working immediately or logout means
    # nothing. An already-revoked token is left alone — an explicit revocation
    # must never be downgraded to a rotation by a later redemption.
    def revoke_rotated(token_id : String) : Nil
      token = find_or_initialize(token_id)
      return if token.revoked?
      token.token_type = ROTATED_MARKER
      token.revoked_at = Time.utc.to_unix
      token.save!
    end

    def store(token_id : String, payload) : Nil
      ensure_payload!(payload)

      token = find_or_initialize(token_id)
      token.token_type = extract_string(payload, "token_type") || token.token_type
      token.client_id = extract_string(payload, "cid") || token.client_id
      token.sub = extract_string(payload, "sub") || token.sub
      token.scope = extract_string(payload, "scope") || token.scope
      token.issued_at = extract_int(payload, "iat") || token.issued_at
      token.expires_at = extract_int(payload, "exp") || token.expires_at
      token.cert_thumbprint = extract_string(payload, "cnf") || token.cert_thumbprint
      token.save!
    end

    def fetch(token_id : String)
      token = ::PlaceOS::Model::OAuthToken.where(jti: token_id).first?
      raise ::Authly::Error.invalid_token if token.nil?

      payload = {} of String => (String | Int64 | Bool | Float64)
      if (token_type = token.token_type)
        payload["token_type"] = token_type
      end
      if (cid = token.client_id)
        payload["cid"] = cid
      end
      if (sub = token.sub)
        payload["sub"] = sub
      end
      if (scope = token.scope)
        payload["scope"] = scope
      end
      if (iat = token.issued_at)
        payload["iat"] = iat
      end
      if (exp = token.expires_at)
        payload["exp"] = exp
      end
      if (cnf = token.cert_thumbprint)
        payload["cnf"] = cnf
      end
      payload["jti"] = token.jti.as(String)
      payload
    end

    def revoke(token_id : String) : Nil
      token = find_or_initialize(token_id)
      return if token.revoked?
      token.revoked_at = Time.utc.to_unix
      token.save!
    end

    def revoked?(token_id : String) : Bool
      token = ::PlaceOS::Model::OAuthToken.where(jti: token_id).first?
      return false if token.nil?
      token.revoked?
    end

    # `valid?` is only consulted in the opaque strategy; the JWT
    # strategy's `JWTToken#valid?` checks `revoked?` + the JWT's own
    # exp claim. Implement for completeness so the abstract module is
    # satisfied.
    def valid?(token_id : String) : Bool
      token = ::PlaceOS::Model::OAuthToken.where(jti: token_id).first?
      return false if token.nil?
      return false if token.revoked?
      if (exp = token.expires_at) && Time.utc.to_unix >= exp
        return false
      end
      true
    end

    private def find_or_initialize(token_id : String) : ::PlaceOS::Model::OAuthToken
      existing = ::PlaceOS::Model::OAuthToken.where(jti: token_id).first?
      return existing if existing
      record = ::PlaceOS::Model::OAuthToken.new
      record.jti = token_id
      record
    end

    private def ensure_payload!(payload) : Nil
      return if payload.is_a?(Hash)
      raise ArgumentError.new("authly token payload must be a Hash, got #{payload.class}")
    end

    private def extract_string(payload, key : String) : String?
      value = payload[key]?
      value.is_a?(String) ? value : nil
    end

    private def extract_int(payload, key : String) : Int64?
      case value = payload[key]?
      when Int64 then value
      when Int   then value.to_i64
      else            nil
      end
    end
  end
end
