require "authly"
require "placeos-models"

module PlaceOS::Auth::AuthlyAdapter
  # Enriches every access-token JWT with the legacy `u: {n, e, p, r}`
  # claim block — same shape the Ruby Doorkeeper service emitted — so
  # downstream PlaceOS services that JWT-decode tokens issued *before*
  # cutover keep working against tokens issued *after*.
  #
  # `u`:
  #   * `n` — `User#name`
  #   * `e` — `User#email` (lowercased)
  #   * `p` — permissions bitflags: `Permissions::User` (0), `Support`
  #          (1), `Admin` (2), `AdminSupport` (3)
  #   * `r` — `User#groups` array
  #
  # We also set the `aud` claim to the authority domain so
  # `ensure_matching_domain` (in `Utils::CurrentUser`) accepts the
  # token on multi-tenant requests.
  class ClaimsProvider
    include ::Authly::ClaimsProvider

    def enrich_access_token(
      payload : ::Authly::JWTPayload,
      client_id : String,
      sub : String,
      scope : String,
    ) : ::Authly::JWTPayload
      user = ::PlaceOS::Model::User.find?(sub)
      return payload unless user

      permissions = ::PlaceOS::Model::UserJWT::Permissions.from_value(permissions_value(user))

      payload["u"] = {
        "n" => user.name,
        "e" => user.email.to_s,
        "p" => permissions.value.to_i64,
        "r" => user.groups,
      } of String => (String | Int64 | Array(String))

      if authority = user.authority.as(::PlaceOS::Model::Authority?)
        payload["aud"] = authority.domain
      end

      payload
    end

    # Bit 0 = support, bit 1 = sys_admin. Same encoding the Ruby service
    # used so tokens stay forward-compatible.
    private def permissions_value(user : ::PlaceOS::Model::User) : Int32
      value = 0
      value |= 1 if user.support
      value |= 2 if user.sys_admin
      value
    end
  end
end
