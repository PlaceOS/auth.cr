require "authly"
require "placeos-models"

module PlaceOS::Auth::AuthlyAdapter
  # `Authly::AuthorizableOwner` impl. We do NOT implement password
  # grant — `authorized?` always returns nil — but we still need
  # `id_token` for the OpenID Connect flow.
  class Owner
    include ::Authly::AuthorizableOwner

    def authorized?(username : String, password : String) : String?
      # Password grant is rejected at the Client layer
      # (`allowed_grant_type?` returns false for "password"). If we ever
      # got here, returning nil produces an invalid_grant response.
      Log.warn { {action: "authly_owner.authorized?", message: "password grant attempted but is disabled"} }
      nil
    end

    # Returns OIDC ID-token claims for `user_id`. Matches the shape
    # the Ruby Doorkeeper-OpenID-Connect service emitted so existing
    # clients that introspect `id_token` keep working.
    def id_token(user_id : String) : Hash(String, String | Int64)
      claims = {} of String => String | Int64
      user = ::PlaceOS::Model::User.find?(user_id)
      return claims unless user

      claims["sub"] = user.id.as(String)
      claims["email"] = user.email.to_s
      claims["full_name"] = user.name
      claims["preferred_username"] = user.login_name.presence || user.email.to_s

      if (given = user.first_name.presence)
        claims["given_name"] = given
      end
      if (family = user.last_name.presence)
        claims["family_name"] = family
      end
      if (nickname = user.nickname.presence)
        claims["nickname"] = nickname
      end
      if (phone = user.phone.presence)
        claims["phone_number"] = phone
      end
      claims
    end
  end
end
