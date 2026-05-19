require "multi_auth"
require "placeos-models"

module PlaceOS::Auth
  # Maps a `MultiAuth::User` (the standardised result of an OAuth2 or
  # SAML round-trip) onto a `PlaceOS::Model::User` row plus its
  # `UserAuthLookup` link. Mirrors the three branches of the legacy
  # Ruby `Auth::SessionsController#create`:
  #
  #   1. existing `UserAuthLookup` → return the linked user (login).
  #   2. no `UserAuthLookup` + caller is already signed in → link
  #      the new provider to the signed-in user.
  #   3. no `UserAuthLookup` + caller is anonymous → auto-create the
  #      user inline. (The legacy `POST /auth/signup` route is dropped
  #      per scope.)
  #
  # In all three branches the user record is upserted from the OAuth
  # profile (name / email / phone / etc.) so the local row stays in
  # sync with what the identity provider currently believes.
  module Utils::OAuthUserMapper
    extend self

    Log = ::PlaceOS::Auth::Log.for(self)

    # Outcome surface: the branch we took + the resulting user. Caller
    # decides what to do with it (set session, publish login event, ...).
    enum Outcome
      Login   # branch (1)
      Link    # branch (2)
      Created # branch (3)
    end

    record Result, user : ::PlaceOS::Model::User, outcome : Outcome, lookup : ::PlaceOS::Model::UserAuthLookup

    # `current_session_user` is the signed-in user (or `nil`). Pass
    # this from the controller so we don't need to import session
    # state here.
    def map(
      authority : ::PlaceOS::Model::Authority,
      oauth_user : ::MultiAuth::User,
      current_session_user : ::PlaceOS::Model::User? = nil,
    ) : Result
      lookup = find_lookup(authority, oauth_user)

      if lookup
        user = resolve_lookup_user(authority, oauth_user, lookup)
        apply_oauth_profile!(user, oauth_user)
        user.save!
        Result.new(user: user, outcome: Outcome::Login, lookup: lookup)
      elsif (signed_in = current_session_user)
        # branch (2): adding a new provider to an already-known user
        apply_oauth_profile!(signed_in, oauth_user)
        signed_in.deleted = false
        signed_in.save!
        lookup = create_lookup(authority, oauth_user, signed_in)
        Result.new(user: signed_in, outcome: Outcome::Link, lookup: lookup)
      else
        # branch (3): new user, auto-create
        user = find_existing_user_by_email(authority, oauth_user)
        if user
          user.deleted = false
        else
          user = ::PlaceOS::Model::User.new
          user.authority_id = authority.id
          assign_initial_fields!(user, oauth_user)
        end
        apply_oauth_profile!(user, oauth_user)
        user.save!
        lookup = create_lookup(authority, oauth_user, user)
        Result.new(user: user, outcome: Outcome::Created, lookup: lookup)
      end
    end

    # ---- private helpers ------------------------------------------------

    private def find_lookup(authority, oauth_user) : ::PlaceOS::Model::UserAuthLookup?
      id = "auth-#{authority.id}-#{oauth_user.provider}-#{oauth_user.uid}"
      ::PlaceOS::Model::UserAuthLookup.find?(id)
    end

    # If the lookup exists but the user has been deleted out from under
    # it, recover by re-creating the user (mirrors the Ruby recursive
    # `return create` recovery).
    private def resolve_lookup_user(authority, oauth_user, lookup) : ::PlaceOS::Model::User
      uid = lookup.user_id
      if uid && (existing = ::PlaceOS::Model::User.find?(uid))
        existing.deleted = false
        return existing
      end
      lookup.destroy
      user = find_existing_user_by_email(authority, oauth_user) || ::PlaceOS::Model::User.new.tap do |u|
        u.authority_id = authority.id
        assign_initial_fields!(u, oauth_user)
      end
      user.deleted = false
      user
    end

    private def create_lookup(authority, oauth_user, user) : ::PlaceOS::Model::UserAuthLookup
      lookup = ::PlaceOS::Model::UserAuthLookup.new
      lookup.uid = oauth_user.uid
      lookup.provider = oauth_user.provider
      lookup.authority_id = authority.id
      lookup.user_id = user.id.as(String)
      lookup.save!
      lookup
    end

    private def find_existing_user_by_email(authority, oauth_user) : ::PlaceOS::Model::User?
      email = oauth_user.email.presence
      return nil if email.nil?
      ::PlaceOS::Model::User.find_by_email(authority.id.as(String), email)
    end

    # Fields we set ONLY at user creation — they describe the row's
    # identity and shouldn't be clobbered on subsequent logins.
    private def assign_initial_fields!(user, oauth_user) : Nil
      email = oauth_user.email.presence
      user.email = ::PlaceOS::Model::Email.new(email) if email
      user.name = oauth_user.name.presence || ""
    end

    # Fields we refresh on every login — keeps the local row in sync
    # with the IdP without overwriting user-set values that the
    # provider doesn't supply.
    private def apply_oauth_profile!(user, oauth_user) : Nil
      if (email = oauth_user.email.presence) && user.email.to_s.empty?
        user.email = ::PlaceOS::Model::Email.new(email)
      end
      if (name = oauth_user.name.presence)
        user.name = name
      end
      if (first = oauth_user.first_name.presence)
        user.first_name = first
      end
      if (last = oauth_user.last_name.presence)
        user.last_name = last
      end
      if (nickname = oauth_user.nickname.presence)
        user.nickname = nickname
      end
      if (phone = oauth_user.phone.presence)
        user.phone = phone
      end
      if (image = oauth_user.image.presence)
        user.image = image
      end

      # Stash the provider tokens so other PlaceOS services that need
      # to call the IdP on the user's behalf (calendar, mailbox, …)
      # have something to work with.
      case token = oauth_user.access_token
      when ::OAuth2::AccessToken::Bearer
        user.access_token = token.access_token
        user.refresh_token = token.refresh_token
        if expires_in = token.expires_in
          user.expires_at = (Time.utc + expires_in.seconds).to_unix
          user.expires = true
        end
      else
        # `OAuth::AccessToken` (OAuth 1.x) — unused for current providers.
      end
    end
  end
end
