require "mutex"

module PlaceOS::Auth::Spec
  # Performs `POST /auth/signin` and returns the `Set-Cookie` value so
  # subsequent requests in the same spec can re-present it. Use:
  #
  #   user = Spec::Authentication.user(sys_admin: true)
  #   cookie = Spec.signin!(user, password: ...)
  #   client.get("/auth/somewhere", headers: HTTP::Headers{"Cookie" => cookie, "Host" => "localhost"})
  def self.signin!(client, user : PlaceOS::Model::User, password : String, continue : String? = nil) : String
    body = {email: user.email.to_s, password: password, continue: continue}.to_json
    headers = HTTP::Headers{
      "Host"         => "localhost",
      "Content-Type" => "application/json",
    }
    result = client.post("/auth/signin", headers: headers, body: body)
    raise "signin failed: #{result.status_code} #{result.body}" unless {202, 303}.includes?(result.status_code)
    set_cookie = result.headers["Set-Cookie"]?
    raise "signin did not return a Set-Cookie header" if set_cookie.nil?
    # Cookie header format echoes back only the name=value pair.
    set_cookie.split(';', 2).first.strip
  end
end

module PlaceOS::Auth::Spec::Authentication
  CREATION_LOCK = Mutex.new(protection: :reentrant)

  def self.authenticated(
    sys_admin : Bool = true,
    support : Bool = true,
    scope = [PlaceOS::Model::UserJWT::Scope::PUBLIC],
    groups = [] of String,
  ) : Tuple(Model::User, HTTP::Headers)
    authentication(sys_admin, support, scope, groups)
  end

  def self.user(sys_admin : Bool = true, support : Bool = true, scope = [PlaceOS::Model::UserJWT::Scope::PUBLIC], groups = [] of String) : Model::User
    CREATION_LOCK.synchronize do
      authenticated(sys_admin, support, scope, groups).first
    end
  end

  def self.headers(sys_admin : Bool = true, support : Bool = true, scope = [PlaceOS::Model::UserJWT::Scope::PUBLIC], groups = [] of String) : HTTP::Headers
    CREATION_LOCK.synchronize do
      authenticated(sys_admin, support, scope, groups).last
    end
  end

  # Authenticated user + `X-API-Key` header (replaces Authorization Bearer).
  def self.x_api_authentication(sys_admin : Bool = true, support : Bool = true, scope = [PlaceOS::Model::UserJWT::Scope::PUBLIC], groups = [] of String)
    CREATION_LOCK.synchronize do
      user, headers = authentication(sys_admin, support, scope, groups)
      email = user.email.to_s

      PlaceOS::Model::ApiKey.where(name: email).each &.destroy

      api_key = PlaceOS::Model::ApiKey.new(name: email)
      api_key.user = user
      api_key.x_api_key # ensure key generated
      api_key.save!

      headers.delete("Authorization")
      headers["X-API-Key"] = api_key.x_api_key.not_nil!

      {user, headers}
    end
  end

  # Authenticated user + Bearer JWT.
  #
  # We build the JWT manually rather than using `Model::Generator.jwt` because
  # the generator hard-codes `domain: Faker::Internet.email`, which doesn't
  # match the seeded authority domain (`localhost`) and trips
  # `ensure_matching_domain` in the real auth flow.
  def self.authentication(sys_admin : Bool = true, support : Bool = true, scope = [PlaceOS::Model::UserJWT::Scope::PUBLIC], groups = [] of String)
    CREATION_LOCK.synchronize do
      user = generate_auth_user(sys_admin, support, scope, groups)
      authority = user.authority.as(PlaceOS::Model::Authority)

      permissions = case ({user.support, user.sys_admin})
                    when {true, true}  then PlaceOS::Model::UserJWT::Permissions::AdminSupport
                    when {true, false} then PlaceOS::Model::UserJWT::Permissions::Support
                    when {false, true} then PlaceOS::Model::UserJWT::Permissions::Admin
                    else                    PlaceOS::Model::UserJWT::Permissions::User
                    end

      meta = PlaceOS::Model::UserJWT::Metadata.new(
        name: user.name,
        email: user.email.to_s,
        permissions: permissions,
        roles: user.groups,
      )

      jwt = PlaceOS::Model::UserJWT.new(
        iss: PlaceOS::Model::UserJWT::ISSUER,
        iat: 5.minutes.ago,
        exp: 1.hour.from_now,
        domain: authority.domain,
        id: user.id.as(String),
        user: meta,
        scope: scope,
      )

      headers = HTTP::Headers{
        "Authorization" => "Bearer #{jwt.encode}",
        "Content-Type"  => "application/json",
        "Host"          => "localhost",
      }

      {user, headers}
    end
  end

  def self.generate_auth_user(sys_admin, support, scopes, groups = [] of String)
    CREATION_LOCK.synchronize do
      authority = PlaceOS::Model::Authority.find_by_domain("localhost") || PlaceOS::Model::Generator.authority
      authority.domain = "localhost"
      authority.save!

      scope_list = scopes.try &.join('-', &.to_s)
      group_list = groups.join('-')
      test_user_email = PlaceOS::Model::Email.new(
        "test-#{"admin-" if sys_admin}#{"supp-" if support}scope-#{scope_list}-#{group_list}-auth@place.tech",
      )

      existing = PlaceOS::Model::User.where(email: test_user_email.to_s, authority_id: authority.id.as(String)).first?
      return existing if existing

      PlaceOS::Model::Generator.user(authority, support: support, admin: sys_admin).tap do |user|
        user.email = test_user_email
        user.groups = groups
        user.save!
      end
    end
  end
end
