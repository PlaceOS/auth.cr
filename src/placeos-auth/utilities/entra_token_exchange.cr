require "http/client"
require "jwt"
require "jwt/jwks"
require "multi_auth"
require "oauth2"
require "placeos-models"

module PlaceOS::Auth
  # RFC 8693 token exchange for Microsoft Entra ID access tokens.
  #
  # An Outlook add-in (or any Entra-signed-in app — Intune-managed clients
  # get the same tokens via the broker) already holds an Entra access token
  # for the authority's app registration. This verifies that token and
  # resolves the PlaceOS user it names, so the token endpoint can mint a
  # PlaceOS token without a second interactive login.
  #
  # Replaces rest-api's `Utils::MSTokenExchange`, which accepted Entra tokens
  # directly as API bearer tokens. The important differences:
  #
  #   * The trust anchor comes from CONFIGURATION, never the token. The
  #     tenant is read from the authority's `oauth_strat` URLs and the
  #     issuer + signing keys from that tenant's discovery document; the
  #     token's `iss` must equal it exactly. Fetching keys from whatever
  #     `iss` the token claims lets anyone who hosts a discovery document
  #     sign their own tokens.
  #   * `aud` must name the strat's own app registration, so a token minted
  #     for some other API (Graph, another app in the tenant) is refused.
  #   * Only delegated (user) tokens are accepted — app-only tokens carry
  #     no user and are refused.
  module Utils::EntraTokenExchange
    extend self

    Log = ::PlaceOS::Auth::Log.for(self)

    GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"

    TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
    TOKEN_TYPE_JWT          = "urn:ietf:params:oauth:token-type:jwt"
    SUBJECT_TOKEN_TYPES     = {TOKEN_TYPE_ACCESS_TOKEN, TOKEN_TYPE_JWT}

    # Entra sign-in hosts, public and sovereign clouds. Matched exactly
    # against the strat's configured URLs: a suffix match would also accept
    # e.g. `evilmicrosoftonline.com`.
    LOGIN_HOSTS = {
      "login.microsoftonline.com",
      "login.windows.net",
      "login.microsoftonline.us",
      "login.chinacloudapi.cn",
      "login.partner.microsoftonline.cn",
      "login.microsoftonline.de",
    }

    GRAPH_RESOURCES = {
      "login.microsoftonline.us"         => "https://graph.microsoft.us/",
      "login.chinacloudapi.cn"           => "https://microsoftgraph.chinacloudapi.cn/",
      "login.partner.microsoftonline.cn" => "https://microsoftgraph.chinacloudapi.cn/",
    }

    # Multi-tenant authority segments. A strat configured with one of these
    # has no single tenant to pin, so it cannot anchor an exchange.
    SHARED_TENANTS = {"common", "organizations", "consumers"}

    GUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i

    # The subject token was refused. The message is for logs only — the
    # client sees a generic `invalid_grant`.
    class Rejected < ::Exception
    end

    record Verified, strat : ::PlaceOS::Model::OAuthAuthentication, claims : JSON::Any

    # Discovery documents and JWKS, cached by the shard (10 minutes, or the
    # JWKS response's `max-age`).
    class_property jwks : JWT::JWKS { JWT::JWKS.new }

    # Verifies `token` against the Entra strats configured on `authority`,
    # returning the claims and the strat that vouched for them.
    def verify(authority : ::PlaceOS::Model::Authority, token : String) : Verified
      strats = ::PlaceOS::Model::OAuthAuthentication.where(authority_id: authority.id.as(String)).to_a
      verify(authority, token, strats)
    end

    def verify(authority : ::PlaceOS::Model::Authority, token : String, strats : Enumerable(::PlaceOS::Model::OAuthAuthentication)) : Verified
      unverified, header = begin
        JWT.decode(token, verify: false, validate: false)
      rescue ex : JWT::Error
        raise Rejected.new("subject_token is not a JWT")
      end

      iss = unverified["iss"]?.try(&.as_s?) || raise Rejected.new("subject_token has no iss")
      audiences = audiences_of(unverified)
      raise Rejected.new("subject_token has no aud") if audiences.empty?

      strat = strats.find { |candidate| audiences.any? { |aud| audience_matches?(aud, candidate, authority) } }
      raise Rejected.new("no oauth strat on this authority matches the token audience") unless strat

      login_host, tenant = entra_tenant(strat) || raise Rejected.new("matching oauth strat is not a single-tenant Entra strat")

      # v1 and v2 tokens have different issuers, each published by its own
      # discovery document. Pick by the token's claim, then require an
      # exact match against what the configured tenant publishes.
      base = "https://#{login_host}/#{tenant}"
      metadata = begin
        jwks.fetch_oidc_metadata(iss.ends_with?("/v2.0") ? "#{base}/v2.0" : base)
      rescue ex
        raise Rejected.new("unable to load Entra discovery for tenant #{tenant}: #{ex.message}")
      end
      raise Rejected.new("subject_token iss #{iss} is not the configured tenant's issuer") unless iss == metadata.issuer

      claims = verify_signature(token, header, metadata)
      enforce_claims!(claims, metadata, audiences)

      Verified.new(strat, claims)
    end

    # Builds the `MultiAuth::User` that a browser SSO login through `strat`
    # would have produced, so `OAuthUserMapper` resolves the same
    # `UserAuthLookup` and the exchange and SSO paths share one account.
    #
    # The strat's `info_mappings` are written against the Graph `/me`
    # profile (`id`, `mail`, `userPrincipalName`, ...), so the token claims
    # are projected onto those names alongside the raw claim names.
    def oauth_user(verified : Verified) : ::MultiAuth::User
      claims = verified.claims
      profile = graph_profile(claims)
      mappings = verified.strat.info_mappings

      mapped = ->(field : String, fallback : String) {
        lookup(profile, mappings[field]? || fallback)
      }

      uid = mapped.call("uid", "id") || raise Rejected.new("subject_token has no oid")

      user = ::MultiAuth::User.new(
        ExternalProviders::OAUTH2_PROVIDER,
        uid,
        mapped.call("name", "displayName"),
        profile.to_json,
        # No IdP token is carried over from the exchange itself; an empty
        # bearer is skipped by the mapper rather than overwriting the user's
        # stored Graph token. See `ensure_graph_token`.
        ::OAuth2::AccessToken::Bearer.new("", nil),
      )
      user.email = mapped.call("email", "mail,userPrincipalName")
      user.first_name = mapped.call("first_name", "givenName")
      user.last_name = mapped.call("last_name", "surname")
      user
    end

    # Obtains a delegated Graph token on the user's behalf (OAuth 2.0
    # on-behalf-of) when the user has no unexpired one, so services acting
    # on the user's mailbox / calendar keep working for users who only ever
    # authenticate through the add-in. Best-effort: a failure is logged and
    # the exchange still succeeds, as in rest-api.
    def ensure_graph_token(verified : Verified, user : ::PlaceOS::Model::User, subject_token : String) : Nil
      if user.access_token.presence && (expires_at = user.expires_at) && expires_at > 5.minutes.from_now.to_unix
        return
      end

      strat = verified.strat
      endpoint = strat_url(strat, strat.token_url)
      return unless endpoint

      v2 = endpoint.path.includes?("/v2.0/")
      form = URI::Params.build do |params|
        params.add "grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"
        params.add "client_id", strat.client_id
        params.add "client_secret", strat.client_secret
        params.add "assertion", subject_token
        params.add "requested_token_use", "on_behalf_of"
        if v2
          params.add "scope", strat.scope
        else
          params.add "resource", GRAPH_RESOURCES[endpoint.host]? || "https://graph.microsoft.com/"
        end
      end

      client = HTTP::Client.new(endpoint)
      client.connect_timeout = 3.seconds
      client.read_timeout = 5.seconds
      response = client.post(endpoint.request_target, headers: HTTP::Headers{"Accept" => "application/json"}, form: form)

      unless response.success?
        Log.warn { {action: "token_exchange.obo", message: "on-behalf-of Graph token request failed", status: response.status_code, user_id: user.id} }
        return
      end

      token = ::OAuth2::AccessToken.from_json(response.body)
      user.access_token = token.access_token
      user.refresh_token = token.refresh_token if token.refresh_token
      if expires_in = token.expires_in
        user.expires_at = expires_in.seconds.from_now.to_unix
        user.expires = true
      end
      user.save!
    rescue ex
      Log.warn(exception: ex) { {action: "token_exchange.obo", message: "on-behalf-of Graph token request failed", user_id: user.id} }
    end

    # ---- audience ---------------------------------------------------------

    # `aud` is the strat's client id (v2 tokens), or one of the App ID URIs
    # Entra issues for it: `api://<client id>`, or — required by Office
    # add-in SSO — `api://<add-in host>/<client id>`, where the host is this
    # authority's domain.
    def audience_matches?(aud : String, strat : ::PlaceOS::Model::OAuthAuthentication, authority : ::PlaceOS::Model::Authority) : Bool
      client_id = strat.client_id
      return false if client_id.empty?
      return true if aud == client_id || aud == "api://#{client_id}"

      host = URI.parse(authority.domain).host.presence || authority.domain
      aud == "api://#{host}/#{client_id}"
    rescue URI::Error
      false
    end

    private def audiences_of(claims : JSON::Any) : Array(String)
      case raw = claims["aud"]?.try(&.raw)
      when String           then [raw]
      when Array(JSON::Any) then raw.compact_map(&.as_s?)
      else                       [] of String
      end
    end

    # ---- tenant -----------------------------------------------------------

    # `{login host, tenant}` for an Entra strat, read from the configured
    # token / authorize URLs (`https://login.microsoftonline.com/<tenant>/oauth2/...`).
    # `nil` for non-Entra strats and for multi-tenant (`common`, ...) ones.
    def entra_tenant(strat : ::PlaceOS::Model::OAuthAuthentication) : Tuple(String, String)?
      {strat.token_url, strat.authorize_url}.each do |configured|
        uri = strat_url(strat, configured)
        next unless uri
        host = uri.host.try(&.downcase)
        next unless host && LOGIN_HOSTS.includes?(host)

        tenant = uri.path.split('/', remove_empty: true).first?
        next unless tenant
        next if SHARED_TENANTS.includes?(tenant.downcase)
        return {host, tenant}
      end
      nil
    end

    # Strat URLs may be absolute or relative to `site`.
    private def strat_url(strat, configured : String) : URI?
      uri = URI.parse(configured)
      uri = URI.parse(strat.site).resolve(uri) unless uri.absolute?
      uri.scheme == "https" ? uri : nil
    rescue URI::Error
      nil
    end

    # ---- signature + claims -----------------------------------------------

    private def verify_signature(token : String, header : Hash(String, JSON::Any), metadata) : JSON::Any
      # Entra signs access tokens with RS256 only; pinning it rules out
      # algorithm-confusion games with the header.
      unless header["alg"]?.try(&.as_s?) == "RS256"
        raise Rejected.new("subject_token is not RS256 signed")
      end
      kid = header["kid"]?.try(&.as_s?) || raise Rejected.new("subject_token has no kid")

      key = begin
        set = jwks.fetch_jwks(metadata.jwks_uri)
        jwks.find_key(set, kid) || jwks.find_key(jwks.fetch_jwks(metadata.jwks_uri, force_refresh: true), kid)
      rescue ex
        raise Rejected.new("unable to load Entra signing keys: #{ex.message}")
      end
      raise Rejected.new("subject_token kid #{kid} is not a signing key of the tenant") unless key
      raise Rejected.new("signing key #{kid} is not RSA") unless key.kty == "RSA"

      payload, _ = JWT.decode(token, key.to_pem, JWT::Algorithm::RS256, verify: true, validate: true)
      payload
    rescue ex : JWT::Error
      raise Rejected.new("subject_token failed verification: #{ex.message}")
    end

    private def enforce_claims!(claims : JSON::Any, metadata, audiences : Array(String)) : Nil
      # `JWT.decode` checks `exp` only when present.
      raise Rejected.new("subject_token has no exp") unless claims["exp"]?.try(&.as_i64?)

      # The issuer pins the tenant already; `tid` is checked as well so a
      # discrepancy between the two can never be papered over.
      tenant_id = metadata.issuer[GUID]?
      unless tenant_id && claims["tid"]?.try(&.as_s?).try(&.downcase) == tenant_id.downcase
        raise Rejected.new("subject_token tid does not match the configured tenant")
      end

      # Delegated tokens carry `scp`; app-only (client credentials) tokens
      # carry `roles` instead and identify no user.
      unless claims["scp"]?.try(&.as_s?).presence
        raise Rejected.new("subject_token is not a delegated user token")
      end
      unless claims["oid"]?.try(&.as_s?).presence
        raise Rejected.new("subject_token has no oid")
      end
    end

    # ---- profile ----------------------------------------------------------

    private def graph_profile(claims : JSON::Any) : Hash(String, JSON::Any)
      profile = claims.as_h.dup
      claim = ->(name : String) { claims[name]?.try(&.as_s?).presence }

      upn = claim.call("upn") || claim.call("preferred_username") || claim.call("unique_name")
      {
        "id"                => claim.call("oid"),
        "mail"              => claim.call("email") || upn,
        "userPrincipalName" => upn,
        "displayName"       => claim.call("name"),
        "givenName"         => claim.call("given_name"),
        "surname"           => claim.call("family_name"),
      }.each do |key, value|
        profile[key] = JSON::Any.new(value) if value && !profile.has_key?(key)
      end
      profile
    end

    # Resolves an `info_mappings` value, honouring the comma-separated
    # fallback list the legacy strategy supported (see `multi_auth_patch`).
    private def lookup(profile : Hash(String, JSON::Any), keys : String) : String?
      keys.split(',').each do |key|
        if value = profile[key.strip]?.try(&.as_s?).presence
          return value
        end
      end
      nil
    end
  end
end
