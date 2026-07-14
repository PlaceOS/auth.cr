require "multi_auth"
require "multi_auth/providers/generic_oauth2"
require "multi_auth_saml"
require "placeos-models"

# Registers two `multi_auth` factory blocks — `oauth2` and `saml` —
# both driven by per-tenant rows in the DB. The `ProviderCallbacks`
# controller picks the right factory based on the `:provider` path
# segment; the `id` query/path parameter selects which row to load.
module PlaceOS::Auth::ExternalProviders
  Log = ::PlaceOS::Auth::Log.for(self)

  # OAuth2 callbacks come in as `/auth/oauth2/callback?id=<oauth_strat.id>`
  # (or the legacy path-style alias). Replaces the OmniAuth
  # `:generic_oauth` strategy from the Ruby service.
  OAUTH2_PROVIDER = "oauth2"

  # SAML callbacks. The legacy Ruby service registered its SAML strategy
  # under the OmniAuth name `adfs` (`generic_adfs`), so that name is
  # baked into external IdP registrations, the `/auth/adfs` kickoff and
  # callback paths, the login-event payload, and — critically — the
  # `UserAuthLookup` id (`auth-<authority>-adfs-<uid>`). We must reuse it
  # verbatim, or existing SAML-linked accounts won't resolve after the
  # swap. `saml` is kept as an internal alias (auth.cr-era callers), but
  # the recorded provider name is always `adfs`.
  SAML_PROVIDER       = "adfs"
  SAML_PROVIDER_ALIAS = "saml"

  def self.register!
    ::MultiAuth.config(OAUTH2_PROVIDER) do |redirect_uri, provider_id|
      build_oauth2(redirect_uri, provider_id)
    end

    ::MultiAuth.config(SAML_PROVIDER) do |redirect_uri, provider_id|
      build_saml(redirect_uri, provider_id)
    end

    ::MultiAuth.config(SAML_PROVIDER_ALIAS) do |redirect_uri, provider_id|
      build_saml(redirect_uri, provider_id)
    end
  end

  # ---- OAuth2 -------------------------------------------------------

  def self.find_oauth_strat(provider_id : String?) : ::PlaceOS::Model::OAuthAuthentication?
    return nil if provider_id.nil? || provider_id.empty?
    ::PlaceOS::Model::OAuthAuthentication.find?(provider_id)
  end

  private def self.build_oauth2(redirect_uri : String, provider_id : String?) : ::MultiAuth::Provider
    strat = find_oauth_strat(provider_id)
    if strat.nil?
      raise ::MultiAuth::Exception.new("unknown oauth strategy: #{provider_id.inspect}")
    end

    ::MultiAuth::Provider::GenericOAuth2.new(
      provider_name: OAUTH2_PROVIDER,
      redirect_uri: redirect_uri,
      key: strat.client_id,
      secret: strat.client_secret,
      site: strat.site,
      authorize_url: strat.authorize_url,
      token_url: strat.token_url,
      authentication_scheme: strat.auth_scheme,
      user_profile_url: strat.raw_info_url || "",
      scopes: strat.scope,
      info_mappings: strat.info_mappings,
    )
  end

  # ---- SAML ---------------------------------------------------------

  def self.find_saml_strat(provider_id : String?) : ::PlaceOS::Model::SamlAuthentication?
    return nil if provider_id.nil? || provider_id.empty?
    ::PlaceOS::Model::SamlAuthentication.find?(provider_id)
  end

  private def self.build_saml(redirect_uri : String, provider_id : String?) : ::MultiAuth::Provider
    strat = find_saml_strat(provider_id)
    if strat.nil?
      raise ::MultiAuth::Exception.new("unknown saml strategy: #{provider_id.inspect}")
    end

    # Advertise the DB-configured ACS URL — exactly what the IdP has
    # registered and what the legacy service sent
    # (`options.assertion_consumer_service_url = strat.assertion_consumer_service_url`).
    # `multi_auth_saml` uses `redirect_uri` as the ACS URL, so pass the
    # DB value straight through (falling back to the computed callback
    # only if the column is somehow blank).
    acs_url = strat.assertion_consumer_service_url.presence || redirect_uri

    ::MultiAuth::Provider::SAML.new(
      provider_name: SAML_PROVIDER,
      redirect_uri: acs_url,
      idp_sso_url: strat.idp_sso_target_url,
      idp_cert: strat.idp_cert,
      idp_cert_fingerprint: strat.idp_cert_fingerprint,
      sp_entity_id: strat.issuer,
      name_identifier_format: strat.name_identifier_format,
      uid_attribute: strat.uid_attribute,
      attribute_statements: saml_attribute_mapping(strat),
      want_assertions_signed: strat.idp_cert.presence || strat.idp_cert_fingerprint.presence ? true : false,
      want_signature_validated: strat.idp_cert.presence || strat.idp_cert_fingerprint.presence ? true : false,
    )
  end

  # `SamlAuthentication.attribute_statements` is stored as
  # `Hash(String, Array(String))` (e.g. `{"email" => ["email", "mail"]}`),
  # but `multi_auth_saml` reads it with hard-coded symbol keys (it only
  # looks for `:name`, `:email`, `:first_name`, `:last_name`,
  # `:nickname` — see `multi_auth_saml/provider.cr#user`). String keys
  # outside that vocabulary are dropped silently — they wouldn't have
  # had a destination field on `MultiAuth::User` anyway.
  private def self.saml_attribute_mapping(strat) : Hash(Symbol, Array(String))
    mapping = Hash(Symbol, Array(String)).new
    strat.attribute_statements.each do |key, values|
      symbol_key = case key
                   when "name"       then :name
                   when "email"      then :email
                   when "first_name" then :first_name
                   when "last_name"  then :last_name
                   when "nickname"   then :nickname
                   end
      mapping[symbol_key] = values if symbol_key
    end
    mapping
  end
end

# Register at require time, same pattern as `AuthlyAdapter.configure!`.
PlaceOS::Auth::ExternalProviders.register!
