require "multi_auth"
require "multi_auth/providers/generic_oauth2"
require "placeos-models"

module PlaceOS::Auth::OAuthProviders
  Log = ::PlaceOS::Auth::Log.for(self)

  # The single `provider` name we register with `multi_auth`. Every
  # incoming OAuth callback comes in as `/auth/oauth2/callback?id=<id>`
  # (or `/auth/oauth2/callback/<id>` for the legacy path-style alias);
  # the `<id>` selects which `OAuthAuthentication` row to load.
  PROVIDER_NAME = "oauth2"

  # Configures `multi_auth` with a single factory under the
  # `oauth2` provider name. The factory receives `(redirect_uri,
  # provider_id)` and returns a `GenericOAuth2` provider configured
  # from the matching `OAuthAuthentication` row.
  #
  # This replaces the OmniAuth `:generic_oauth` strategy from the
  # legacy Ruby service. The dynamic per-request lookup is exactly
  # how the Ruby strategy worked too — config lives in the DB, not
  # in initializer code.
  def self.register!
    ::MultiAuth.config(PROVIDER_NAME) do |redirect_uri, provider_id|
      build_provider(redirect_uri, provider_id)
    end
  end

  # Surfaces the strat that drives a given callback. The OAuth `id`
  # query parameter / path segment carries the `OAuthAuthentication`
  # primary key.
  def self.find_strat(provider_id : String?) : ::PlaceOS::Model::OAuthAuthentication?
    return nil if provider_id.nil? || provider_id.empty?
    ::PlaceOS::Model::OAuthAuthentication.find?(provider_id)
  end

  private def self.build_provider(redirect_uri : String, provider_id : String?) : ::MultiAuth::Provider
    strat = find_strat(provider_id)
    if strat.nil?
      raise ::MultiAuth::Exception.new("unknown oauth strategy: #{provider_id.inspect}")
    end

    ::MultiAuth::Provider::GenericOAuth2.new(
      provider_name: PROVIDER_NAME,
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
end

# Register at require time, same pattern as `AuthlyAdapter.configure!`.
PlaceOS::Auth::OAuthProviders.register!
