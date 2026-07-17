require "multi_auth"
require "multi_auth/providers/generic_oauth2"

# Patch: restore the comma-separated fallback semantics the legacy Ruby
# `generic_oauth` strategy had for `info_mappings`. Ruby treated each mapping
# value as a comma-separated fallback list (e.g.
# `email => "email,mail,userPrincipalName"`) and used the first key present in
# the provider's profile JSON — notably how Azure/Entra surfaces the email as
# `userPrincipalName`. multi_auth's `GenericOAuth2` does a single literal
# lookup, so a comma-list value resolves to `nil` and email/name/uid come back
# empty for any strat that relied on the fallback.
#
# We reopen the shard class here — the same technique `authly_adapter.cr` uses
# on the Authly shard — instead of forking the third-party `msa7/multi_auth`.
# `get_value_from_json` is the single choke point every mapped field flows
# through (including the getter-only `uid`/`name`, which are set at
# construction and can't be overridden after the fact), so patching it fixes
# all fields uniformly. `previous_def` reuses the shard's own dot-path +
# array-index walker per candidate key, so no lookup logic is duplicated.
class MultiAuth::Provider::GenericOAuth2
  private def get_value_from_json(json : JSON::Any, path : String) : String?
    return previous_def unless path.includes?(',')

    path.split(',').each do |key|
      key = key.strip
      next if key.empty?
      if (value = previous_def(json, key)) && !value.empty?
        return value
      end
    end
    nil
  end
end
