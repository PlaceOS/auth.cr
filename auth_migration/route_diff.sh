#!/usr/bin/env bash
# Route-parity checker for the Ruby auth -> auth.cr migration (PPT-2536).
#
# Normalizes both route tables (upcased verb, stripped `(.:format)`,
# sorted `VERB PATH` pairs) and diffs them, ignoring documented
# intentional differences (see allowlists below and parity_matrix.md).
#
# Usage:
#   ./auth_migration/route_diff.sh                 # builds + prints diff
#   ./auth_migration/route_diff.sh path/to/binary  # use an existing build
set -euo pipefail

cd "$(dirname "$0")/.."

BINARY="${1:-bin/placeos-auth}"
RAILS_ROUTES="auth_migration/routes_rails.txt"

if [[ ! -x "$BINARY" ]]; then
  echo "building $BINARY ..." >&2
  shards build >/dev/null
fi

# --- Rails side -------------------------------------------------------------
# Keep lines that contain a verb + /path; strip route names, formats.
# The catch-all `/*any` line has no verb and is handled as an allowlisted
# behaviour (404 on unmatched paths) rather than a routable entry.
rails_normalized() {
  awk '{
    for (i = 1; i <= NF; i++) {
      if ($i ~ /^(GET|POST|PUT|PATCH|DELETE)$/ && $(i+1) ~ /^\//) {
        path = $(i+1)
        sub(/\(\.:format\)$/, "", path)
        print $i, path
      }
    }
  }' "$RAILS_ROUTES" | sort -u
}

# --- auth.cr side -----------------------------------------------------------
authcr_normalized() {
  "$BINARY" --routes | awk 'NR > 1 && NF >= 3 {
    verb = toupper($(NF-1)); path = $NF
    if (path ~ /^\//) print verb, path
  }' | sort -u
}

# --- Intentional differences (documented in parity_matrix.md) ----------------
# auth.cr extras: additive, harmless. Every OAuth endpoint is served at
# both the short /auth/* path and the legacy /auth/oauth/* mount; Rails
# only had the /oauth/* form for some, so the short forms show as extras.
AUTHCR_EXTRA_ALLOWLIST='^(GET /auth/healthz|POST /auth/token|GET /auth/authorize|POST /auth/authorize|DELETE /auth/authorize|GET /auth/authorize/native|POST /auth/revoke|GET /auth/userinfo|POST /auth/userinfo|POST /auth/introspect|GET /auth/token/info|GET /auth/:provider)$'
# Rails-only entries accepted as intentionally absent (pending decisions
# are listed in parity_matrix.md; remove entries here as they are closed).
RAILS_ONLY_ALLOWLIST='^$'

rails_only=$(comm -23 <(rails_normalized) <(authcr_normalized) | grep -Ev "$RAILS_ONLY_ALLOWLIST" || true)
authcr_only=$(comm -13 <(rails_normalized) <(authcr_normalized) | grep -Ev "$AUTHCR_EXTRA_ALLOWLIST" || true)

status=0
if [[ -n "$rails_only" ]]; then
  echo "MISSING from auth.cr (present in Rails):"
  echo "$rails_only" | sed 's/^/  /'
  status=1
fi
if [[ -n "$authcr_only" ]]; then
  echo "UNEXPECTED extras in auth.cr (not in Rails, not allowlisted):"
  echo "$authcr_only" | sed 's/^/  /'
  status=1
fi
[[ $status -eq 0 ]] && echo "route parity: OK"
exit $status
