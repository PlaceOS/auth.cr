# Route parity matrix — Ruby auth → auth.cr (PPT-2536)

Contract source of truth: the Rails service at its locked gem versions
(doorkeeper 5.9.2, doorkeeper-openid_connect 1.10.1, doorkeeper-jwt 0.4.2 —
`auth/Gemfile.lock`), with deployment config from
`auth/config/initializers/doorkeeper*.rb`. `routes_rails.txt` is the
`rails routes` dump; `routes_auth_cr_before.txt` is auth.cr master at the
start of this work (fa87af7). Run `./auth_migration/route_diff.sh` to check
the live table.

Legend: ✅ implemented & matching · 🟰 pre-existing parity (Mia's PR #1) ·
📝 implemented with documented divergence · ⏸ intentionally not implemented
(pending sign-off) · ➕ auth.cr extra (additive, allowlisted in route_diff.sh)

## OAuth2 / OIDC server surface

| Rails route | Status | Notes |
|---|---|---|
| POST /auth/oauth/token | 🟰 | + unprefixed alias ➕ |
| GET /auth/oauth/authorize | 🟰 | code flow only — implicit/password deliberately dropped |
| POST /auth/oauth/authorize | ✅ | same semantics as GET (Rails consent screen never renders: `skip_authorization { true }`, so create == immediate grant) |
| DELETE /auth/oauth/authorize | ✅ | deny → 302 `redirect_uri?error=access_denied&error_description=…` |
| GET /auth/oauth/authorize/native | ✅ | 200 HTML echoing `?code=` (OOB flow; no OOB redirect URIs exist in any known deployment) |
| POST /auth/oauth/revoke | 🟰 | RFC 7009; always 200 |
| POST /auth/oauth/introspect | ✅ | RFC 7662; client-credentials (Basic or params) or foreign-bearer auth; `{"active":false}` for unknown/expired/cross-client-invisible; 400/401 error family with `WWW-Authenticate` |
| GET /auth/oauth/token/info | ✅ | `{resource_owner_id, scope: [array], expires_in: remaining, application: {uid}, created_at}`; 401 `invalid_token` family |
| GET+POST /auth/oauth/userinfo | 📝 | Both verbs served. **Divergence (superset):** Rails effectively returned only `{"sub"}` because `profile`/`email`/`phone` were never registered as issuable scopes; auth.cr returns the full ID-token claim set. Auth: any valid bearer (Rails required `openid` scope; 401/403 empty-body split not replicated — auth.cr returns its standard JSON error envelope) |
| GET /auth/oauth/discovery/keys | ✅ | JWKS derived from JWT_SECRET public key: `{kty, n, e, kid (RFC 7638 thumbprint), use: "sig", alg: "RS256"}`. NB Rails signed with the same RSA key; a symmetric-key deployment could never publish usable JWKS |
| /auth/oauth/applications CRUD (7 routes) | 📝 | Admin-gated on a signed-in sys_admin; non-admins get **404** (Doorkeeper's invisible-resource intent). JSON parity incl. the gem's quirks: index → **204 empty**, create/show/update → 200 full record **including plaintext secret**, destroy → 204, validation failure → 422 `{"errors": […]}`. **Divergence:** `new`/`edit` serve a minimal placeholder HTML form rather than the gem's full admin views (the real admin UI is rest-api `/oauth_apps` + Backoffice, which fully supersede these routes) |
| GET /auth/oauth/authorized_applications, DELETE /:id | 📝 | Session-scoped to the resource owner; index → JSON array of public app shapes; destroy revokes the user's **tokens** for that app, 204. **Divergences:** (1) grants aren't revoked separately — auth.cr doesn't persist grant records (authly grant codes are short-lived, 10 min); (2) an unauthenticated caller gets **401** (JSON) rather than Doorkeeper's browser redirect to login |

## Discovery / well-known

| Rails route | Status | Notes |
|---|---|---|
| GET /.well-known/openid-configuration | 🟰📝 | Endpoint fields now advertise the `/auth/oauth/*` mounts + `jwks_uri` + `introspection_endpoint`. **Divergences (deliberate):** `response_types_supported`/`grant_types_supported` list only what auth.cr actually supports (no implicit/password — Rails advertised both, incl. the pseudo-flow `implicit_oidc`); `code_challenge_methods_supported: ["S256"]` is advertised (auth.cr supports PKCE; Rails omitted it — its schema lacked the grant columns entirely) |
| GET /.well-known/oauth-authorization-server | ✅ | RFC 8414 alias, same document |
| GET /auth/.well-known/openid-configuration + oauth-authorization-server | ✅ | `scope :auth` mount variants |
| GET /.well-known/webfinger + /auth/.well-known/webfinger | ✅ | `{subject: <resource>, links: [{rel: …issuer, href: <issuer>}]}`; 400 without `resource` (Rails ParameterMissing behaviour) |
| — | ⚠ | **The Rails endpoints in this section 500 at the locked gem versions** (doorkeeper-openid_connect 1.10.1 issuer-block arity regression vs the 1.8-era initializer). auth.cr implements the documented *intent* (`https://<request host>`); i.e. these routes work here and are broken in the legacy service |

## Sessions / identity

| Rails route | Status | Notes |
|---|---|---|
| GET /auth/login, /auth/logout; POST /auth/signin | 🟰 | incl. form-encoded signin bodies |
| GET+POST /auth/:provider/callback (+/:strategy) | 🟰 | + GET /auth/:provider initiate ➕ (OmniAuth request phase was Rack middleware, invisible to `rails routes`) |
| POST /auth/signup | 📝 | Route served, returns **403** (empty). Faithful because Ruby only completed a signup with a valid short-lived `social` cookie, which auth.cr never issues (OAuth users are auto-created in the callback) — so 403 is the only state reachable in either service. **The user-creation path itself stays intentionally dropped** (README) — resurrecting it is a separate product decision for Stephen; the full contract is in tasks/PPT-2536 investigation dive 2 §11 |
| GET /auth/failure | 🟰 | |
| GET /auth/authority | 🟰 | |
| catch-all /*any → 404 | ✅ | 404 with empty body on all verbs/unmatched paths under the service |

## Accepted wire differences (recorded, not bugs)

1. **Format suffixes**: every Rails route tolerated `(.:format)` (e.g. `/auth/authority.json`); auth.cr routes do not — such URLs 404. No known caller uses suffixes.
2. **Error body shapes**: auth.cr uses its consistent JSON error envelope (`{error, error_description}` for OAuth; `{error: message}` common) where Rails variously produced empty bodies, HTML error pages, or Doorkeeper JSON. Statuses match; bodies may not, except where a shape is load-bearing (token, introspect, token/info, discovery — matched exactly).
3. **userinfo claims**: superset (see matrix row).
4. **Discovery capability lists**: honest advertisement vs Rails' aspirational one (see matrix row).
5. `GET /auth/healthz` and the unprefixed `/auth/{token,authorize,revoke,userinfo}` + `/auth/:provider` initiate are auth.cr additions, allowlisted in `route_diff.sh`.
