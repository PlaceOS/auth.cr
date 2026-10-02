# auth.cr — tasks

Granular checklist that mirrors `PLAN.md`. Check off as we go; capture corrections in `lessons.md`.

## Phase 0 — Scaffolding
- [x] Cut `auth-replacement` branch on `../models` (push to origin deferred until first commit lands)
- [x] Update `shard.yml`: `placeos-models` (branch ref), `multi_auth`, `multi_auth_saml`, `authly`, `pg-orm`, `jwt`, `secrets-env`, `redis`
- [x] Port `src/constants.cr` (APP_NAME, VERSION, JWT_SECRET, PLACE_URI, session cookie name, OIDC issuer)
- [x] Port `src/config.cr` (middleware: ErrorHandler, LogHandler with redacted fields)
- [x] Port `src/logging.cr` (placeos-log-backend setup + signal-driven level switching)
- [x] Rewrite `src/app.cr` (OptionParser, PgORM bootstrap, server start with cluster mode)
- [x] Add `src/placeos-auth.cr` module entrypoint + `src/placeos-auth/error.cr`
- [x] `src/placeos-auth/controllers/application.cr` base controller + `controllers/root.cr` healthz
- [x] Port `spec/helper.cr` + `spec/spec_helpers/{authentication,client,spec}.cr` (no ES)
- [x] `spec/controllers/root_spec.cr` healthz smoke test
- [x] Add `./test` script + `docker-compose.yml` (Postgres + Redis + migrator)
- [x] `spec/migration/{Dockerfile,run.sh,shard.yml,src/migration.cr}` cloning models@auth-replacement
- [x] Mirror `rest-api/.github/workflows/{ci,build}.yml`
- [x] Update `Dockerfile` for the renamed binary (`placeos-auth`) and `/auth/healthz` probe
- [x] Verify type-checks (`crystal build --no-codegen src/app.cr`), `crystal tool format --check`, `./bin/ameba` clean — all green
- [ ] Run `./test` end-to-end (deferred — verify in a subagent after first real spec lands)

## Phase 1 — Foundations
- [x] `ApplicationController` base — authority resolution by host (`current_authority` memoized getter)
- [x] Auth parser: X-API-Key → Bearer JWT precedence (cookie session deferred to Phase 2 when `Sessions#signin` lands)
- [x] Error handler exceptions (Unauthorized, Forbidden, NotFound, ModelValidation) — wired in Phase 0
- [ ] Encrypted cookie helpers — deferred to Phase 2 (consumed by `Sessions#signin`)
- [x] `Authorities#current` (GET `/auth/authority`) — including ?health probe semantics
- [x] Spec: `spec/controllers/authorities_spec.cr` — 5 specs, all green (happy path, 404, health, Bearer JWT, X-API-Key, malformed bearer)
- [x] `./test` runs 7/7 green

## Phase 2 — Local auth
- [x] `ActionController::Session` configured (`_coauth_session`, path=`/auth`, encrypted, secret from `COOKIE_SESSION_SECRET`)
- [x] `Utils::SessionHelper` mixin: `new_session`, `remove_session`, `session_user`, `signed_in?`, `set_continue`, `consume_continue`, `sanitize_continue`
- [x] `Sessions#signin` (POST `/auth/signin`) — bcrypt verify, set session, optional 303 redirect or 202
- [x] `Sessions#destroy` (GET `/auth/logout`) — stamps `logged_out_at`, clears session, safe redirect
- [x] `Sessions#new` (GET `/auth/login`) — continue validation, provider redirect, inline API-key short-circuit, fallback to `authority.login_url` with `{{url}}` substitution
- [x] `Failures#show` (GET `/auth/failure`) — 401 HTML
- [x] `signed_in?` wired into `Authorities#current` response
- [x] Specs: 10 sessions + 1 failures + 6 authorities + 1 root = 18 specs, all green
- [ ] Doorkeeper token revocation on logout — deferred to Phase 3 when authly token store lands

## Phase 3 — OAuth2 / OIDC server (authly)
- [x] `AuthlyAdapter::Owner` against `User` (id_token only — password grant disabled)
- [x] `AuthlyAdapter::Client` against `DoorkeeperApplication` (uid lookup, grant-type allowlist, scope guard)
- [x] `AuthlyAdapter::ClaimsProvider` — emits `u:{n,e,p,r}` + `aud=authority.domain`
- [x] JWT signing config (RS256, `JWT_SECRET` env, derives public key)
- [x] `Authly.configure!` runs at require time so spec env + prod both wired
- [x] OAuth controller — POST `/auth/token` (client_credentials, authorization_code, refresh_token) + GET `/auth/authorize` (code flow)
- [x] Reject `grant_type=password` with `unsupported_grant_type`
- [x] Open-class patch for `Authly::Code#jwt` to read live `Authly.config.{issuer,code_ttl}` (upstream captures at load time)
- [x] Specs: client_credentials happy + 401 unknown + 401 bad secret + password rejection + unknown grant + authorization_code → refresh round-trip + authorize redirect/unauth/unknown response_type/unregistered redirect — 9 specs all green
- [x] OAuthToken model + migration added to placeos-models@auth-replacement, pushed
- [x] `AuthlyAdapter::TokenStore` — PG-backed, jti-keyed, marker-row on revoke-without-store
- [x] `Authly.config.persist_jwt_tokens = true`
- [x] `POST /auth/revoke` (RFC 7009; always 200)
- [x] `GET /auth/userinfo` (Bearer-required, OIDC claims via Owner#id_token)
- [x] `GET /.well-known/openid-configuration` (separate `Discovery < Application` controller mounted at `/`)
- [x] `Sessions#destroy` revokes any presented Bearer JWT
- [x] Specs: revoke happy + revoke unknown + userinfo happy + userinfo 401 + discovery (32/32 ./test green)

## Phase 4 — OAuth2 client (multi_auth)
- [x] Per-request multi_auth provider registration from `oauth_strat` (factory under `oauth2` name)
- [x] `ProviderCallbacks` controller — `GET /auth/:provider` kickoff + `GET/POST /auth/:provider/callback` consume
- [x] `Utils::OAuthUserMapper` covering all three branches: existing lookup (login), no-lookup + signed-in (link), no-lookup + anonymous (auto-create)
- [x] Path alias `/auth/:provider/callback/:strategy`
- [x] CSRF state validation via the session cookie
- [x] Specs: 5 — kickoff redirect, kickoff 404 unknown strat, callback creates user, state mismatch 401, existing lookup logs in
- [x] `./test`: 37/37 green
- [ ] Azure B2C redirect rewrite — deferred until a concrete tenant needs it
- [ ] `before_signup` extension hook — wired in Phase 6 alongside `after_login`

## Phase 5 — SAML / ADFS
- [x] Per-request `multi_auth_saml` provider registration from `adfs_strat` rows (factory under `saml` name)
- [x] SAML callbacks share `ProviderCallbacks#callback` with OAuth (same user-mapping + state-validation path)
- [x] Smoke specs: kickoff redirect with SAMLRequest, 404 unknown strat
- [x] Full SAMLResponse signature-validation round-trip deferred — `multi_auth_saml`'s own spec suite covers SAML XML parsing; the auth.cr-specific bits (user mapping, state check) are exercised through the shared code path by `provider_callbacks_spec.cr`

## Phase 6 — Extensions
- [x] Redis login event publisher (`LoginEvents.publish` → `placeos/auth/login`)
- [x] Wired into `Sessions#signin` (provider="internal") and `ProviderCallbacks#callback` (provider=oauth_user.provider)
- [x] Test-swappable publisher (`LoginEvents.publisher` class_property)
- [x] Specs: signin → "internal" event, OAuth callback → provider name event (2 specs)
- [ ] Crystal-native `before_signup` / `after_login` hooks — deferred. The Ruby version was a Rails-initialiser plug-in pattern; auth.cr is a standalone binary so there's no obvious consumer. Add when a concrete need arises.
- [x] X-API-Key header already supported via `Utils::CurrentUser#extract_api_key` (Phase 1)

## Phase 7 — Cutover prep
- [x] Wire-format spot checks vs Ruby — one delta found and fixed (`GET /auth/failure` now 200, matching legacy). JWT shape, /auth/authority response, OAuth error envelope, signin/logout/login statuses, OIDC discovery shape all match.
- [x] Dockerfile polish — done in Phase 0 (renamed binary `/placeos-auth`, `/auth/healthz` probe).
- [x] README rewrite — endpoint inventory, env-var reference, run / test / deploy commands, cutover checklist.
- [x] Cutover deltas documented in README under "Migration from the Ruby service"
- [ ] Changelog entry — deferred; the git log captures every phase

## Review

41/41 specs green across 7 commits on master + 1 on `placeos/models@auth-replacement`.

| # | Commit | Phase | Δ specs |
|---|---|---|---|
| 1 | `6128be6` | 0–2 scaffolding + foundations + local auth | 18 |
| 2 | `3a9a4fb` | 3a/b authly + /token, /authorize | +9 |
| 3 | `24cd209` | 3c/d token store + /revoke, /userinfo, discovery | +5 |
| 4 | `4453bde` | 4 OAuth2 client via multi_auth | +5 |
| 5 | `397cb6f` | 5 SAML SP via multi_auth_saml | +2 |
| 6 | `0760bf5` | 6 Redis login events | +2 |
| 7 | (this) | 7 cutover prep — README + failure-status tweak | 0 |

**Deferred (post-cutover follow-ups):**
- Azure B2C redirect rewrite (`RewriteRedirectResponse` Ruby middleware) — only matters if a real B2C tenant is on the cutover list
- JWKS endpoint (`/.well-known/jwks.json`) — downstream PlaceOS services validate via baked-in `JWT_SECRET`, so not urgent
- `before_signup` / `after_login` Crystal-native hooks — Rails-initialiser pattern, no obvious consumer in the binary world
- Upstream PRs to `placeos-models` (Generator.jwt domain, User#password attribute shadowing) and `authly` (`AuthorizableClient` missing `allowed_grant_type?`, struct-const captures) — captured in `tasks/lessons.md`

## MCP authentication (seamless OAuth for MCP clients)

Context: MCP clients (Claude Code/Desktop, VS Code, Cursor, ...) discover auth.cr via
rest-api's RFC 9728 metadata (`authorization_servers: ["https://<tenant host>"]`), then
`/.well-known/oauth-authorization-server`, register themselves, and run authorization
code + PKCE with the `resource` parameter. Today that fails at registration (no DCR /
CIMD), at the redirect (exact-match loopback ports), and would issue codes to arbitrary
clients without user consent.

### Design (confirmed 2026-10-02: CIMD + DCR; consent for dynamic clients AND DB apps without skip_authorization; optional CIMD host allow-list)
1. **Loopback redirects (RFC 8252 §7.3):** a registered `http://127.0.0.1|[::1]|localhost`
   redirect URI matches any port (same scheme/host/path/query). Applies to all clients.
2. **Client ID Metadata Documents** (MCP 2025-11-25 preferred):
   - A `client_id` that is an `https://` URL is fetched as JSON. It must have
     `client_id == URL`, `redirect_uris`, an optional `client_name`/`client_uri`/
     `logo_uri`, a `token_endpoint_auth_method` of `none` (or absent), and no secret.
   - SSRF guards:
     - https only, no IP-literal/localhost hosts;
     - resolved addresses must be public;
     - no redirects, 3s/5s timeouts, 10KB body cap.
   - Documents are cached in memory (honouring `max-age`, clamped to 5 min–1 h).
   - An optional `MCP_CLIENT_ID_HOSTS` allow-list restricts which hosts may act as
     clients.
   - CIMD clients are virtual: public, `public` scope, no DB row. Tokens persist fine
     because `oauth_tokens.client_id` has no FK.
   - Advertised as `client_id_metadata_document_supported: true` in discovery.
3. **Dynamic Client Registration (RFC 7591):** `POST /auth/register` and
   `/auth/oauth/register`.
   - Public clients only (`token_endpoint_auth_method: none`), with the
     `authorization_code` and `refresh_token` grants and `public` scope.
   - `redirect_uris` must be https, loopback http, or a private-use scheme (no
     `javascript:`/`data:`/`file:`/non-loopback http).
   - The uid is random (prefixed `dcr-`, avoiding the MD5(redirect_uri) unique
     index); the name gets a unique suffix; `owner_id` is nil.
   - Rate limited per IP (in memory). Advertised as `registration_endpoint`.
4. **Consent screen** for dynamic clients (CIMD URL or `dcr-` uid) **and DB apps with
   `skip_authorization = false`** (decided: honour the column; apps that should stay
   silent must set it).
   - `GET /auth/authorize` renders a minimal HTML page showing the client name, the
     client_id host, the redirect target, the scopes and the tenant, with Allow/Deny
     buttons.
   - Allow POSTs back with a one-time CSRF token (stored in the session, bound to
     the request params; needed because the session cookie is SameSite=None).
   - Deny redirects `error=access_denied`.
   - DB apps with `skip_authorization = true` keep today's silent grant.
5. **PKCE:** S256 is required for dynamic clients; `plain` and missing challenges are
   rejected. Legacy clients are unchanged.
6. **`resource` (RFC 8707):** accepted on authorize, the authorization_code grant and
   the refresh_token grant. Its host must equal the request's authority host (the token
   `aud`); otherwise `invalid_target`. Token exchange keeps rejecting it.

### Tasks
- [x] loopback redirect matching in `AuthlyAdapter::Client` + specs
- [x] `Utils::ClientMetadata` (fetch, validate, SSRF guards, cache) + Client adapter
      lookup + specs (local HTTPS stub / injected fetcher)
- [x] DCR endpoint + rate limit + specs
- [x] consent page, CSRF token, allow/deny + specs
- [x] PKCE S256 enforcement for dynamic clients + specs
- [x] `resource` validation on authorize/token + specs
- [x] discovery: `registration_endpoint`, `client_id_metadata_document_supported`
- [x] README section; `./test` green (subagent); format + ameba
- [x] E2E: rest-api style MCP metadata → auth.cr discovery → DCR/CIMD → consent →
      token, using the official MCP TS SDK auth helpers against a local stack

### Review
Done (uncommitted).

Files:
- `utilities/redirect_uri.cr` (new): RFC 8252 loopback any-port matching and
  `registrable?` (https, loopback http, private-use scheme).
- `utilities/client_metadata.cr` (new): CIMD fetch with SSRF guards (https, no IP
  literals or localhost, public DNS only, no redirects, 3s/5s timeouts, 10KB cap),
  validation, a positive and negative cache, the `MCP_CLIENT_ID_HOSTS` allow-list,
  and a replaceable `fetcher` for specs.
- `utilities/consent.cr` (new): length-prefixed HMAC consent token (session uid +
  iat + every authorize param, 10 min), escaped consent page.
- `utilities/rate_limiter.cr` (new): fixed window, per process.
- `controllers/registrations.cr` (new): RFC 7591 `POST /auth/register` and
  `/auth/oauth/register`; public clients only; the uid is `dcr-<hex>`; each
  registration owns itself (`owner_id = uid`); JSON only.
- `authly_adapter/client.cr`: `ClientInfo` (DB app, `dcr-` app or CIMD), with
  consent/PKCE policy; loopback-aware `valid_redirect?`; dynamic clients are
  limited to authorization_code and refresh_token.
- `controllers/oauth.cr`: consent flow, mandatory S256 for dynamic clients,
  `resource` validation (authorize, authorization_code, refresh), shared
  `access_denied_url`; discovery gains `registration_endpoint` and
  `client_id_metadata_document_supported`.
- Specs: new `spec/controllers/mcp_auth_spec.cr` (17); 26 existing fixtures set
  `skip_authorization = true`.
- README: "MCP clients" section, routes and `MCP_CLIENT_ID_HOSTS`.

Verification:
- `./test`: 381 examples, 0 failures, 1 pending (baseline 364/0/1).
- Format clean; ameba clean on all new/changed files.
- E2E: live binary + Postgres driven by the official MCP TS SDK (discovery →
  registerClient → startAuthorization w/ PKCE + resource → signin → consent →
  allow → ephemeral loopback redirect → exchangeAuthorization →
  refreshAuthorization): all passed, token `aud` = authority host.

Follow-ups:
- Deploy: DB apps without `skip_authorization` (e.g. Backoffice) now get the
  consent screen; set the column on first-party apps before rollout.
- Discovery `issuer` drops non-default ports, so local dev on a custom port
  advertises port-less endpoints (production unaffected).
- `authorized_applications` doesn't list CIMD clients (no DB row).
- No cleanup of unused `dcr-` registrations yet.
