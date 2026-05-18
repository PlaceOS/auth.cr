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
- [ ] Per-request multi_auth provider registration from `oauth_strat`
- [ ] `Sessions#callback` (GET/POST `/auth/:provider/callback`)
- [ ] Branch: signed-in user linking new provider
- [ ] Branch: new user + new auth (with before_signup hook)
- [ ] Branch: existing auth + existing user (login)
- [ ] Path alias `/auth/:provider/callback/:strategy`
- [ ] Azure B2C redirect rewrite
- [ ] Inline auto-create user in callback when no `UserAuthLookup` exists (replaces dropped `/auth/signup`)
- [ ] Specs for each branch + the Azure rewrite

## Phase 5 — SAML / ADFS
- [ ] Per-request `multi_auth_saml` provider registration from `adfs_strat`
- [ ] Route SAML callbacks through `Sessions#callback` (shared with OAuth)
- [ ] Specs against canned IdP responses

## Phase 6 — Extensions
- [ ] Redis login event publisher (`placeos/auth/login`)
- [ ] Crystal-native `before_signup` / `after_login` hooks
- [ ] Finalise API key validator + X-API-Key header support

## Phase 7 — Cutover prep
- [ ] Wire-format diff vs Ruby service (cookies, JWT, response codes/headers)
- [ ] Dockerfile (mirror rest-api)
- [ ] README env var documentation
- [ ] Changelog entry

## Review (filled in at the end)
- _Outcome summary goes here._
