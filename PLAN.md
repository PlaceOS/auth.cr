# auth.cr — Crystal port of the legacy Ruby auth service

> Living plan. Update as routes land. See `tasks/todo.md` for granular tracking, `tasks/lessons.md` for corrections captured along the way.

## Goal

Replace `/home/steve/projects/placeos/auth-replacement/auth` (Ruby/Rails + Doorkeeper + OmniAuth) with a Crystal/spider-gazelle service that exposes the same wire protocol so existing PlaceOS clients keep working without changes.

## Scope decisions

| Concern | Decision |
|---|---|
| Local password login (`POST /auth/signin`) | **Keep** — backed by `User#authenticate` (bcrypt) |
| OAuth2 client (Google, Microsoft, generic) | **Keep** — implement via `multi_auth`, configured from `oauth_strat` rows |
| SAML / ADFS | **Keep** — implement via `multi_auth_saml` shard (`spider-gazelle/multi_auth_saml`), configured from `adfs_strat` rows |
| `POST /auth/signup` | **Drop** — Ruby route exists but is unused in production; auto-create OAuth users inline in `Sessions#callback` instead |
| API key auth (`X-API-Key`) | **Keep** — format `{id}.{secret}`, HMAC-SHA512 |
| OAuth2 / OIDC *server* (issue tokens) | **Keep** — implement via `authly` |
| OAuth2 `password` grant | **Drop** — return `unsupported_grant_type` |
| LDAP | **Drop** — no controller, no strategy, ignore `ldap_strat` table |
| OmniAuth `:developer` strategy | **Drop** — Rails-dev convenience only |
| Redis login event publish (`placeos/auth/login`) | **Keep** — pluggable post-login hook |
| `before_signup` / `after_login` extension points | **Keep** — Crystal-native equivalents |

## Architecture

```
                       ┌─────────────────────────────┐
HTTP request (host)  ──▶│ ApplicationController       │
                       │  - resolve_authority (host) │
                       │  - parse session cookie /   │
                       │    Bearer / X-API-Key       │
                       └────────────┬────────────────┘
                                    │
        ┌───────────────────────────┼─────────────────────────────┐
        ▼                           ▼                             ▼
  Sessions (cookie)         multi_auth (OAuth/SAML)        authly (OAuth server)
  /auth/login               /auth/:provider                /auth/authorize
  /auth/signin              /auth/:provider/callback       /auth/token
  /auth/logout              /auth/signup                   /auth/revoke
  /auth/authority           /auth/failure                  /auth/userinfo
                                                           /.well-known/*
```

- **Data layer:** `placeos-models` shard. Reuse `User`, `Authority`, `UserAuthLookup` (table: `authentication`), `OAuthAuthentication` (table: `oauth_strat`), `SamlAuthentication` (table: `adfs_strat`), `ApiKey`, `DoorkeeperApplication` (table: `oauth_applications`). Any missing tables (e.g. token store, openid request) are added on a new `models` branch.
- **Session cookie:** `_coauth_session`, path `/auth`, encrypted, payload `{id, expires, iat}` — preserved for compatibility with existing nginx/asset SSO.
- **JWT:** RS256, issuer `"POS"`, audience = `authority.domain`, claims include `u: {n, e, p, r}`. Same shape as Ruby Doorkeeper output so downstream services keep validating tokens.
- **Multi-tenancy:** every request resolves `Authority` from `request.host` (case-insensitive). All queries scoped on `authority_id`.

## Route map (Ruby → Crystal)

| Method | Path | Ruby handler | Crystal controller#action | Notes |
|---|---|---|---|---|
| GET | `/auth/login` | `SessionsController#new` | `Sessions#new` | Validates `continue`, dispatches to provider, supports API-key inline |
| POST | `/auth/signin` | `SessionsController#signin` | `Sessions#signin` | Local bcrypt login |
| GET | `/auth/logout` | `SessionsController#destroy` | `Sessions#destroy` | Updates `logged_out_at`, revokes token |
| GET/POST | `/auth/:provider/callback` | `SessionsController#create` (OmniAuth) | `Sessions#callback` | Bridges `multi_auth.user(query_params)` / `multi_auth_saml` |
| GET/POST | `/auth/:provider/callback/:strategy` | same | `Sessions#callback` | Path-style strategy id (legacy alias) |
| ~~POST~~ | ~~`/auth/signup`~~ | ~~`SignupsController#create`~~ | _(dropped)_ | Unused — OAuth users auto-created inline in `Sessions#callback` |
| GET | `/auth/failure` | `SignupsController#show` | `Failures#show` | Failure page |
| GET | `/auth/authority` | `AuthoritiesController#current` | `Authorities#current` | Authority info + token check + health |
| POST | `/auth/token` | Doorkeeper | `authly` handler | Drop `password` grant |
| GET | `/auth/authorize` | Doorkeeper | `authly` handler | |
| POST | `/auth/revoke` | Doorkeeper | `authly` handler | |
| GET | `/auth/userinfo` | Doorkeeper OIDC | `authly` handler | |
| GET | `/.well-known/openid-configuration` | Doorkeeper OIDC | `authly` handler | |
| GET | `/.well-known/oauth-authorization-server` | Doorkeeper OIDC | `authly` handler | |
| GET | `/.well-known/webfinger` | Doorkeeper OIDC | `authly` handler (or stub if unused) | Verify in scope |

## Phased delivery (one route at a time)

Each phase: **spec first** (reproduce expected behaviour or describe new contract), implement, format/lint, run `./test` via subagent, mark done.

### Phase 0 — Scaffolding
1. Cut a new branch (`auth-replacement`) on `../models`; pin `auth.cr` to it from day 1.
2. Add deps to `shard.yml`: `placeos-models` (branch), `multi_auth`, `multi_auth_saml`, `authly`, `pg-orm`, `jwt`, `secrets-env`, `redis`.
3. Mirror `rest-api` layout: `src/controllers/application.cr`, `src/constants.cr`, `src/config.cr`, `src/app.cr`.
4. Spec scaffolding: `spec/helper.cr`, `spec/spec_helpers/{authentication,client,spec}.cr` ported from `rest-api`. **No Elasticsearch in the test stack** — auth flows use direct DB lookups.
5. `./test` script + `docker-compose.yml` with Postgres only.
6. CI workflow mirroring `rest-api` (`crystal-style`, `containerised-test`).

### Phase 1 — Foundations
6. `ApplicationController`: authority resolution by host, JWT/cookie/API-key parsing, error handlers (Unauthorized, Forbidden, RecordNotFound, RecordInvalid).
7. Cookie session helpers (encrypt/decrypt `_coauth_session`, set/clear, redirect safety).
8. `Authorities#current` (GET `/auth/authority`) + spec — simplest endpoint, validates scaffolding end-to-end.

### Phase 2 — Local auth
9. `Sessions#signin` (POST `/auth/signin`) + spec — bcrypt verify, set session, optional 202 / redirect.
10. `Sessions#destroy` (GET `/auth/logout`) + spec.
11. `Sessions#new` (GET `/auth/login`) + spec — `continue` validation, API-key inline flow, provider redirect.
12. `Failures#show` (GET `/auth/failure`) + spec.

### Phase 3 — OAuth2 / OIDC server (authly)
13. Mount `authly` handler under `/auth/...`. Implement `AuthlyOwner`, `AuthlyClient`, `AuthlyClaimsProvider`, `AuthlyTokenStore` against placeos-models.
14. JWT signer compatible with existing Ruby tokens (RS256, issuer "POS", claim shape `{iss,iat,exp,jti,aud,scope,sub,u}`).
15. Spec coverage for: authorization_code, client_credentials, refresh_token, revoke, userinfo, `.well-known/openid-configuration`.
16. Verify `password` grant returns `unsupported_grant_type`.

### Phase 4 — OAuth2 client (multi_auth)
17. Wire `multi_auth` provider registration from `oauth_strat` rows at request time (per-Authority dynamic config).
18. `Sessions#callback` (GET/POST `/auth/:provider/callback`) — handle three Ruby scenarios:
    - signed-in user adding a new provider link,
    - new user + new auth (with `before_signup_block` hook),
    - existing auth + existing user.
19. Path-style alias `/auth/:provider/callback/:strategy` (matches RewriteCallbackRequest middleware semantics).
20. Azure B2C redirect rewrite (matches RewriteRedirectResponse).
21. Inline user auto-creation in the callback when no `UserAuthLookup` exists (replaces the dropped `/auth/signup` flow).

### Phase 5 — SAML / ADFS
22. Wire `multi_auth_saml` provider registration from `adfs_strat` rows at request time.
23. Route SAML callbacks through the same `Sessions#callback` shape (`/auth/:provider/callback`) so the user-mapping branches stay shared with OAuth.

### Phase 6 — Extensions
24. Redis login event publisher (`placeos/auth/login`).
25. `Authentication.before_signup` / `after_login` Crystal equivalents (callable hooks, not Ruby blocks).
26. API key validation (`X-API-Key` header) — already partly in Phase 1, finalise.

### Phase 7 — Cutover prep
27. Compatibility audit against the Ruby service: identical cookie format, identical JWT shape, identical response codes/headers for each endpoint.
28. Deployment: Dockerfile mirroring `rest-api`, env var documentation.
29. Update changelog / README.

## Open questions

- **`oauth_access_grants` / `oauth_access_tokens` tables** — migrations exist in `models` but no Crystal model. Authly's own token store will replace them; decide whether to migrate existing tokens or invalidate on cutover.
- **Token signing key compatibility** — confirm `JWT_SECRET` env var format is reusable as-is, so existing public keys still verify issued tokens.
- **`/.well-known/webfinger`** — actually used by any consumer? If not, drop.

## Resolved

- ~~SAML library~~ — using `spider-gazelle/multi_auth_saml`.
- ~~Elasticsearch in test stack~~ — not needed; auth flows are direct DB lookups.
- ~~`POST /auth/signup`~~ — dropped; OAuth users are created inline in the callback.

## Done means

- All routes in the table above respond with the same status codes and response shapes as the Ruby service.
- `./test` is green (per-controller specs, integration where authly is involved).
- `crystal tool format` clean; `./bin/ameba` clean.
- README documents env vars, Docker run, and the dropped LDAP / password-grant behaviour.
- A staff engineer would approve the diff.
