# auth.cr

[![CI](https://github.com/PlaceOS/auth/actions/workflows/ci.yml/badge.svg)](https://github.com/PlaceOS/auth/actions/workflows/ci.yml)

Crystal/spider-gazelle replacement for the legacy Ruby/Rails `auth`
service. Route-for-route compatible with the existing wire protocol so
clients can flip over without changes.

## What it does

* **Local password sign-in** — `POST /auth/signin` (bcrypt verify).
* **OAuth2 client flows** — `/auth/oauth2`, `/auth/oauth2/callback` —
  per-tenant provider configs loaded from the `oauth_strat` table
  via [`spider-gazelle/multi_auth`][multi_auth] (and its custom
  `GenericOAuth2` provider).
* **SAML SP** — `/auth/saml`, `/auth/saml/callback` — backed by
  [`spider-gazelle/multi_auth_saml`][multi_auth_saml] reading the
  `adfs_strat` table.
* **OAuth2 / OIDC server** — `/auth/authorize`, `/auth/token`,
  `/auth/revoke`, `/auth/userinfo`, `/.well-known/openid-configuration`.
  Backed by [`place-labs/authly`][authly]. JWTs are RS256 with the
  legacy `u: {n, e, p, r}` claim block + `aud=authority.domain` so
  downstream PlaceOS services keep validating tokens issued before
  cutover.
* **API key auth** — `X-API-Key` header (HMAC-SHA512 secret format
  `{id}.{secret}`).
* **Login event publisher** — fires `{user_id, provider}` JSON on the
  `placeos/auth/login` Redis channel after every successful login.

[multi_auth]: https://github.com/msa7/multi_auth
[multi_auth_saml]: https://github.com/spider-gazelle/multi_auth_saml
[authly]: https://github.com/place-labs/authly

## What's intentionally out of scope

| Dropped | Why |
|---|---|
| OAuth2 `password` grant | Deprecated by OAuth 2.1; security risk. Token endpoint returns `unsupported_grant_type`. Local logins still work via the cookie session on `POST /auth/signin`. |
| LDAP | All current tenants have migrated off. |
| `POST /auth/signup` | Unused in production. OAuth users are auto-created inline in the callback when no `UserAuthLookup` exists. |
| OmniAuth `:developer` strategy | Rails-dev convenience only. |

## Routes

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/auth/healthz` | Liveness |
| `GET` | `/auth/authority` | Authority info + session/token flags (`?health=` makes it a probe) |
| `POST` | `/auth/signin` | Local password login |
| `GET` | `/auth/logout` | Session teardown + Bearer revoke + `logged_out_at` stamp |
| `GET` | `/auth/login` | Inline login dispatcher |
| `GET` | `/auth/failure` | OAuth / SAML failure landing page |
| `GET` | `/auth/oauth2` | Kickoff OAuth2 client flow |
| `GET/POST` | `/auth/oauth2/callback[/:strategy]` | Consume OAuth2 callback |
| `GET` | `/auth/saml` | Kickoff SAML SP flow |
| `GET/POST` | `/auth/saml/callback[/:strategy]` | Consume SAMLResponse |
| `GET` | `/auth/authorize` | OAuth2 authorization endpoint (code flow) |
| `POST` | `/auth/token` | OAuth2 token endpoint (`authorization_code`, `client_credentials`, `refresh_token`) |
| `POST` | `/auth/revoke` | RFC 7009 token revocation |
| `GET` | `/auth/userinfo` | OIDC `userinfo` (Bearer-gated) |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery |

## Environment

### Required in production

| Var | Purpose |
|---|---|
| `JWT_SECRET` | Base64-encoded RSA private PEM. Signs every issued JWT (RS256). Public key derived. Falls back to a hardcoded dev key if unset — DO NOT ship that to production. |
| `COOKIE_SESSION_SECRET` | ≥32 bytes. Encrypts/signs the session cookie. Dev fallback generates an ephemeral key per boot. |
| `PG_DATABASE_URL` *or* `PG_HOST` / `PG_PORT` / `PG_DB` / `PG_USER` / `PG_PASSWORD` | PostgreSQL connection. |
| `REDIS_URL` | Used to publish login events. If unset, `LoginEvents.publish` is a no-op (logged at warn). |

### Optional / tunable

| Var | Default | Purpose |
|---|---|---|
| `SG_ENV` | `development` | `production` flips secure-cookie + production logging. |
| `JWT_ISSUER` | `POS` | `iss` claim on issued JWTs. Match the legacy Ruby value or services that pin issuer will reject. |
| `SESSION_TIMEOUT_MINUTES` | `1440` | Session-cookie max age. Per-authority override available via `authority.internals["session_timeout"]`. |
| `LOGIN_EVENTS_CHANNEL` | `placeos/auth/login` | Redis pub/sub channel for login events. |
| `PLACE_URI` | _(unset)_ | Base URL used when a legacy `X-API-Key` validation needs to round-trip to the core engine. |

## Run

### Locally (against a running Postgres + Redis)

```sh
shards install
crystal run src/app.cr -- -b 0.0.0.0 -p 3000
```

### Useful flags

```sh
./placeos-auth --routes        # dump the route table
./placeos-auth --docs          # OpenAPI YAML on stdout
./placeos-auth --env           # list every ENV var the app touched
./placeos-auth --version
./placeos-auth -c http://127.0.0.1:3000/auth/healthz   # health-check (exit 0 on 2xx-4xx)
```

### Container

```sh
docker build -t placeos/auth .
docker run --rm -p 3000:3000 -e JWT_SECRET=... -e COOKIE_SESSION_SECRET=... placeos/auth
```

The `HEALTHCHECK` probes `/auth/healthz`.

## Test

`./test` spins up Postgres + Redis + a migrator container (clones
`placeos/models@<branch>` and runs `micrate up`) and runs the spec
suite end-to-end.

```sh
./test                                    # full suite
./test spec/controllers/oauth_spec.cr     # one file
```

### Iterating on placeos-models migrations

The migrator's `git clone` is Docker-cached. After pushing new
migrations to the `placeos/models` branch this project points at:

```sh
docker compose build --no-cache migrator
./test
```

## Working on the codebase

* Code style: `crystal tool format && ./bin/ameba` — both must be
  clean before committing. CI rejects either.
* Plans + lessons live in `tasks/todo.md` and `tasks/lessons.md`
  (please update both as you go — `lessons.md` has caught at least
  five upstream library quirks already).
* `PLAN.md` is the high-level phase map.

## Migration from the Ruby service

| Aspect | Ruby | auth.cr |
|---|---|---|
| Session cookie | `_coauth_session` at path `/auth`, Rails AES encryption | Same name + path, but **action-controller `MessageEncryptor` wire format**. Users are forced to re-sign-in at cutover (acceptable for an auth-service rotation). |
| JWT issuer (`iss`) | `POS` | `POS` |
| JWT shape | `{iss, iat, exp, jti, aud, scope, sub, u:{n,e,p,r}}` | Same |
| Bcrypt password digest | Stored in `user.password_digest` | Same (placeos-models reused). |
| OmniAuth `:generic_oauth` | DB-driven `oauth_strat` | `multi_auth` factory under the `oauth2` provider name; same `oauth_strat` rows. |
| OmniAuth `:generic_adfs` | DB-driven `adfs_strat` | `multi_auth_saml` factory under the `saml` provider name; same `adfs_strat` rows. |
| OAuth `password` grant | Allowed | Rejected with `unsupported_grant_type`. |
| `POST /auth/signup` | Manual signup endpoint | Removed; OAuth users are auto-created inline in the callback. |
| Redis login channel | `placeos/auth/login` | Same. |
| LDAP | Supported | **Dropped.** |

### Cutover steps

1. Ensure `JWT_SECRET` matches the Ruby deployment — downstream
   services validate by signature, so a key rotation breaks them.
2. Roll out `placeos-models` with the `oauth_tokens` migration first
   (or use the `auth-replacement` branch).
3. Set `COOKIE_SESSION_SECRET` to a real ≥32-byte value. Existing
   `_coauth_session` cookies will be invalid — users re-sign-in.
4. Switch the auth service container image to this build. The route
   table is wire-compatible.
5. Watch the `placeos/auth/login` Redis channel + `/auth/healthz` for
   regressions.
