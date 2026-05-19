# Lessons

Captured corrections and surprises during the auth.cr port. Review at session start.

## Project-level rules (from initial brief)
- LDAP is out of scope — do not port the `generic_ldap` strategy or reference `ldap_strat` from controllers.
- The OAuth2 `password` grant is out of scope — token endpoint must return `unsupported_grant_type`. Local password login lives on `POST /auth/signin` via cookie session, not the token endpoint.
- Tackle one route at a time. Don't batch big multi-route PRs.
- Use subagents for `./test` runs (slow) and for codebase research that spans many files.

## Corrections
_(append entries here as the user pushes back on anything)_

## Scaffolding gotchas (2026-05-18)
- `multi_auth_saml` transitively pins `msa7/multi_auth, branch: master`. If you declare `multi_auth` in this project's `shard.yml` against the spider-gazelle fork, the resolver errors with "ambiguous sources". Use `github: msa7/multi_auth, branch: master` to match.
- `crystal build --no-codegen` over pg-orm fails (`undefined method 'on_error' for PgORM::Base+.class`) when no model concrete classes are in scope. Pulling in `placeos-models` at the controllers entry point resolves it — pg-orm assumes at least one model is defined.
- `log_helper` is NOT a shard. The rest-api `require "log_helper"` resolves against an internal action-controller path that isn't always exposed; safe to drop.
- For local dev, override `placeos-models` with a `path: ../models` entry in `shard.override.yml`. Avoids the chicken-and-egg of needing the branch on GitHub before `shards install` works.
- Path overrides break inside the `./test` Docker stack — `lib/placeos-models` becomes a symlink to `../../models` on the host, which is not mounted in the test container. Once the branch is pushed, switch the override to `github: placeos/models, branch: <name>`.
- `simple_retry` is not a transitive dep — it was an unused inheritance from rest-api's helper.cr. Auth.cr doesn't need it (no eventual-consistency search to wait on).

## placeos-models User#password gotchas (2026-05-19)
- `Crypto::Bcrypt::Password` in the Crystal stdlib does NOT overload `==(String)`. `bcrypt == "raw_pw"` is reference equality and always returns false. Use `.verify(raw_pw)` instead. The placeos-models docs that claim Bcrypt::Password overloads `==` are wrong for Crystal.
- The User model declares both `attribute password : String?` (line 65) AND `def password : Password` (line 388). The active-model `attribute` macro expands in a `macro finished` block, which means its auto-generated getter wins over the explicit `def`. `user.password` resolves to `String | Nil` at compile time, not `Bcrypt::Password`. Confirmed via compile error: "undefined method 'verify' for Nil (compile-time type is (String | Nil))".
- Workaround in auth.cr (used in `Sessions#signin`): reconstruct the password directly — `Crypto::Bcrypt::Password.new(user.password_digest).verify(raw)`. Upstream fix would be either renaming the transient field (e.g. `pending_password`) or removing the `attribute password : String?` declaration and relying on `assign_attributes_from_json` writing to `@password` directly.

## action-controller status codes (2026-05-19)
- Returning a String from a `@[AC::Route::GET]` action triggers the responder which writes status before any manual `response.status_code = ...` takes effect. Set the status via the annotation: `@[AC::Route::GET("/x", status_code: HTTP::Status::UNAUTHORIZED)]`.
- Same applies to `@[AC::Route::Exception(...)]` handlers — `status_code:` is baked in at compile time. If you need a *variable* response status, split into multiple exception classes (one per status code) and attach a separate annotation to each.

## Authly shard gotchas (2026-05-19)
- **`AuthorizableClient` interface is incomplete.** Authly internally calls `Authly.clients.allowed_grant_type?(client_id, grant_type)` on the typed `AuthorizableClient` reference, but the abstract module doesn't declare it. Our custom Client class must define it explicitly. Same goes for `Enumerable(Authly::Client)` — `device_authorization_handler` iterates clients via `.any?`; even if you don't mount the device flow, the file has to type-check. Add `include Enumerable(::Authly::Client)` with a no-op `each`.
- **`Authly.config` mutations don't backfill struct-level constants captured at load time.** `Authly::Code` defines `ISSUER = Authly.config.issuer` and `CODE_TTL = Authly.config.code_ttl` at class load; same with `Authly::AccessToken::{ACCESS_TTL, REFRESH_TTL}`. If you call `Authly.configure` *after* the file is required (the only realistic option), tokens are minted with the upstream defaults while `Authly.jwt_decode` validates against your live config. Open-class the affected methods to read `Authly.config.<field>` dynamically. Pattern lives in `src/placeos-auth/authly_adapter.cr`.
- **`Authly.config.clients` is captured by ref but `Authly::Code::ISSUER` is captured by value.** Distinct semantics, easy to confuse.

## Spec env vs. production wiring (2026-05-19)
- The spec runner loads `src/config.cr` via `spec/helper.cr` but does NOT load `src/app.cr`. Anything that needs to run for both prod and tests has to land in `config.cr` or in a file `config.cr` requires (typically `src/placeos-auth/<thing>.cr`). The Authly `configure!` call had this exact bug — was in `app.cr` only, so specs ran with the upstream defaults.

## DoorkeeperApplication.secret is regenerated (2026-05-19)
- `placeos-models`' `DoorkeeperApplication` has a `before_create :generate_secret` callback that overwrites whatever `secret` you set on a fresh record with `Random::Secure.urlsafe_base64(40)`. Specs must read `app.secret` AFTER `save!` if they need the real value.

## multi_auth shard quirks (2026-05-19)
- `multi_auth.cr` top-level does `require "./multi_auth/*"` — globs ONE level only. Providers under `multi_auth/providers/` are NOT auto-required. Add an explicit `require "multi_auth/providers/generic_oauth2"` (or whichever you use).
- `MultiAuth.config(provider, &builder)` is the dynamic registration path — the only one that works with `GenericOAuth2`, because the static `GenericOAuth2.new(redirect_uri, key, secret)` 3-arg constructor raises by design. Use the factory form.
- `multi_auth` does NOT validate the OAuth `state` parameter — it only echoes it through. The application MUST stash a random state on the session before kickoff and check `request.params["state"]` on callback.
- `request.query_params` is `URI::Params` (Enumerable of `{String, String}`) — exactly the shape `Engine#user(params)` wants. No conversion needed.

## Spec module shadowing (2026-05-19)
- Inside `module PlaceOS::Auth`, an unqualified `Spec` resolves to `PlaceOS::Auth::Spec` (our own helper module), NOT the Crystal stdlib `::Spec`. Calling `Spec.before_each { ... }` errors out as "undefined method ... for PlaceOS::Auth::Spec:Module". Qualify as `::Spec.before_each` to reach the stdlib hooks.

## Migrator Docker layer caching (2026-05-19)
- `spec/migration/Dockerfile` clones `placeos/models@auth-replacement` via `RUN git clone ...`. Docker caches this layer aggressively. When new migrations are pushed to the branch, `./test` won't pick them up until you force a rebuild:
  ```
  docker compose build --no-cache migrator
  ```
  Symptom: `relation "..." does not exist (PQ::PQError)` from the token store / models. Worth scripting into `./test` later — for now it's manual after each models push.

## Spec helper gotchas (2026-05-19)
- `PlaceOS::Model::Generator.jwt` hard-codes `domain: Faker::Internet.email`. That works in rest-api specs only by accident: `URI.parse("name@example.com").host` returns nil and `URI.parse("localhost").host` also returns nil, so `ensure_matching_domain`'s `nil == nil` check passes. Any current_user implementation that falls back to the raw domain string when host is nil — which is the *correct* check in production — breaks against this seed data.
  - **Fix:** build the JWT manually in auth.cr's `Spec::Authentication.authentication` with `domain: authority.domain` rather than calling `Model::Generator.jwt`.
  - Consider upstream PR to placeos-models so the generator defaults to `user.authority.domain` instead of `Faker::Internet.email`.
