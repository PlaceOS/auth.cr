# auth_migration — Ruby auth → auth.cr route parity (PPT-2536)

Artefacts tracking the drop-in replacement of the legacy Ruby/Rails auth
service by this one.

| File | Purpose |
|---|---|
| `routes_rails.txt` | `rails routes` dump from the legacy service (verified consistent with its `config/routes.rb` + the catch-all appended in `config/application.rb`) |
| `routes_auth_cr_before.txt` | auth.cr route table at the start of the parity work (master @ fa87af7) |
| `parity_matrix.md` | Route-by-route status, contract decisions, and every accepted wire difference |
| `route_diff.sh` | Mechanical parity check — normalizes both route tables and diffs, with allowlisted intentional extras |

## Checking parity

```sh
./auth_migration/route_diff.sh          # builds if needed; exit 0 == parity
```

Regenerating the Rails dump (containerized; local Ruby is not viable):

```sh
cd ../auth   # legacy repo checkout
docker compose build auth2
docker compose run --rm auth2 bundle exec rails routes
```

## Behavioural verification

Route existence is proven by `route_diff.sh`; behaviour (status codes,
body shapes, redirects) is covered by the controller specs
(`spec/controllers/discovery_spec.cr`, `oauth_*_spec.cr`, …) and the
per-route contracts in `parity_matrix.md`. For an end-to-end check
against the full platform, build this repo's image and swap it into a
[PlaceOS/local](https://github.com/PlaceOS/local) stack:

```sh
docker build --build-arg PLACE_COMMIT=$(git rev-parse --short HEAD) -t placeos/auth:authcr-dev .
# in the local repo: set PLACE_AUTH_TAG=authcr-dev in .env,
# override the auth service command to bind 8080 (nginx expects auth:8080),
# add COOKIE_SESSION_SECRET + SG_ENV=production to its environment,
# then: ./placeos start --no-pull
```

The legacy service can be run side-by-side from its own repo
(`docker compose up -d` → http://localhost:3000) for golden comparison —
note it runs RAILS_ENV=test there, where Doorkeeper's admin gate is open.
