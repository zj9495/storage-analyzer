# Repository Guidelines

## Project Structure & Module Organization

This is a Rust workspace with a React/TypeScript frontend. Backend crates live in
`crates/nas-analyzer` (Axum service, jobs, reports, and persistence) and
`crates/fssecure` (secure filesystem access). Frontend source, tests, and Vite
configuration are under `web/`; API definitions are in `api/`. SQL migrations are
grouped by database area under `migrations/`, deployment assets under `deploy/`,
and design, acceptance, and operational documentation under `docs/`.

## Build, Test, and Development Commands

Use the locked toolchain and committed lockfiles:

```bash
make format lint check       # Rust formatting, clippy, and compilation checks
make test-unit               # Rust libraries plus frontend Vitest tests
make test-integration        # fssecure integration tests
make test-security           # filesystem security adversarial tests
make check-web               # install frozen frontend deps, typecheck, lint
make build                   # release backend and frontend build
make test-e2e E2E_BASE_URL=http://127.0.0.1:3010
```

Run locally with `cargo run -p nas-analyzer -- serve --config /path/to/config.yaml`
or start the frontend with `pnpm --dir web dev`. E2E tests require a running real
service; use `scripts/linux-cargo.sh` for Linux-specific filesystem semantics.

## Coding Style & Naming Conventions

Rust uses edition 2024 and `cargo fmt`; keep clippy warnings at zero (`-D warnings`).
Use `snake_case` for Rust modules/functions, `UpperCamelCase` for types, and clear
domain names. TypeScript follows ESLint and strict TypeScript checks; use
`camelCase` for variables/functions and `PascalCase` for React components. Keep
API and migration changes aligned with the documented schemas and contracts.

## Testing Guidelines

Rust unit tests stay beside implementation or in crate test modules; integration
and adversarial tests are in `crates/*/tests`. Frontend unit tests use Vitest and
browser acceptance tests use Playwright under `web/tests`. Name tests after the
behavior they verify and run the narrowest relevant `make` target before broader
checks.

## Commit & Pull Request Guidelines

Commits use short, imperative subjects with a category prefix, such as
`feat: 修改目录` (the existing history is concise). Keep commits focused. Pull
requests should explain behavior and affected contracts, link the relevant issue
or acceptance item, list validation commands and results, and include UI screenshots
when frontend behavior changes. Call out migration, configuration, or security
implications explicitly.

## Security & Configuration Tips

Never commit real credentials, deployment paths, or generated artifacts. Copy
`deploy/.env.example` and `deploy/config.example.yaml` for local setup, replacing
all placeholders. Preserve the read-only scanning and explicit cleanup safeguards;
route filesystem access through `crates/fssecure`.
