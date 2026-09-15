#!/usr/bin/env bash
# Small, executable release-entry audit. It verifies the checked-in deployment
# contract and runs only checks that are available from this repository.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

test -s Makefile
test -s README.md
test -s deploy/Dockerfile
test -s deploy/compose.example.yaml
test -s deploy/config.example.yaml
test -s deploy/smoke.sh
test -s web/tests/e2e/smoke.spec.ts
test -x deploy/smoke.sh
test -x deploy/verify-delivery.sh

grep -Eq '^\.PHONY:.*verify-delivery' Makefile
grep -Eq '^test-integration:$' Makefile
grep -Eq '^test-security:$' Makefile
grep -Eq '^test-e2e:$' Makefile
grep -Eq '^bench:$' Makefile
grep -Eq 'No Rust benchmark target exists' Makefile
grep -Eq 'E2E_BASE_URL' Makefile
grep -Eq "test\('未登录访问 / 会进入登录页'" web/tests/e2e/smoke.spec.ts

grep -Eq '^config_version:[[:space:]]*2[[:space:]]*$' deploy/config.example.yaml
grep -Eq '^    user: "\$\{APP_UID:\?Set APP_UID\}:\$\{APP_GID:\?Set APP_GID\}"$' deploy/compose.example.yaml
grep -Eq '^APP_UID=([1-9][0-9]*)$' deploy/.env.example
grep -Eq '^APP_GID=([1-9][0-9]*)$' deploy/.env.example
grep -Eq '^    read_only: true$' deploy/compose.example.yaml
grep -Eq '^    healthcheck:$' deploy/compose.example.yaml
grep -Eq '^USER 1000:1000$' deploy/Dockerfile
grep -Eq '^HEALTHCHECK ' deploy/Dockerfile
grep -Eq '^LABEL org\.opencontainers\.image\.title=' deploy/Dockerfile
grep -Eq '^      org\.opencontainers\.image\.revision=' deploy/Dockerfile
grep -Eq '^RUN pnpm run build$' deploy/Dockerfile
grep -Eq '^RUN cargo \+1\.98\.1 build --release --locked -p nas-analyzer$' deploy/Dockerfile

cargo run --locked -p nas-analyzer -- config-check --config deploy/config.example.yaml
pnpm --dir web run typecheck
pnpm --dir web run build

if command -v docker >/dev/null 2>&1; then
  docker compose --env-file deploy/.env.example -f deploy/compose.example.yaml config >/dev/null
else
  echo >&2 'docker is required for Compose verification'
  exit 2
fi

echo 'DELIVERY CONTRACT PASS'
