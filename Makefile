CARGO ?= cargo
PNPM ?= pnpm
DOCKER ?= docker
IMAGE ?= nas-storage-analyzer:local
IMAGE_AMD64 ?= nas-storage-analyzer:local-amd64
MULTIARCH_OUTPUT ?= /tmp/nas-storage-analyzer-multiarch.tar
BASE_REGISTRY ?= docker.m.daocloud.io/library

.PHONY: format lint check test-unit test-integration test-security test-e2e real-api-flow test-release bench build docker-build docker-build-amd64 docker-build-multiarch smoke smoke-amd64 check-web dependency-audit compose-config verify-delivery

format:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --workspace --all-targets --locked -- -D warnings

check:
	$(CARGO) check --workspace --all-targets --locked

test-unit:
	$(CARGO) test --workspace --locked --lib
	$(PNPM) --dir web run test:unit

test-integration:
	$(CARGO) test --workspace --locked --test adversarial

test-security:
	$(CARGO) test --locked -p fssecure --test adversarial

test-e2e:
	@test -n "$(E2E_BASE_URL)" || { echo >&2 'E2E_BASE_URL must point to a running real service; refusing a false PASS.'; exit 2; }
	$(PNPM) --dir web run test:e2e

real-api-flow:
	bash scripts/real-api-flow.sh

test-release:
	$(CARGO) test --workspace --release --locked

bench:
	@test -n "$$(find crates -type f -path '*/benches/*.rs' -print -quit)" || { echo >&2 'No Rust benchmark target exists under crates/*/benches; refusing a false PASS.'; exit 2; }
	$(CARGO) bench --workspace --locked

build:
	$(CARGO) build --release --locked -p nas-analyzer
	$(PNPM) --dir web run build

docker-build:
	$(DOCKER) buildx build --platform linux/arm64 --build-arg BASE_REGISTRY=$(BASE_REGISTRY) -f deploy/Dockerfile -t $(IMAGE) --load .

docker-build-amd64:
	$(DOCKER) buildx build --platform linux/amd64 --build-arg BASE_REGISTRY=$(BASE_REGISTRY) -f deploy/Dockerfile -t $(IMAGE_AMD64) --load .

docker-build-multiarch:
	$(DOCKER) buildx build --platform linux/amd64,linux/arm64 --build-arg BASE_REGISTRY=$(BASE_REGISTRY) -f deploy/Dockerfile -t $(IMAGE) --output=type=oci,dest=$(MULTIARCH_OUTPUT) .

smoke:
	bash deploy/smoke.sh $(IMAGE)

smoke-amd64:
	bash deploy/smoke.sh $(IMAGE_AMD64)

compose-config:
	$(DOCKER) compose --env-file deploy/.env.example -f deploy/compose.example.yaml config

verify-delivery:
	bash deploy/verify-delivery.sh

check-web:
	$(PNPM) --dir web install --frozen-lockfile
	$(PNPM) --dir web run typecheck
	$(PNPM) --dir web run lint

dependency-audit:
	bash scripts/dependency-audit.sh
