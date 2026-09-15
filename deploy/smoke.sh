#!/usr/bin/env bash
# Container smoke test (M8; also runnable after any docker-build):
# builds nothing itself — expects the image passed as $1 or the default local
# image to exist. Verifies non-root execution, read-only root and source
# mounts, image healthcheck, config-check, setup gating, graceful stop and
# SQLite persistence across a container restart.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${1:-nas-storage-analyzer:local}"
SMOKE_PORT="${SMOKE_PORT:-18080}"
CONTAINER="nas-smoke-${BASHPID}"
WORK="$(mktemp -d "$SCRIPT_DIR/.smoke.XXXXXX")"
trap 'docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

mkdir -p "$WORK/data" "$WORK/src-alpha" "$WORK/config"
chmod 0777 "$WORK/data"
printf '%s\n' 'smoke-content' > "$WORK/src-alpha/file.txt"
cp -- "$SCRIPT_DIR/config.example.yaml" "$WORK/config/config.yaml"

wait_for_live() {
  for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:${SMOKE_PORT}/health/live" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

echo "== image runs as non-root"
uid="$(docker run --rm --entrypoint /usr/bin/id "$IMAGE" -u)"
[ "$uid" != "0" ]

echo "== source mount rejects writes"
docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --mount "type=bind,source=$WORK/src-alpha,target=/sources/main,readonly" \
  --entrypoint /bin/sh "$IMAGE" \
  -ec 'touch /sources/main/.smoke-write 2>/dev/null && exit 1 || exit 0'

echo "== config-check"
docker run --rm --mount "type=bind,source=$WORK/config/config.yaml,target=/config/config.yaml,readonly" "$IMAGE" \
  config-check --config /config/config.yaml

echo "== start detached (read-only root, tmpfs /tmp, ro source)"
docker run -d --name "$CONTAINER" \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --mount "type=bind,source=$WORK/data,target=/data" \
  --mount "type=bind,source=$WORK/config/config.yaml,target=/config/config.yaml,readonly" \
  --mount "type=bind,source=$WORK/src-alpha,target=/sources/main,readonly" \
  -p "127.0.0.1:${SMOKE_PORT}:8080" \
  "$IMAGE" serve --config /config/config.yaml

echo "== inspect runtime security mounts"
[ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$CONTAINER")" = "true" ]
[ "$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/sources/main"}}{{.RW}}{{end}}{{end}}' "$CONTAINER")" = "false" ]

echo "== wait for health"
wait_for_live
curl -fsS "http://127.0.0.1:${SMOKE_PORT}/health/live" | grep -q '"status":"ok"'
curl -fsS "http://127.0.0.1:${SMOKE_PORT}/health/ready" >/dev/null

for _ in $(seq 1 60); do
  health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$CONTAINER")"
  [ "$health" = "healthy" ] && break
  [ "$health" = "unhealthy" ] && exit 1
  sleep 1
done
[ "$(docker inspect --format '{{.State.Health.Status}}' "$CONTAINER")" = "healthy" ]

echo "== business API gated before setup"
code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${SMOKE_PORT}/api/v1/sources")"
[ "$code" = "401" ] || [ "$code" = "503" ]

echo "== SIGTERM graceful stop"
docker stop -t 60 "$CONTAINER" >/dev/null
test -s "$WORK/data/control.sqlite"

echo "== restart keeps data"
docker start "$CONTAINER" >/dev/null
wait_for_live
curl -fsS "http://127.0.0.1:${SMOKE_PORT}/health/live" >/dev/null
test -s "$WORK/data/control.sqlite"

echo "SMOKE PASS: $IMAGE"
