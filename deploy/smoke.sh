#!/usr/bin/env bash
# Container smoke test (M8; also runnable after any docker-build):
# builds nothing itself — expects the image passed as $1 or the default local
# image to exist. Verifies non-root execution, read-only root and source
# mounts, image healthcheck, config-check, default-login gating, graceful stop and
# SQLite persistence across a container restart, including the default login
# and first-password-change gate.
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

echo "== default login creates a restricted session"
COOKIE_JAR="$WORK/cookies.txt"
login_body="$WORK/login.json"
printf '%s\n' '{"username":"admin","password":"admin"}' > "$login_body"
login_response="$(curl -fsS \
  -H "Origin: http://127.0.0.1:${SMOKE_PORT}" \
  -H 'Content-Type: application/json' \
  -c "$COOKIE_JAR" \
  --data-binary "@$login_body" \
  "http://127.0.0.1:${SMOKE_PORT}/api/v1/auth/login")"
printf '%s' "$login_response" | jq -e '.data.admin.username == "admin" and .data.admin.must_change_password == true' >/dev/null

echo "== business API requires the first password change"
restricted_response="$(curl -sS \
  -b "$COOKIE_JAR" \
  "http://127.0.0.1:${SMOKE_PORT}/api/v1/sources")"
printf '%s' "$restricted_response" | jq -e '.error.code == "PASSWORD_CHANGE_REQUIRED"' >/dev/null

echo "== first password change revokes the bootstrap session"
csrf_token="$(awk '$6 == "nas_csrf" { print $7 }' "$COOKIE_JAR")"
change_body="$WORK/change-password.json"
printf '%s\n' '{"new_password":"smoke-password"}' > "$change_body"
curl -fsS \
  -H "Origin: http://127.0.0.1:${SMOKE_PORT}" \
  -H "X-CSRF-Token: $csrf_token" \
  -H 'Content-Type: application/json' \
  -b "$COOKIE_JAR" \
  --data-binary "@$change_body" \
  "http://127.0.0.1:${SMOKE_PORT}/api/v1/auth/change-password" \
  | jq -e '.data == {}' >/dev/null
old_session_code="$(curl -s -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" "http://127.0.0.1:${SMOKE_PORT}/api/v1/auth/me")"
[ "$old_session_code" = "401" ]

echo "== changed password replaces the bootstrap password"
printf '%s\n' '{"username":"admin","password":"smoke-password"}' > "$login_body"
login_response="$(curl -fsS \
  -H "Origin: http://127.0.0.1:${SMOKE_PORT}" \
  -H 'Content-Type: application/json' \
  -c "$COOKIE_JAR" \
  --data-binary "@$login_body" \
  "http://127.0.0.1:${SMOKE_PORT}/api/v1/auth/login")"
printf '%s' "$login_response" | jq -e '.data.admin.must_change_password == false' >/dev/null

echo "== SIGTERM graceful stop"
docker stop -t 60 "$CONTAINER" >/dev/null
test -s "$WORK/data/control.sqlite"

echo "== restart keeps data"
docker start "$CONTAINER" >/dev/null
wait_for_live
curl -fsS "http://127.0.0.1:${SMOKE_PORT}/health/live" >/dev/null
test -s "$WORK/data/control.sqlite"
echo "== changed password survives restart"
login_response="$(curl -fsS \
  -H "Origin: http://127.0.0.1:${SMOKE_PORT}" \
  -H 'Content-Type: application/json' \
  -c "$COOKIE_JAR" \
  --data-binary "@$login_body" \
  "http://127.0.0.1:${SMOKE_PORT}/api/v1/auth/login")"
printf '%s' "$login_response" | jq -e '.data.admin.must_change_password == false' >/dev/null

echo "SMOKE PASS: $IMAGE"
