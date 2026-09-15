#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
WEB_DIR="$ROOT_DIR/web"
if [[ -n "${E2E_BACKEND_DOCKER_IMAGE:-}" ]]; then
  E2E_ROOT="$(mktemp -d "$ROOT_DIR/.nas-storage-analyzer-e2e.XXXXXX")"
else
  E2E_ROOT="$(mktemp -d /tmp/nas-storage-analyzer-e2e.XXXXXX)"
fi
DATA_ROOT="$E2E_ROOT/data"
SOURCE_ROOT="$E2E_ROOT/source"
CONFIG_PATH="$E2E_ROOT/config.yaml"
BACKEND_LOG="$E2E_ROOT/backend.log"
FRONTEND_LOG="$E2E_ROOT/frontend.log"
BACKEND_PID=""
FRONTEND_PID=""
BACKEND_CONTAINER_NAME=""
SETUP_CONTAINER_NAME=""
DATA_VOLUME_NAME=""
E2E_URL="http://127.0.0.1:4173"
BACKEND_HEALTH_URL="http://127.0.0.1:8080"
E2E_DOCKER_HOST_PORT="${E2E_DOCKER_HOST_PORT:-8080}"
E2E_TOKEN_FILE="$DATA_ROOT/setup-token"
if [[ -n "${E2E_BACKEND_BINARY:-}" && -n "${E2E_BACKEND_DOCKER_IMAGE:-}" ]]; then
  echo 'E2E_BACKEND_BINARY 与 E2E_BACKEND_DOCKER_IMAGE 不能同时设置' >&2
  exit 1
elif [[ -n "${E2E_BACKEND_DOCKER_IMAGE:-}" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo 'E2E_BACKEND_DOCKER_IMAGE 模式需要 docker' >&2
    exit 1
  fi
  BACKEND_CONTAINER_NAME="nas-storage-analyzer-e2e-$$"
  SETUP_CONTAINER_NAME="${BACKEND_CONTAINER_NAME}-setup"
  DATA_VOLUME_NAME="${BACKEND_CONTAINER_NAME}-data"
  docker volume create "$DATA_VOLUME_NAME" >/dev/null
  docker run --rm --user 0:0 --entrypoint /bin/chown -v "$DATA_VOLUME_NAME:/data" "${E2E_BACKEND_DOCKER_IMAGE}" 1000:1000 /data
  E2E_URL="http://127.0.0.1:${E2E_DOCKER_HOST_PORT}"
  BACKEND_HEALTH_URL="$E2E_URL"
  E2E_TOKEN_FILE="$E2E_ROOT/setup-token"
  CONFIG_LISTEN='0.0.0.0:8080'
  CONFIG_DATA_DIR='/data'
  CONFIG_OUTPUT_ROOT='/data/exports'
  CONFIG_MOUNT_PATH='/sources/main'
  SETUP_COMMAND=(docker run --init --read-only --cap-drop=ALL --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=64m,mode=1777 --pids-limit=128 --cpus=2 --memory=1g --user 1000:1000 --name "$SETUP_CONTAINER_NAME" --mount "type=volume,source=$DATA_VOLUME_NAME,target=/data" "${E2E_BACKEND_DOCKER_IMAGE}")
  BACKEND_COMMAND=(docker run --rm --init --read-only --cap-drop=ALL --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=64m,mode=1777 --pids-limit=128 --cpus=2 --memory=1g --user 1000:1000 --name "$BACKEND_CONTAINER_NAME" -p "${E2E_DOCKER_HOST_PORT}:8080" --mount "type=volume,source=$DATA_VOLUME_NAME,target=/data" --mount "type=bind,source=$CONFIG_PATH,target=/config/config.yaml,readonly" --mount "type=bind,source=$SOURCE_ROOT,target=/sources/main,readonly" "${E2E_BACKEND_DOCKER_IMAGE}")
elif [[ -n "${E2E_BACKEND_BINARY:-}" ]]; then
  if [[ ! -x "$E2E_BACKEND_BINARY" ]]; then
    echo "E2E_BACKEND_BINARY 不存在或不可执行：$E2E_BACKEND_BINARY" >&2
    exit 1
  fi
  BACKEND_COMMAND=("$E2E_BACKEND_BINARY")
  SETUP_COMMAND=("${BACKEND_COMMAND[@]}")
  CONFIG_LISTEN='127.0.0.1:8080'
  CONFIG_DATA_DIR="$DATA_ROOT"
  CONFIG_OUTPUT_ROOT="$DATA_ROOT/exports"
  CONFIG_MOUNT_PATH="$SOURCE_ROOT"
else
  BACKEND_COMMAND=(cargo run --locked -p nas-analyzer --)
  SETUP_COMMAND=("${BACKEND_COMMAND[@]}")
  CONFIG_LISTEN='127.0.0.1:8080'
  CONFIG_DATA_DIR="$DATA_ROOT"
  CONFIG_OUTPUT_ROOT="$DATA_ROOT/exports"
  CONFIG_MOUNT_PATH="$SOURCE_ROOT"
fi

cleanup() {
  local exit_status=$?
  if [[ -n "$FRONTEND_PID" ]]; then kill "$FRONTEND_PID" >/dev/null 2>&1 || true; fi
  if [[ -n "$BACKEND_CONTAINER_NAME" ]]; then
    docker rm -f "$BACKEND_CONTAINER_NAME" >/dev/null 2>&1 || true
    docker rm -f "$SETUP_CONTAINER_NAME" >/dev/null 2>&1 || true
    docker volume rm "$DATA_VOLUME_NAME" >/dev/null 2>&1 || true
  elif [[ -n "$BACKEND_PID" ]]; then
    kill "$BACKEND_PID" >/dev/null 2>&1 || true
  fi
  if [[ "$exit_status" -eq 0 ]]; then
    rm -rf -- "$E2E_ROOT"
  else
    rm -f -- "$E2E_TOKEN_FILE"
    echo "真实 E2E 启动失败；临时运行根目录已保留：$E2E_ROOT" >&2
    echo "后端日志：$BACKEND_LOG" >&2
    echo "前端日志：$FRONTEND_LOG" >&2
  fi
}
trap cleanup EXIT

mkdir -p "$DATA_ROOT" "$SOURCE_ROOT/nested"
printf '%s\n' 'real e2e alpha' > "$SOURCE_ROOT/alpha.txt"
printf '%s\n' 'real e2e beta' > "$SOURCE_ROOT/nested/beta.log"
printf '%s\n' 'real e2e duplicate' > "$SOURCE_ROOT/duplicate-a.txt"
printf '%s\n' 'real e2e duplicate' > "$SOURCE_ROOT/duplicate-b.txt"

cp -- "$ROOT_DIR/deploy/config.example.yaml" "$CONFIG_PATH"
sed -i.bak \
  -e "s#listen: \"0.0.0.0:8080\"#listen: \"$CONFIG_LISTEN\"#" \
  -e "s#data_dir: /data#data_dir: $CONFIG_DATA_DIR#" \
  -e "s#- /data/exports#- $CONFIG_OUTPUT_ROOT#" \
  -e "s#container_path: /sources/main#container_path: $CONFIG_MOUNT_PATH#" \
  "$CONFIG_PATH"
rm -f -- "$CONFIG_PATH.bak"

if [[ -n "$BACKEND_CONTAINER_NAME" ]]; then
  chmod 0777 "$DATA_ROOT"
else
  chmod 0700 "$DATA_ROOT"
fi
"${SETUP_COMMAND[@]}" admin setup-token --data-dir "${CONFIG_DATA_DIR}" > "$E2E_ROOT/setup.log"
if [[ -n "$BACKEND_CONTAINER_NAME" ]]; then
  docker cp "$SETUP_CONTAINER_NAME:/data/setup-token" "$E2E_TOKEN_FILE"
  chmod 0644 "$E2E_TOKEN_FILE"
  docker rm "$SETUP_CONTAINER_NAME" >/dev/null
fi

if [[ -n "$BACKEND_CONTAINER_NAME" ]]; then
  "${BACKEND_COMMAND[@]}" serve --config /config/config.yaml > "$BACKEND_LOG" 2>&1 &
else
  "${BACKEND_COMMAND[@]}" serve --config "$CONFIG_PATH" > "$BACKEND_LOG" 2>&1 &
fi
BACKEND_PID=$!
for _ in $(seq 1 120); do
  if curl -fsS "$BACKEND_HEALTH_URL/health/live" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS "$BACKEND_HEALTH_URL/health/live" >/dev/null

if [[ -z "$BACKEND_CONTAINER_NAME" ]]; then
  pnpm --dir "$WEB_DIR" dev --host 127.0.0.1 --port 4173 > "$FRONTEND_LOG" 2>&1 &
  FRONTEND_PID=$!
  for _ in $(seq 1 120); do
    if curl -fsS http://127.0.0.1:4173/ >/dev/null 2>&1; then break; fi
    sleep 1
  done
  curl -fsS http://127.0.0.1:4173/ >/dev/null
fi

set +e
E2E_BASE_URL="$E2E_URL" \
E2E_SETUP_TOKEN_FILE="$E2E_TOKEN_FILE" \
E2E_ADMIN_USERNAME="${E2E_ADMIN_USERNAME:-e2e-admin}" \
E2E_ADMIN_PASSWORD="${E2E_ADMIN_PASSWORD:-$(openssl rand -hex 24)}" \
E2E_SOURCE_ROOT="$SOURCE_ROOT" \
pnpm --dir "$WEB_DIR" exec playwright test tests/e2e/real-flow.spec.ts "$@"
TEST_STATUS=$?
set -e

if [[ "$TEST_STATUS" -ne 0 ]]; then
  rm -f -- "$E2E_TOKEN_FILE"
  trap - EXIT
  kill "$FRONTEND_PID" >/dev/null 2>&1 || true
  if [[ -n "$BACKEND_CONTAINER_NAME" ]]; then
    docker rm -f "$BACKEND_CONTAINER_NAME" >/dev/null 2>&1 || true
    docker rm -f "$SETUP_CONTAINER_NAME" >/dev/null 2>&1 || true
    docker volume rm "$DATA_VOLUME_NAME" >/dev/null 2>&1 || true
  else
    kill "$BACKEND_PID" >/dev/null 2>&1 || true
  fi
  echo "真实 E2E 失败；临时运行根目录已保留：$E2E_ROOT" >&2
  echo "后端日志：$BACKEND_LOG" >&2
  echo "前端日志：$FRONTEND_LOG" >&2
  exit "$TEST_STATUS"
fi

echo "真实 E2E 通过；临时运行根目录已清理。"
