#!/usr/bin/env bash
set -euo pipefail

# Real HTTP integration flow for a local, isolated application instance.
# It deliberately uses one temporary data root and one temporary source root;
# no user-supplied or production path is accepted by this script.

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="http://127.0.0.1:${REAL_API_PORT:-18080}"
API_PORT="${REAL_API_PORT:-18080}"
if [[ -n "${REAL_API_DOCKER_IMAGE:-}" ]]; then
  RUN_ROOT="$(mktemp -d "$ROOT_DIR/.nas-storage-analyzer-real-api.XXXXXX")"
else
  RUN_ROOT="$(mktemp -d /tmp/nas-storage-analyzer-real-api.XXXXXX)"
fi
DATA_ROOT="$RUN_ROOT/data"
SOURCE_ROOT="$RUN_ROOT/sources"
CONFIG_PATH="$RUN_ROOT/config.yaml"
RESPONSE_ROOT="$RUN_ROOT/responses"
COOKIE_JAR="$RUN_ROOT/cookies.txt"
BACKEND_LOG="$RUN_ROOT/backend.log"
BACKEND_PID=""
BACKEND_CONTAINER_NAME=""
DATA_VOLUME_NAME=""
RESPONSE_SEQ=0
LAST_RESPONSE=""
LAST_EVIDENCE=""
CSRF_TOKEN=""
ADMIN_USERNAME="admin"
NEW_ADMIN_PASSWORD="$(openssl rand -hex 24)"
ADMIN_PASSWORD="admin"
CONFIG_LISTEN="127.0.0.1:${API_PORT}"
CONFIG_DATA_DIR="$DATA_ROOT"
CONFIG_OUTPUT_ROOT="$DATA_ROOT/exports"
CONFIG_MOUNT_PATH="$SOURCE_ROOT"

fail() {
  local message="$1"
  printf 'REAL API FLOW FAILED: %s\n' "$message" >&2
  if [[ -n "$LAST_EVIDENCE" && -f "$LAST_EVIDENCE" ]]; then
    printf '%s\n' '--- last HTTP response ---' >&2
    sed -n '1,240p' "$LAST_EVIDENCE" >&2 || true
  fi
  if [[ -f "$BACKEND_LOG" ]]; then
    printf '%s\n' '--- backend log tail ---' >&2
    tail -n 120 "$BACKEND_LOG" >&2 || true
  fi
  printf 'Evidence retained at: %s\n' "$RUN_ROOT" >&2
  exit 1
}

cleanup() {
  local status=$?
  if [[ -n "$BACKEND_PID" ]]; then
    kill "$BACKEND_PID" >/dev/null 2>&1 || true
    wait "$BACKEND_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$BACKEND_CONTAINER_NAME" ]]; then
    docker rm -f "$BACKEND_CONTAINER_NAME" >/dev/null 2>&1 || true
    docker volume rm "$DATA_VOLUME_NAME" >/dev/null 2>&1 || true
  fi
  if [[ "$status" -eq 0 ]]; then
    rm -rf -- "$RUN_ROOT"
  else
    rm -f -- "$COOKIE_JAR" "$RUN_ROOT/login.json" "$RUN_ROOT/change-password.json" "$RUN_ROOT/reauth.json" "$RUN_ROOT/reauth-restore.json"
    rm -f -- "$RESPONSE_ROOT"/.raw-*.json
    printf 'Evidence retained at: %s\n' "$RUN_ROOT" >&2
  fi
}
trap cleanup EXIT

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

for command_name in curl jq openssl shasum sed mktemp grep unzip tar cmp; do
  require_command "$command_name"
done
if [[ -n "${REAL_API_DOCKER_IMAGE:-}" ]]; then
  [[ -z "${REAL_API_BINARY:-}" ]] || fail 'REAL_API_DOCKER_IMAGE and REAL_API_BINARY cannot both be set'
  require_command docker
  BACKEND_CONTAINER_NAME="nas-storage-analyzer-real-api-${BASHPID}"
  DATA_VOLUME_NAME="${BACKEND_CONTAINER_NAME}-data"
  docker volume create "$DATA_VOLUME_NAME" >/dev/null || fail "could not create temporary Docker data volume"
  docker run --rm --user 0:0 --entrypoint /bin/chown \
    -v "$DATA_VOLUME_NAME:/data" "${REAL_API_DOCKER_IMAGE}" 1000:1000 /data \
    || fail "could not initialize temporary Docker data volume"
  CONFIG_LISTEN='0.0.0.0:8080'
  CONFIG_DATA_DIR='/data'
  CONFIG_OUTPUT_ROOT='/data/exports'
  CONFIG_MOUNT_PATH='/sources/main'
  UTILITY_COMMAND=(docker run --rm --init --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=64m,mode=1777 \
    --pids-limit=128 --cpus=2 --memory=1g --user 1000:1000 \
    --mount "type=volume,source=$DATA_VOLUME_NAME,target=/data" \
    --mount "type=bind,source=$CONFIG_PATH,target=/config/config.yaml,readonly" \
    "${REAL_API_DOCKER_IMAGE}")
  BACKEND_COMMAND=(docker run --rm --init --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=64m,mode=1777 \
    --pids-limit=128 --cpus=2 --memory=1g --user 1000:1000 \
    --name "$BACKEND_CONTAINER_NAME" -p "${API_PORT}:8080" \
    --mount "type=volume,source=$DATA_VOLUME_NAME,target=/data" \
    --mount "type=bind,source=$CONFIG_PATH,target=/config/config.yaml,readonly" \
    --mount "type=bind,source=$SOURCE_ROOT,target=/sources/main,readonly" \
    "${REAL_API_DOCKER_IMAGE}")
else
  UTILITY_COMMAND=()
  BACKEND_COMMAND=(cargo run --locked -p nas-analyzer --)
fi

mkdir -p "$DATA_ROOT" "$SOURCE_ROOT/alpha/docs" "$SOURCE_ROOT/alpha/media" "$SOURCE_ROOT/beta" "$DATA_ROOT/exports" "$RESPONSE_ROOT"

# The fixture is the acceptance golden dataset: 8 regular paths, 7 physical
# objects, 50 logical bytes, and 44 unique logical bytes.
printf 'hello\n' > "$SOURCE_ROOT/alpha/docs/readme.txt"
cp -- "$SOURCE_ROOT/alpha/docs/readme.txt" "$SOURCE_ROOT/alpha/docs/copy.txt"
ln -- "$SOURCE_ROOT/alpha/docs/readme.txt" "$SOURCE_ROOT/alpha/docs/hard.txt"
for _ in $(seq 1 17); do printf 'B'; done > "$SOURCE_ROOT/alpha/media/movie.bin"
: > "$SOURCE_ROOT/alpha/empty.dat"
ALPHA_SPECIAL_NAME=$'名称,\n换行.txt'
printf 'xyz' > "$SOURCE_ROOT/alpha/$ALPHA_SPECIAL_NAME"
cp -- "$SOURCE_ROOT/alpha/docs/readme.txt" "$SOURCE_ROOT/beta/copy.txt"
printf 'HELLO\n' > "$SOURCE_ROOT/beta/changed.txt"

hash_file() {
  shasum -a 256 -- "$1" | cut -d' ' -f1
}

BEFORE_README="$(hash_file "$SOURCE_ROOT/alpha/docs/readme.txt")"
BEFORE_COPY="$(hash_file "$SOURCE_ROOT/alpha/docs/copy.txt")"
BEFORE_HARD="$(hash_file "$SOURCE_ROOT/alpha/docs/hard.txt")"
BEFORE_MOVIE="$(hash_file "$SOURCE_ROOT/alpha/media/movie.bin")"
BEFORE_EMPTY="$(hash_file "$SOURCE_ROOT/alpha/empty.dat")"
BEFORE_SPECIAL="$(hash_file "$SOURCE_ROOT/alpha/$ALPHA_SPECIAL_NAME")"
BEFORE_BETA_COPY="$(hash_file "$SOURCE_ROOT/beta/copy.txt")"
BEFORE_CHANGED="$(hash_file "$SOURCE_ROOT/beta/changed.txt")"
tar -cf "$RUN_ROOT/source-before.tar" -C "$SOURCE_ROOT" .
BEFORE_SOURCE_ARCHIVE="$(hash_file "$RUN_ROOT/source-before.tar")"

cp -- "$ROOT_DIR/deploy/config.example.yaml" "$CONFIG_PATH"
sed -i.bak \
  -e "s#listen: \"0.0.0.0:8080\"#listen: \"$CONFIG_LISTEN\"#" \
  -e "s#data_dir: /data#data_dir: $CONFIG_DATA_DIR#" \
  -e "s#- /data/exports#- $CONFIG_OUTPUT_ROOT#" \
  -e "s#container_path: /sources/main#container_path: $CONFIG_MOUNT_PATH#" \
  "$CONFIG_PATH"
rm -f -- "$CONFIG_PATH.bak"

if [[ -n "${REAL_API_DOCKER_IMAGE:-}" ]]; then
  :
elif [[ -n "${REAL_API_BINARY:-}" ]]; then
  [[ -x "$REAL_API_BINARY" ]] || fail "REAL_API_BINARY is not executable: $REAL_API_BINARY"
  BACKEND_COMMAND=("$REAL_API_BINARY")
fi

printf '%s\n' '== validate deployment config'
if [[ -n "${REAL_API_DOCKER_IMAGE:-}" ]]; then
  "${UTILITY_COMMAND[@]}" config-check --config /config/config.yaml > "$RUN_ROOT/config-check.log" 2>&1 || fail "config-check failed"
else
  "${BACKEND_COMMAND[@]}" config-check --config "$CONFIG_PATH" > "$RUN_ROOT/config-check.log" 2>&1 || fail "config-check failed"
fi

printf '%s\n' '== start local HTTP service'
if [[ -n "${REAL_API_DOCKER_IMAGE:-}" ]]; then
  "${BACKEND_COMMAND[@]}" serve --config /config/config.yaml > "$BACKEND_LOG" 2>&1 &
else
  "${BACKEND_COMMAND[@]}" serve --config "$CONFIG_PATH" > "$BACKEND_LOG" 2>&1 &
fi
BACKEND_PID=$!
for _ in $(seq 1 120); do
  if curl -fsS "$BASE_URL/health/live" > "$RUN_ROOT/health-live.json" 2>/dev/null; then
    break
  fi
  kill -0 "$BACKEND_PID" >/dev/null 2>&1 || fail "backend exited before health/live became ready"
  sleep 1
done
curl -fsS "$BASE_URL/health/live" > "$RUN_ROOT/health-live.json" || fail "health/live did not become ready"
jq -e '.status == "ok"' "$RUN_ROOT/health-live.json" >/dev/null || fail "health/live response is not status=ok"

api_request() {
  local label="$1"
  local method="$2"
  local path="$3"
  local expected_status="$4"
  local body="$5"
  local csrf_header="$6"
  local idempotency_key="$7"
  RESPONSE_SEQ=$((RESPONSE_SEQ + 1))
  LAST_RESPONSE="$RESPONSE_ROOT/.raw-$(printf '%04d-%s.json' "$RESPONSE_SEQ" "$label")"
  LAST_EVIDENCE="$RESPONSE_ROOT/$(printf '%04d-%s.json' "$RESPONSE_SEQ" "$label")"
  local status
  local -a curl_args=(-sS -b "$COOKIE_JAR" -c "$COOKIE_JAR" -X "$method" -H 'Accept: application/json' -H "Origin: $BASE_URL")
  if [[ -n "$body" ]]; then
    curl_args+=(-H 'Content-Type: application/json' --data-binary "@$body")
  fi
  if [[ -n "$csrf_header" ]]; then
    curl_args+=(-H "X-CSRF-Token: $csrf_header")
  fi
  if [[ -n "$idempotency_key" ]]; then
    curl_args+=(-H "Idempotency-Key: $idempotency_key")
  fi
  if ! status="$(curl "${curl_args[@]}" -o "$LAST_RESPONSE" -w '%{http_code}' "$BASE_URL$path")"; then
    fail "$label: curl transport failure"
  fi
  jq 'walk(if type == "object" then del(.csrf_token, .reauth_token, .setup_token, .password, .secrets_passphrase) else . end)' "$LAST_RESPONSE" > "$LAST_EVIDENCE" 2>/dev/null || cp -- "$LAST_RESPONSE" "$LAST_EVIDENCE"
  if [[ "$status" != "$expected_status" ]]; then
    fail "$label: expected HTTP $expected_status, got $status"
  fi
}

api_get() {
  api_request "$1" GET "$2" "$3" '' '' ''
}

api_json() {
  api_request "$1" "$2" "$3" "$4" "$5" "$CSRF_TOKEN" "${6:-}"
}

assert_response() {
  local label="$1"
  shift
  jq -e "$@" "$LAST_RESPONSE" >/dev/null || fail "$label: JSON assertion failed"
}

assert_file_equal() {
  local expected="$1"
  local path="$2"
  local actual
  actual="$(hash_file "$path")"
  [[ "$actual" == "$expected" ]] || fail "source file changed: $path"
}

wait_for_job() {
  local label="$1"
  local job_id="$2"
  local expected_state="$3"
  local job_response=""
  for _ in $(seq 1 180); do
    api_get "$label-job" "/api/v1/jobs/$job_id" 200
    job_response="$LAST_RESPONSE"
    local state
    state="$(jq -er '.data.state' "$job_response")" || fail "$label: job response has no state"
    case "$state" in
      SUCCEEDED|PARTIAL|FAILED|CANCELLED|INTERRUPTED)
        if [[ "$state" != "$expected_state" ]]; then
          LAST_RESPONSE="$job_response"
          fail "$label: terminal job state is $state, expected $expected_state"
        fi
        LAST_RESPONSE="$job_response"
        return 0
        ;;
    esac
    sleep 1
  done
  LAST_RESPONSE="$job_response"
  fail "$label: job did not reach a terminal state within 180 seconds"
}

wait_for_export_ready() {
  local label="$1"
  local export_id="$2"
  local export_response=""
  for _ in $(seq 1 120); do
    api_get "$label-export" "/api/v1/exports/$export_id" 200
    export_response="$LAST_RESPONSE"
    local state
    state="$(jq -er '.data.state' "$export_response")" || fail "$label: export response has no state"
    case "$state" in
      ready)
        LAST_RESPONSE="$export_response"
        return 0
        ;;
      failed|expired)
        LAST_RESPONSE="$export_response"
        fail "$label: export reached terminal state $state"
        ;;
    esac
    sleep 1
  done
  LAST_RESPONSE="$export_response"
  fail "$label: export did not become ready within 120 seconds"
}

printf '%s\n' '== login with the default credentials'
jq -n --arg username "$ADMIN_USERNAME" --arg password "$ADMIN_PASSWORD" \
  '{username:$username, password:$password}' > "$RUN_ROOT/login.json"
api_request login POST /api/v1/auth/login 200 "$RUN_ROOT/login.json" '' ''
CSRF_TOKEN="$(jq -er '.data.csrf_token' "$LAST_RESPONSE")" || fail 'login response has no csrf_token'
assert_response login '.data.admin.username == $username' --arg username "$ADMIN_USERNAME"
assert_response login-default-password '.data.admin.must_change_password == true'

printf '%s\n' '== force the first password change'
jq -n --arg password "$NEW_ADMIN_PASSWORD" '{new_password:$password}' > "$RUN_ROOT/change-password.json"
api_json change-password POST /api/v1/auth/change-password 200 "$RUN_ROOT/change-password.json"
CSRF_TOKEN=''

printf '%s\n' '== re-login with the changed password'
jq -n --arg username "$ADMIN_USERNAME" --arg password "$NEW_ADMIN_PASSWORD" \
  '{username:$username, password:$password}' > "$RUN_ROOT/login.json"
api_request relogin POST /api/v1/auth/login 200 "$RUN_ROOT/login.json" '' ''
CSRF_TOKEN="$(jq -er '.data.csrf_token' "$LAST_RESPONSE")" || fail 'relogin response has no csrf_token'
assert_response relogin '.data.admin.username == $username' --arg username "$ADMIN_USERNAME"
assert_response relogin-password-cleared '.data.admin.must_change_password == false'
ADMIN_PASSWORD="$NEW_ADMIN_PASSWORD"

api_get capabilities /api/v1/auth/me 200
assert_response readonly-capability '.data.capabilities.write_operations_allowed == false and .data.capabilities.can_cleanup == false'

printf '%s\n' '== assert read-only source write gate'
jq -n '{name:"should-fail-write-source", mount_key:"main", relative_root:"alpha", storage_kind:"local", read_policy:"content_allowed", write_enabled:true, protected:false}' > "$RUN_ROOT/write-source.json"
api_json readonly-source-write POST /api/v1/sources 403 "$RUN_ROOT/write-source.json"
assert_response readonly-source-write '.error.code == "READ_ONLY_MODE"'

printf '%s\n' '== create temporary volume and two source registrations'
jq -n '{name:"real-api-temporary-volume"}' > "$RUN_ROOT/volume.json"
api_json create-volume POST /api/v1/volumes 200 "$RUN_ROOT/volume.json"
VOLUME_ID="$(jq -er '.data.id' "$LAST_RESPONSE")" || fail 'volume response has no id'

jq -n '{name:"alpha", mount_key:"main", relative_root:"alpha", storage_kind:"local", read_policy:"content_allowed", write_enabled:false, protected:false}' > "$RUN_ROOT/source-alpha.json"
api_json create-source-alpha POST /api/v1/sources 200 "$RUN_ROOT/source-alpha.json"
ALPHA_ID="$(jq -er '.data.id' "$LAST_RESPONSE")" || fail 'alpha source response has no id'

jq -n '{name:"beta", mount_key:"main", relative_root:"beta", storage_kind:"local", read_policy:"content_allowed", write_enabled:false, protected:false}' > "$RUN_ROOT/source-beta.json"
api_json create-source-beta POST /api/v1/sources 200 "$RUN_ROOT/source-beta.json"
BETA_ID="$(jq -er '.data.id' "$LAST_RESPONSE")" || fail 'beta source response has no id'

api_get source-list '/api/v1/sources?page_size=50' 200
assert_response two-sources '.data | length == 2'

printf '%s\n' '== preview and apply identity/quota metadata import'
jq -n --arg alpha "$ALPHA_ID" --arg beta "$BETA_ID" --arg volume "$VOLUME_ID" \
  '{schema_version:1, generated_at:"2026-09-13T00:00:00Z", provider_label:"real-api-temporary-fixture", identities:[{namespace:"posix-container", uid:1000, gid:1000, display_name:"fixture-owner", observed_at:"2026-09-13T00:00:00Z"}], source_links:[{source_id:$alpha, volume_id:$volume, provider_volume_key:null},{source_id:$beta, volume_id:$volume, provider_volume_key:null}], quotas:[{principal:{namespace:"posix-container", uid:1000}, scope:{kind:"source", id:$alpha}, metric:"logical_bytes", origin:"advisory", limit:{state:"known", bytes:"100"}, used_bytes:"38", observed_at:"2026-09-13T00:00:00Z", expires_at:null, provider_label:"real-api-temporary-fixture"},{principal:{namespace:"posix-container", uid:1000}, scope:{kind:"volume", id:$volume}, metric:"filesystem_quota_bytes", origin:"system_imported", limit:{state:"unlimited", bytes:null}, used_bytes:null, observed_at:"2026-09-13T00:00:00Z", expires_at:null, provider_label:"real-api-temporary-fixture"}]}' > "$RUN_ROOT/metadata.json"
api_json metadata-preview POST /api/v1/metadata/import/preview 200 "$RUN_ROOT/metadata.json"
METADATA_PREVIEW_ID="$(jq -er '.data.preview_id' "$LAST_RESPONSE")" || fail 'metadata preview has no preview_id'
METADATA_DIGEST="$(jq -er '.data.digest' "$LAST_RESPONSE")" || fail 'metadata preview has no digest'
assert_response metadata-preview '.data.valid == true and .data.counts.identities == 1 and .data.counts.links == 2 and .data.counts.quotas == 2'
jq -n --arg preview "$METADATA_PREVIEW_ID" --arg digest "$METADATA_DIGEST" \
  '{preview_id:$preview, digest:$digest, confirmation:"APPLY_METADATA_IMPORT"}' > "$RUN_ROOT/metadata-apply.json"
api_json metadata-apply POST /api/v1/metadata/import/apply 200 "$RUN_ROOT/metadata-apply.json"
assert_response metadata-apply '.data.applied == true and .data.identities_applied == 1 and .data.source_links_applied == 2 and .data.quotas_applied == 2'

printf '%s\n' '== create and run first two-source report'
jq -n --arg alpha "$ALPHA_ID" --arg beta "$BETA_ID" \
  '{name:"real-api-golden-report", enabled:true, scope:{mode:"selected", source_ids:[$alpha,$beta], include_future_registered:false, include_globs:[], exclude_globs:[], file_kind_policy:"regular_only"}, sections:["volume","folders","owners","quota","categories","duplicates","largest","recently_modified","least_accessed"], owner_ids_to_list:[1000], duplicates:{enabled:true, match_name:false, match_mtime:false, min_size_bytes:"1", max_size_bytes:null, max_listed_files:5000, hash_budget_bytes:null, content_read_policy:"respect_source_policy"}, rank_limit:200, schedule:{type:"manual"}, retention:{report_keep_count:30, detail_keep_count:3}, notifications:{recipients:[], notify_on:["succeeded","partial","failed"], attach_summary:false, public_base_url:null}, resources:{}}' > "$RUN_ROOT/profile.json"
api_json create-profile POST /api/v1/profiles 200 "$RUN_ROOT/profile.json"
PROFILE_ID="$(jq -er '.data.id' "$LAST_RESPONSE")" || fail 'profile response has no id'
api_json run-first POST "/api/v1/profiles/$PROFILE_ID/run" 202 '' "scan-first-$PROFILE_ID"
FIRST_JOB_ID="$(jq -er '.data.job_id' "$LAST_RESPONSE")" || fail 'first run response has no job_id'
FIRST_RUN_ID="$(jq -er '.data.run_id' "$LAST_RESPONSE")" || fail 'first run response has no run_id'
wait_for_job first-scan "$FIRST_JOB_ID" SUCCEEDED

api_get reports-after-first '/api/v1/reports?page_size=50' 200
FIRST_REPORT_ID="$(jq -er --arg run "$FIRST_RUN_ID" '[.data[] | select(.run_id == $run)] | if length == 1 then .[0].id else error("expected exactly one first report") end' "$LAST_RESPONSE")" || fail 'first run did not publish exactly one report'
api_get first-report "/api/v1/reports/$FIRST_REPORT_ID" 200
assert_response first-report '(.data.status == "succeeded" and .data.totals.file_count == "8" and .data.totals.logical_bytes == "50" and ([.data.quota_snapshot[] | select(.scope.kind == "source" and .scope.id == $alpha and .metric == "logical_bytes" and .limit.state == "known" and .limit.bytes == "100" and .used_bytes == "38" and .origin == "advisory")] | length == 1) and ([.data.quota_snapshot[] | select(.scope.kind == "volume" and .scope.id == $volume and .metric == "filesystem_quota_bytes" and .limit.state == "unlimited" and .limit.bytes == null and .used_bytes == null and .origin == "system_imported")] | length == 1))' --arg alpha "$ALPHA_ID" --arg volume "$VOLUME_ID"
jq -S '.data' "$LAST_RESPONSE" > "$RUN_ROOT/first-report.data.before-category-change.json"

api_get first-files "/api/v1/reports/$FIRST_REPORT_ID/files?page_size=50" 200
assert_response first-files '(.data | length == 8) and (([.data[] | select(.device_id != null and .inode_id != null)] | group_by([.device_id, .inode_id]) | length) == 7) and (([.data[] | select(.device_id != null and .inode_id != null)] | group_by([.device_id, .inode_id]) | map(.[0].size_bytes | tonumber) | add) == 44) and ([.data[] | select(.display_path | endswith("docs/hard.txt"))][0].nlink == 2)'
api_get first-folders "/api/v1/reports/$FIRST_REPORT_ID/folders?page_size=50" 200
assert_response first-folders '.data | length >= 2'
api_get first-owners "/api/v1/reports/$FIRST_REPORT_ID/owners?page_size=50" 200
assert_response first-owners '.data | length >= 1'
api_get first-rankings "/api/v1/reports/$FIRST_REPORT_ID/rankings/largest?page_size=50" 200
assert_response first-rankings '.data | length >= 1'

api_get first-categories "/api/v1/reports/$FIRST_REPORT_ID/categories?metric=logical_bytes&sort=name_asc&page_size=50" 200
assert_response golden-categories '([.data[] | select(.category_id == "documents")][0].logical_bytes == "33") and ([.data[] | select(.category_id == "disk_images")][0].logical_bytes == "17") and ([.data[] | select(.category_id == "other")][0].logical_bytes == "0")'
assert_response golden-source-breakdown '([.data[].source_breakdown[] | select(.source_id == $alpha) | .logical_bytes | tonumber] | add) == 38 and ([.data[].source_breakdown[] | select(.source_id == $beta) | .logical_bytes | tonumber] | add) == 12' --arg alpha "$ALPHA_ID" --arg beta "$BETA_ID"

printf '%s\n' '== verify full-hash duplicate group and prepare read-only cleanup preview'
api_get duplicate-groups "/api/v1/reports/$FIRST_REPORT_ID/duplicates?complete_only=true&page_size=50" 200
DUPLICATE_GROUP_ID="$(jq -er '[.data[] | select(.size_bytes == "6" and .reclaimable_bytes == "12" and .complete == true and .member_count == 4)] | if length == 1 then .[0].group_id else error("expected one hello duplicate group") end' "$LAST_RESPONSE")" || fail 'golden hello duplicate group not found'
api_get duplicate-group "/api/v1/reports/$FIRST_REPORT_ID/duplicates/$DUPLICATE_GROUP_ID" 200
KEEP_ALPHA_ID="$(jq -er --arg source "$ALPHA_ID" '[.data.members[] | select(.source_id == $source and (.display_path | endswith("readme.txt"))) | .entry_id] | if length == 1 then .[0] else error("missing alpha readme duplicate member") end' "$LAST_RESPONSE")" || fail 'could not select alpha readme keep entry'
TARGET_ALPHA_ID="$(jq -er --arg source "$ALPHA_ID" '[.data.members[] | select(.source_id == $source and (.display_path | endswith("copy.txt"))) | .entry_id] | if length == 1 then .[0] else error("missing alpha copy duplicate target") end' "$LAST_RESPONSE")" || fail 'could not select alpha copy target entry'
TARGET_BETA_ID="$(jq -er --arg source "$BETA_ID" '[.data.members[] | select(.source_id == $source and (.display_path | endswith("copy.txt"))) | .entry_id] | if length == 1 then .[0] else error("missing beta copy target") end' "$LAST_RESPONSE")" || fail 'could not select beta copy target entry'
TARGET_HARD_ID="$(jq -er --arg source "$ALPHA_ID" '[.data.members[] | select(.source_id == $source and (.display_path | endswith("hard.txt"))) | .entry_id] | if length == 1 then .[0] else error("missing hardlink target") end' "$LAST_RESPONSE")" || fail 'could not select hardlink target entry'
jq -n --arg report "$FIRST_REPORT_ID" --arg group "$DUPLICATE_GROUP_ID" --arg keep_alpha "$KEEP_ALPHA_ID" --arg target_alpha "$TARGET_ALPHA_ID" --arg target_beta "$TARGET_BETA_ID" --arg target_hard "$TARGET_HARD_ID" \
  '{report_id:$report, groups:[{group_id:$group, keep_entry_ids:[$keep_alpha], target_entry_ids:[$target_alpha,$target_beta,$target_hard]}]}' > "$RUN_ROOT/cleanup-plan.json"
api_json cleanup-preview POST /api/v1/cleanup/plans 200 "$RUN_ROOT/cleanup-plan.json"
CLEANUP_PLAN_ID="$(jq -er '.data.id' "$LAST_RESPONSE")" || fail 'cleanup preview has no plan id'
assert_response cleanup-preview '(.data.state == "preview" and .data.action == "quarantine" and .data.selected_count == 2 and .data.logical_total_bytes == "12" and .data.confirmation_text == "QUARANTINE_SELECTED_FILES" and ([.data.blocked_entries[] | select(.entry_id == $hard and .reason == "hardlink_not_allowed")] | length == 1))' --arg hard "$TARGET_HARD_ID"
tar -cf "$RUN_ROOT/source-after-cleanup-preview.tar" -C "$SOURCE_ROOT" .
AFTER_SOURCE_ARCHIVE="$(hash_file "$RUN_ROOT/source-after-cleanup-preview.tar")"
[[ "$AFTER_SOURCE_ARCHIVE" == "$BEFORE_SOURCE_ARCHIVE" ]] || fail 'cleanup preview changed the source tree'
api_get quarantine-after-preview /api/v1/cleanup/quarantine 200
assert_response quarantine-after-preview '.data | length == 0'

jq -n --arg password "$ADMIN_PASSWORD" '{password:$password}' > "$RUN_ROOT/reauth.json"
api_json reauth-for-cleanup POST /api/v1/auth/reauth 200 "$RUN_ROOT/reauth.json"
REAUTH_TOKEN="$(jq -er '.data.reauth_token' "$LAST_RESPONSE")" || fail 'reauth response has no reauth_token'
jq -n --arg reauth "$REAUTH_TOKEN" '{reauth_token:$reauth, confirmation:"QUARANTINE_SELECTED_FILES"}' > "$RUN_ROOT/cleanup-execute.json"
api_json cleanup-execute POST "/api/v1/cleanup/plans/$CLEANUP_PLAN_ID/execute" 202 "$RUN_ROOT/cleanup-execute.json" "cleanup-read-only-$CLEANUP_PLAN_ID"
CLEANUP_ACTION_ID="$(jq -er '.data.action_id' "$LAST_RESPONSE")" || fail 'cleanup execute response has no action_id'
CLEANUP_JOB_ID="$(jq -er '.data.job_id' "$LAST_RESPONSE")" || fail 'cleanup execute response has no job_id'
wait_for_job cleanup-read-only "$CLEANUP_JOB_ID" INTERRUPTED
assert_response cleanup-read-only '.data.error.code == "INTERRUPTED"'
api_get cleanup-action "/api/v1/cleanup/actions/$CLEANUP_ACTION_ID" 200
assert_response cleanup-action '.data.state == "interrupted"'
api_get quarantine-after-readonly /api/v1/cleanup/quarantine 200
assert_response quarantine-after-readonly '.data | length == 0'
assert_file_equal "$BEFORE_README" "$SOURCE_ROOT/alpha/docs/readme.txt"
assert_file_equal "$BEFORE_COPY" "$SOURCE_ROOT/alpha/docs/copy.txt"
assert_file_equal "$BEFORE_HARD" "$SOURCE_ROOT/alpha/docs/hard.txt"
assert_file_equal "$BEFORE_MOVIE" "$SOURCE_ROOT/alpha/media/movie.bin"
assert_file_equal "$BEFORE_EMPTY" "$SOURCE_ROOT/alpha/empty.dat"
assert_file_equal "$BEFORE_SPECIAL" "$SOURCE_ROOT/alpha/$ALPHA_SPECIAL_NAME"
assert_file_equal "$BEFORE_BETA_COPY" "$SOURCE_ROOT/beta/copy.txt"
assert_file_equal "$BEFORE_CHANGED" "$SOURCE_ROOT/beta/changed.txt"

printf '%s\n' '== change classification rules and run second report'
api_get category-rules-before /api/v1/settings/categories 200
assert_response category-rules-before '.data.version == 1 and ([.data.rules.documents[] | select(. == "txt")] | length == 1)'
jq -c '.data.rules | .documents = (.documents | map(select(. != "txt"))) | .pictures = (.pictures + ["txt"]) | {rules: .}' "$LAST_RESPONSE" > "$RUN_ROOT/category-update.json"
api_json category-rules-update PUT /api/v1/settings/categories 200 "$RUN_ROOT/category-update.json"
assert_response category-rules-update '.data.version == 2 and ([.data.rules.documents[] | select(. == "txt")] | length == 0) and ([.data.rules.pictures[] | select(. == "txt")] | length == 1)'

api_json run-second POST "/api/v1/profiles/$PROFILE_ID/run" 202 '' "scan-second-$PROFILE_ID"
SECOND_JOB_ID="$(jq -er '.data.job_id' "$LAST_RESPONSE")" || fail 'second run response has no job_id'
SECOND_RUN_ID="$(jq -er '.data.run_id' "$LAST_RESPONSE")" || fail 'second run response has no run_id'
wait_for_job second-scan "$SECOND_JOB_ID" SUCCEEDED
api_get reports-after-second '/api/v1/reports?page_size=50' 200
SECOND_REPORT_ID="$(jq -er --arg run "$SECOND_RUN_ID" '[.data[] | select(.run_id == $run)] | if length == 1 then .[0].id else error("expected exactly one second report") end' "$LAST_RESPONSE")" || fail 'second run did not publish exactly one report'
api_get first-report-after-category-change "/api/v1/reports/$FIRST_REPORT_ID" 200
assert_response historical-report-stable '(.data.classification_version == 1 and .data.totals.file_count == "8" and .data.totals.logical_bytes == "50")'
jq -S '.data' "$LAST_RESPONSE" > "$RUN_ROOT/first-report.data.after-category-change.json"
cmp -- "$RUN_ROOT/first-report.data.before-category-change.json" "$RUN_ROOT/first-report.data.after-category-change.json" || fail 'historical report data changed after category update'
api_get first-categories-after-category-change "/api/v1/reports/$FIRST_REPORT_ID/categories?metric=logical_bytes&sort=name_asc&page_size=50" 200
assert_response historical-categories-stable '([.data[] | select(.category_id == "documents")][0].logical_bytes == "33") and ([.data[] | select(.category_id == "pictures")] | length == 0)'
api_get second-report "/api/v1/reports/$SECOND_REPORT_ID" 200
assert_response second-report '(.data.classification_version == 2 and .data.totals.file_count == "8" and .data.totals.logical_bytes == "50")'
api_get second-categories "/api/v1/reports/$SECOND_REPORT_ID/categories?metric=logical_bytes&sort=name_asc&page_size=50" 200
assert_response second-categories '([.data[] | select(.category_id == "pictures")][0].logical_bytes == "33") and ([.data[] | select(.category_id == "documents")] | length == 0)'

printf '%s\n' '== compare the immutable reports'
jq -n --arg other "$FIRST_REPORT_ID" '{other_report_id:$other, mode:"aggregate"}' > "$RUN_ROOT/compare.json"
api_json compare POST "/api/v1/reports/$SECOND_REPORT_ID/compare" 202 "$RUN_ROOT/compare.json" "compare-classification-$SECOND_REPORT_ID"
COMPARISON_ID="$(jq -er '.data.comparison_id' "$LAST_RESPONSE")" || fail 'compare response has no comparison_id'
COMPARE_JOB_ID="$(jq -er '.data.job_id' "$LAST_RESPONSE")" || fail 'compare response has no job_id'
assert_response compare-queued '.data.comparable == false and ([.data.incompatibility_reasons[] | select(. == "classification_version_mismatch")] | length == 1)'
wait_for_job compare "$COMPARE_JOB_ID" SUCCEEDED
api_get comparison "/api/v1/comparisons/$COMPARISON_ID" 200
assert_response comparison '(.data.state == "succeeded" and .data.comparable == false and ([.data.incompatibility_reasons[] | select(. == "classification_version_mismatch")] | length == 1))'

printf '%s\n' '== export categories twice with one idempotency key'
jq -n '{section:"categories", format:"csv", scope:"all", query:{}}' > "$RUN_ROOT/export.json"
EXPORT_KEY="export-idempotency-$FIRST_REPORT_ID"
api_json export-first POST "/api/v1/reports/$FIRST_REPORT_ID/exports" 202 "$RUN_ROOT/export.json" "$EXPORT_KEY"
EXPORT_ID="$(jq -er '.data.export_id' "$LAST_RESPONSE")" || fail 'first export response has no export_id'
EXPORT_JOB_ID="$(jq -er '.data.job_id' "$LAST_RESPONSE")" || fail 'first export response has no job_id'
EXPORT_RESPONSE_FIRST="$LAST_RESPONSE"
api_json export-repeat POST "/api/v1/reports/$FIRST_REPORT_ID/exports" 202 "$RUN_ROOT/export.json" "$EXPORT_KEY"
assert_response export-repeat '.data.export_id == $export and .data.job_id == $job' --arg export "$EXPORT_ID" --arg job "$EXPORT_JOB_ID"
wait_for_job export "$EXPORT_JOB_ID" SUCCEEDED
wait_for_export_ready categories "$EXPORT_ID"
curl -sS -b "$COOKIE_JAR" -o "$RUN_ROOT/categories.csv" "$BASE_URL/api/v1/exports/$EXPORT_ID/download" || fail 'category export download failed'
[[ -s "$RUN_ROOT/categories.csv" ]] || fail 'category export is empty'
grep -q 'report_id' "$RUN_ROOT/categories.csv" || fail 'category export lacks report_id header'

printf '%s\n' '== backup, download, restore preview and apply'
jq -n '{include_secrets:false}' > "$RUN_ROOT/backup.json"
api_json backup-create POST /api/v1/settings/backup 202 "$RUN_ROOT/backup.json" "backup-idempotency-$PROFILE_ID"
BACKUP_EXPORT_ID="$(jq -er '.data.export_id' "$LAST_RESPONSE")" || fail 'backup response has no export_id'
BACKUP_JOB_ID="$(jq -er '.data.job_id' "$LAST_RESPONSE")" || fail 'backup response has no job_id'
wait_for_job backup "$BACKUP_JOB_ID" SUCCEEDED
wait_for_export_ready backup "$BACKUP_EXPORT_ID"
curl -sS -b "$COOKIE_JAR" -o "$RUN_ROOT/config-backup.zip" "$BASE_URL/api/v1/exports/$BACKUP_EXPORT_ID/download" || fail 'backup download failed'
unzip -tq "$RUN_ROOT/config-backup.zip" || fail 'downloaded configuration backup is not a valid zip'

jq -n --arg backup "$BACKUP_EXPORT_ID" '{backup_export_id:$backup}' > "$RUN_ROOT/restore-preview.json"
api_json restore-preview POST /api/v1/settings/restore/preview 200 "$RUN_ROOT/restore-preview.json"
assert_response restore-preview '.data.compatible == true and .data.config_version == 1 and .data.preview_id == $backup' --arg backup "$BACKUP_EXPORT_ID"
jq -n --arg password "$ADMIN_PASSWORD" '{password:$password}' > "$RUN_ROOT/reauth-restore.json"
api_json reauth-for-restore POST /api/v1/auth/reauth 200 "$RUN_ROOT/reauth-restore.json"
RESTORE_REAUTH_TOKEN="$(jq -er '.data.reauth_token' "$LAST_RESPONSE")" || fail 'restore reauth response has no reauth_token'
RESTORE_KEY="restore-idempotency-$BACKUP_EXPORT_ID"
jq -n --arg preview "$BACKUP_EXPORT_ID" --arg reauth "$RESTORE_REAUTH_TOKEN" '{preview_id:$preview, reauth_token:$reauth, confirmation:"RESTORE_CONFIGURATION"}' > "$RUN_ROOT/restore-apply.json"
api_json restore-apply-first POST /api/v1/settings/restore/apply 200 "$RUN_ROOT/restore-apply.json" "$RESTORE_KEY"
assert_response restore-apply '.data.applied == true and (.data.pre_restore_backup_export_id | type) == "string"'
jq -S '.data' "$LAST_RESPONSE" > "$RUN_ROOT/restore-response-first.data.json"
api_json restore-apply-repeat POST /api/v1/settings/restore/apply 200 "$RUN_ROOT/restore-apply.json" "$RESTORE_KEY"
jq -S '.data' "$LAST_RESPONSE" > "$RUN_ROOT/restore-response-repeat.data.json"
cmp -- "$RUN_ROOT/restore-response-first.data.json" "$RUN_ROOT/restore-response-repeat.data.json" || fail 'restore idempotency response changed'

api_get final-diagnostics /api/v1/diagnostics 200
assert_response final-diagnostics '(.data.memory_budget.api_budget_mib == 128 and .data.memory_budget.worker_budget_mib == 512 and (.data.runtime.read_only_boundary | type) == "boolean")'

printf '%s\n' 'REAL API FLOW PASSED: two-source scan, metadata/quota import, category history, compare, export idempotency, backup/restore, cleanup preview and read-only gate.'
