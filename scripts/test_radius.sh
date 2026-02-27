#!/bin/bash

set -euo pipefail
set -o errtrace

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BUILD_MODE="${BUILD_MODE:-}"
IMAGE="${IMAGE:-}"
PYTHON_IMAGE="${PYTHON_IMAGE:-kanidm/radius:devel}"
RUST_IMAGE="${RUST_IMAGE:-kanidm/radius:rust-dev}"
KEEP_CONTAINERS="${KEEP_CONTAINERS:-0}"
RADIUS_MODULE_IMPL="${RADIUS_MODULE_IMPL:-rust}"
RUN_SETUP_DEV_ENV="${RUN_SETUP_DEV_ENV:-0}"
RADIUS_TEST_USER="${RADIUS_TEST_USER:-radius_test_user}"
RADIUS_GROUP="${RADIUS_GROUP:-radius_access_allowed}"
RADIUS_SERVICE_ACCOUNT="${RADIUS_SERVICE_ACCOUNT:-radius_server}"
RADIUS_DEFAULT_VLAN="${RADIUS_DEFAULT_VLAN:-10}"
RADIUS_CLIENT_SECRET="${RADIUS_CLIENT_SECRET:-testing123}"
RADIUS_CONTAINER_NAME="${RADIUS_CONTAINER_NAME:-radiusd-e2e}"
RADIUS_CLIENT_IP="${RADIUS_CLIENT_IP:-127.0.0.1}"
RADIUS_CLIENT_NASPORT="${RADIUS_CLIENT_NASPORT:-10}"
IDM_ADMIN_SPN="${IDM_ADMIN_SPN:-idm_admin@localhost}"
ADMIN_SPN="${ADMIN_SPN:-admin@localhost}"
ASSERT_VLAN="${ASSERT_VLAN:-0}"

KANIDM_STARTED=0
KANIDMD_PID=""
RADIUS_CONFIG_FILE=""
RADIUS_MOD_FILE=""
RADIUS_DEFAULT_SITE_FILE=""
RADIUS_INNER_SITE_FILE=""
KANIDMD_LOG_FILE="/tmp/kanidm/test_radius_kanidmd.log"
TESTS_PASSED=0
TESTS_FAILED=0

SETUP_DEV_SCRIPT="${REPO_ROOT}/scripts/setup_dev_environment.sh"
RADIUS_RUN_SCRIPT="${REPO_ROOT}/rlm_python/run_radius_container.sh"
DEFAULT_RADIUS_CONFIG="${REPO_ROOT}/examples/kanidm"
RUST_MOD_TEMPLATE="${REPO_ROOT}/rlm_python/mods-available/kanidm_rust"
SERVER_DAEMON_DIR="${REPO_ROOT}/server/daemon"
KANIDM_CONFIG_FILE="${SERVER_DAEMON_DIR}/insecure_server.toml"
KANIDM_CA_PATH="/tmp/kanidm/ca.pem"

log() {
    echo "[test_radius] $*"
}

die() {
    echo "[test_radius] ERROR: $*" >&2
    exit 1
}

cleanup() {
    set +e
    if [[ "${KEEP_CONTAINERS}" != "1" ]]; then
        docker rm -f "${RADIUS_CONTAINER_NAME}" >/dev/null 2>&1 || true
    fi
    if [[ "${KANIDM_STARTED}" -eq 1 && -n "${KANIDMD_PID}" ]]; then
        kill "${KANIDMD_PID}" >/dev/null 2>&1 || true
        wait "${KANIDMD_PID}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${RADIUS_CONFIG_FILE}" && -f "${RADIUS_CONFIG_FILE}" ]]; then
        rm -f "${RADIUS_CONFIG_FILE}"
    fi
    if [[ -n "${RADIUS_MOD_FILE}" && -f "${RADIUS_MOD_FILE}" ]]; then
        rm -f "${RADIUS_MOD_FILE}"
    fi
    if [[ -n "${RADIUS_DEFAULT_SITE_FILE}" && -f "${RADIUS_DEFAULT_SITE_FILE}" ]]; then
        rm -f "${RADIUS_DEFAULT_SITE_FILE}"
    fi
    if [[ -n "${RADIUS_INNER_SITE_FILE}" && -f "${RADIUS_INNER_SITE_FILE}" ]]; then
        rm -f "${RADIUS_INNER_SITE_FILE}"
    fi
}

on_error() {
    local line="${1}"
    local cmd="${2}"
    set +e
    echo "[test_radius] FAILURE at line ${line}: ${cmd}" >&2
    if docker ps -a --format '{{.Names}}' | grep -qx "${RADIUS_CONTAINER_NAME}"; then
        echo "[test_radius] Last FreeRADIUS logs:" >&2
        docker logs --tail 120 "${RADIUS_CONTAINER_NAME}" >&2 || true
    fi
    if [[ -f "${KANIDMD_LOG_FILE}" ]]; then
        echo "[test_radius] Last kanidmd logs:" >&2
        tail -n 120 "${KANIDMD_LOG_FILE}" >&2 || true
    fi
}

trap cleanup EXIT
trap 'on_error "${LINENO}" "${BASH_COMMAND}"' ERR

check_cmd() {
    local cmd="${1}"
    command -v "${cmd}" >/dev/null 2>&1 || die "Missing required command: ${cmd}"
}

check_file() {
    local file="${1}"
    [[ -f "${file}" ]] || die "Missing required file: ${file}"
}

wait_for_kanidm() {
    local attempts=0
    local max_attempts=60
    local status_url="${KANIDM_URL%/}/status"

    while ! curl --cacert "${KANIDM_CA_PATH}" -fs "${status_url}" >/dev/null 2>&1; do
        attempts=$((attempts + 1))
        if [[ "${attempts}" -ge "${max_attempts}" ]]; then
            die "Kanidm did not become healthy at ${status_url}"
        fi
        sleep 2
    done
}

build_kanidm_cmd() {
    KANIDM_CMD=(cargo run --manifest-path "${REPO_ROOT}/Cargo.toml")
    if [[ -n "${BUILD_MODE}" ]]; then
        KANIDM_CMD+=("${BUILD_MODE}")
    fi
    KANIDM_CMD+=(--bin kanidm --)
}

build_kanidmd_cmd() {
    KANIDMD_CMD=(cargo run --manifest-path "${REPO_ROOT}/Cargo.toml")
    if [[ -n "${BUILD_MODE}" ]]; then
        KANIDMD_CMD+=("${BUILD_MODE}")
    fi
    KANIDMD_CMD+=(-p daemon --bin kanidmd --)
}

verify_rust_image_has_module() {
    local out
    local rc=0
    set +e
    out="$(
        docker run --rm --entrypoint /bin/sh "${IMAGE}" -c \
            'for d in /usr/lib64/freeradius /usr/lib/freeradius; do [ -f "$d/rlm_kanidm.so" ] && echo "$d/rlm_kanidm.so" && exit 0; done; exit 1' 2>&1
    )"
    rc=$?
    set -e
    if [[ "${rc}" -ne 0 ]]; then
        echo "${out}" >&2
        die "Rust module rlm_kanidm.so not found in image ${IMAGE}"
    fi
    log "Found Rust module in image: ${out}"
}

prepare_rust_radius_overrides() {
    RADIUS_MOD_FILE="$(mktemp /tmp/kanidm/radius_mod_kanidm.XXXXXX)"
    cp "${RUST_MOD_TEMPLATE}" "${RADIUS_MOD_FILE}"

    RADIUS_DEFAULT_SITE_FILE="$(mktemp /tmp/kanidm/radius_site_default.XXXXXX)"
    RADIUS_INNER_SITE_FILE="$(mktemp /tmp/kanidm/radius_site_inner.XXXXXX)"
    sed -E 's/^[[:space:]]*python3[[:space:]]*$/    kanidm/' "${REPO_ROOT}/rlm_python/sites-available/default" > "${RADIUS_DEFAULT_SITE_FILE}"
    sed -E 's/^[[:space:]]*python3[[:space:]]*$/    kanidm/' "${REPO_ROOT}/rlm_python/sites-available/inner-tunnel" > "${RADIUS_INNER_SITE_FILE}"
}

run_allow_exists() {
    local context="$1"
    shift
    local output
    local rc=0

    set +e
    output="$("$@" 2>&1)"
    rc=$?
    set -e

    if [[ "${rc}" -eq 0 ]]; then
        return 0
    fi

    if echo "${output}" | grep -Eiq "AttrUnique|already exists|already a member|duplicate|exists"; then
        log "${context}: already satisfied"
        return 0
    fi

    echo "${output}" >&2
    die "${context} failed"
}

extract_last_json_line() {
    local input="$1"
    echo "${input}" | awk '/^\{.*\}$/ { line = $0 } END { print line }'
}

extract_api_token() {
    local input="$1"
    local json_line
    local token=""

    json_line="$(extract_last_json_line "${input}")"
    if [[ -n "${json_line}" ]]; then
        token="$(echo "${json_line}" | jq -r '.result // .secret // empty' 2>/dev/null || true)"
    fi

    if [[ -z "${token}" ]]; then
        token="$(echo "${input}" | awk 'NF { last=$0 } END { print last }' | tr -d '\r')"
        if [[ "${token}" == Success:* ]]; then
            token=""
        fi
    fi

    if [[ -z "${token}" ]]; then
        token="$(echo "${input}" | grep -Eo '[[:alnum:]_-]{24,}' | tail -n 1 || true)"
    fi

    echo "${token}"
}

toml_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/}"
    value="${value//$'\r'/}"
    echo "${value}"
}

assert_radtest_result() {
    local label="$1"
    local username="$2"
    local password="$3"
    local expected="$4"
    local output
    local rc=0
    local err_trap=""

    err_trap="$(trap -p ERR || true)"
    trap - ERR

    if command -v radtest >/dev/null 2>&1; then
        if output="$(radtest "${username}" "${password}" "${RADIUS_CLIENT_IP}" "${RADIUS_CLIENT_NASPORT}" "${RADIUS_CLIENT_SECRET}" 2>&1)"; then
            rc=0
        else
            rc=$?
        fi
    else
        if output="$(docker exec "${RADIUS_CONTAINER_NAME}" radtest "${username}" "${password}" "${RADIUS_CLIENT_IP}" "${RADIUS_CLIENT_NASPORT}" "${RADIUS_CLIENT_SECRET}" 2>&1)"; then
            rc=0
        else
            rc=$?
        fi
    fi
    if [[ -n "${err_trap}" ]]; then
        eval "${err_trap}"
    fi

    if ! echo "${output}" | grep -q "${expected}"; then
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo "[test_radius] ${label}: expected ${expected}, rc=${rc}" >&2
        echo "${output}" >&2
        return 1
    fi

    TESTS_PASSED=$((TESTS_PASSED + 1))
    log "${label}: ${expected}"
    echo "${output}"
    return 0
}

log "Checking prerequisites"
check_cmd cargo
check_cmd jq
check_cmd curl
check_cmd docker
check_cmd grep
check_cmd awk
check_file "${RADIUS_RUN_SCRIPT}"
check_file "${RUST_MOD_TEMPLATE}"
if [[ "${RUN_SETUP_DEV_ENV}" == "1" ]]; then
    check_file "${SETUP_DEV_SCRIPT}"
fi
if [[ -n "${CONFIG_FILE:-}" ]]; then
    check_file "${CONFIG_FILE}"
else
    check_file "${DEFAULT_RADIUS_CONFIG}"
fi
if ! command -v radtest >/dev/null 2>&1; then
    log "radtest not found on host, will use container radtest"
fi

build_kanidm_cmd
build_kanidmd_cmd

case "${RADIUS_MODULE_IMPL}" in
    rust)
        if [[ -z "${IMAGE}" ]]; then
            IMAGE="${RUST_IMAGE}"
        fi
        log "Validating Rust FreeRADIUS module exists in image ${IMAGE}"
        verify_rust_image_has_module
        log "Preparing FreeRADIUS config overrides for rust module"
        prepare_rust_radius_overrides
        ;;
    python)
        if [[ -z "${IMAGE}" ]]; then
            IMAGE="${PYTHON_IMAGE}"
        fi
        log "Using existing python3 FreeRADIUS module path"
        ;;
    *)
        die "Unsupported RADIUS_MODULE_IMPL='${RADIUS_MODULE_IMPL}', expected 'rust' or 'python'"
        ;;
esac

[[ -f "${KANIDM_CONFIG_FILE}" ]] || die "Kanidm server config file not found: ${KANIDM_CONFIG_FILE}"
KANIDM_URL="$(grep -E '^origin.*https' "${KANIDM_CONFIG_FILE}" | awk '{print $NF}' | tr -d '"')"
[[ -n "${KANIDM_URL}" ]] || die "Failed to derive KANIDM_URL from ${KANIDM_CONFIG_FILE}"

if ! curl --cacert "${KANIDM_CA_PATH}" -fs "${KANIDM_URL%/}/status" >/dev/null 2>&1; then
    log "Kanidm not healthy; starting temporary dev server"
    mkdir -p /tmp/kanidm
    rm -f /tmp/kanidm/kanidm.db
    (
        cd "${SERVER_DAEMON_DIR}" || exit 1
        export KANIDM_CONFIG="./insecure_server.toml"
        "${KANIDMD_CMD[@]}" cert-generate >/dev/null
        "${KANIDMD_CMD[@]}" server >"${KANIDMD_LOG_FILE}" 2>&1 &
        echo $! > /tmp/kanidm/test_radius_kanidmd.pid
    )
    KANIDMD_PID="$(cat /tmp/kanidm/test_radius_kanidmd.pid)"
    rm -f /tmp/kanidm/test_radius_kanidmd.pid
    KANIDM_STARTED=1
fi

log "Waiting for Kanidm readiness at ${KANIDM_URL%/}/status"
wait_for_kanidm

if [[ "${RUN_SETUP_DEV_ENV}" == "1" ]]; then
    log "Running base environment setup"
    (
        cd "${REPO_ROOT}" || exit 1
        BUILD_MODE="${BUILD_MODE}" "${SETUP_DEV_SCRIPT}"
    )
else
    log "Skipping setup_dev_environment.sh (RUN_SETUP_DEV_ENV=${RUN_SETUP_DEV_ENV})"
fi

export KANIDM_URL
export KANIDM_CA_PATH
export KANIDM_CONFIG_FILE="${KANIDM_CONFIG_FILE}"

log "Recovering admin credentials"
IDM_ADMIN_PASS_RAW="$(
    cd "${SERVER_DAEMON_DIR}" && \
    KANIDM_CONFIG="./insecure_server.toml" "${KANIDMD_CMD[@]}" scripting recover-account idm_admin 2>&1
)"
IDM_ADMIN_PASS_JSON="$(extract_last_json_line "${IDM_ADMIN_PASS_RAW}")"
IDM_ADMIN_PASS="$(echo "${IDM_ADMIN_PASS_JSON}" | jq -r '.output // .password // empty')"
[[ -n "${IDM_ADMIN_PASS}" ]] || die "Failed to recover idm_admin password"

log "Logging in as ${IDM_ADMIN_SPN}"
"${KANIDM_CMD[@]}" login -D "${IDM_ADMIN_SPN}" --password "${IDM_ADMIN_PASS}"

log "Provisioning deterministic RADIUS fixtures"
run_allow_exists "create service account ${RADIUS_SERVICE_ACCOUNT}" \
    "${KANIDM_CMD[@]}" service-account create "${RADIUS_SERVICE_ACCOUNT}" "${RADIUS_SERVICE_ACCOUNT}" "${IDM_ADMIN_SPN}" -D "${IDM_ADMIN_SPN}"
run_allow_exists "create person ${RADIUS_TEST_USER}" \
    "${KANIDM_CMD[@]}" person create "${RADIUS_TEST_USER}" "${RADIUS_TEST_USER}" -D "${IDM_ADMIN_SPN}"
run_allow_exists "create group ${RADIUS_GROUP}" \
    "${KANIDM_CMD[@]}" group create "${RADIUS_GROUP}" -D "${IDM_ADMIN_SPN}"
run_allow_exists "add ${RADIUS_TEST_USER} to ${RADIUS_GROUP}" \
    "${KANIDM_CMD[@]}" group add-members "${RADIUS_GROUP}" "${RADIUS_TEST_USER}" -D "${IDM_ADMIN_SPN}"
run_allow_exists "add ${RADIUS_SERVICE_ACCOUNT} to idm_radius_servers" \
    "${KANIDM_CMD[@]}" group add-members idm_radius_servers "${RADIUS_SERVICE_ACCOUNT}" -D "${IDM_ADMIN_SPN}"

log "Generating radius secret for ${RADIUS_TEST_USER}"
"${KANIDM_CMD[@]}" person radius generate-secret "${RADIUS_TEST_USER}" -D "${IDM_ADMIN_SPN}"
RADIUS_SECRET_OUTPUT="$("${KANIDM_CMD[@]}" person radius show-secret "${RADIUS_TEST_USER}" -D "${IDM_ADMIN_SPN}" 2>&1)"
RADIUS_USER_SECRET="$(echo "${RADIUS_SECRET_OUTPUT}" | sed -n 's/^RADIUS secret for .*: //p' | tail -n 1)"
[[ -n "${RADIUS_USER_SECRET}" ]] || die "Failed to parse RADIUS user secret from output: ${RADIUS_SECRET_OUTPUT}"

log "Generating API token for ${RADIUS_SERVICE_ACCOUNT}"
if date -u -v+2H "+%Y-%m-%dT%H:%M:%SZ" >/dev/null 2>&1; then
    TOKEN_EXPIRY="$(date -u -v+2H "+%Y-%m-%dT%H:%M:%SZ")"
else
    TOKEN_EXPIRY="$(date -u -d "+2 hour" "+%Y-%m-%dT%H:%M:%SZ")"
fi
API_TOKEN_JSON="$("${KANIDM_CMD[@]}" service-account api-token generate "${RADIUS_SERVICE_ACCOUNT}" radius "${TOKEN_EXPIRY}" -o json -D "${IDM_ADMIN_SPN}" 2>&1)"
SERVICE_ACCOUNT_TOKEN="$(extract_api_token "${API_TOKEN_JSON}")"
[[ -n "${SERVICE_ACCOUNT_TOKEN}" ]] || die "Failed to parse service account API token"

CERT_SOURCE="/tmp/kanidm/cert.pem"
if [[ ! -f "${CERT_SOURCE}" ]]; then
    CERT_SOURCE="/tmp/kanidm/chain.pem"
fi
[[ -f "/tmp/kanidm/ca.pem" ]] || die "Missing /tmp/kanidm/ca.pem"
[[ -f "/tmp/kanidm/key.pem" ]] || die "Missing /tmp/kanidm/key.pem"
[[ -f "${CERT_SOURCE}" ]] || die "Missing certificate file (/tmp/kanidm/cert.pem or /tmp/kanidm/chain.pem)"

CERT_BASENAME="$(basename "${CERT_SOURCE}")"
RADIUS_CONFIG_FILE="$(mktemp /tmp/kanidm/radius_e2e.XXXXXX.toml)"
KANIDM_URL_ESCAPED="$(toml_escape "${KANIDM_URL}")"
SERVICE_ACCOUNT_TOKEN_ESCAPED="$(toml_escape "${SERVICE_ACCOUNT_TOKEN}")"
RADIUS_GROUP_ESCAPED="$(toml_escape "${RADIUS_GROUP}")"
RADIUS_CLIENT_SECRET_ESCAPED="$(toml_escape "${RADIUS_CLIENT_SECRET}")"
CERT_BASENAME_ESCAPED="$(toml_escape "${CERT_BASENAME}")"
cat > "${RADIUS_CONFIG_FILE}" <<EOF
uri = "${KANIDM_URL_ESCAPED}"
ca_path = "/certs/ca.pem"
auth_token = "${SERVICE_ACCOUNT_TOKEN_ESCAPED}"
radius_default_vlan = ${RADIUS_DEFAULT_VLAN}
radius_required_groups = ["${RADIUS_GROUP_ESCAPED}", "${RADIUS_GROUP_ESCAPED}@localhost"]
radius_groups = [
    { spn = "${RADIUS_GROUP_ESCAPED}", vlan = ${RADIUS_DEFAULT_VLAN} },
    { spn = "${RADIUS_GROUP_ESCAPED}@localhost", vlan = ${RADIUS_DEFAULT_VLAN} },
]
radius_clients = [
    { name = "localhost", ipaddr = "127.0.0.1", secret = "${RADIUS_CLIENT_SECRET_ESCAPED}" },
    { name = "docker", ipaddr = "172.17.0.0/16", secret = "${RADIUS_CLIENT_SECRET_ESCAPED}" },
]
radius_ca_path = "/certs/ca.pem"
radius_key_path = "/certs/key.pem"
radius_cert_path = "/certs/${CERT_BASENAME_ESCAPED}"
EOF

log "Starting FreeRADIUS container: ${RADIUS_CONTAINER_NAME}"
docker rm -f "${RADIUS_CONTAINER_NAME}" >/dev/null 2>&1 || true
DOCKER_RUN_ARGS=(
    -d
    --name "${RADIUS_CONTAINER_NAME}"
    --network host
    -e KANIDM_RLM_CONFIG=/data/kanidm
    -v /tmp/kanidm/:/data/
    -v /tmp/kanidm/:/tmp/kanidm/
    -v /tmp/kanidm/:/certs/
    -v "${RADIUS_CONFIG_FILE}:/data/kanidm:ro"
)
DOCKER_CMD_ARGS=()

if [[ "${RADIUS_MODULE_IMPL}" == "rust" ]]; then
    DOCKER_RUN_ARGS+=(
        --entrypoint /usr/sbin/radiusd
        -v "${RADIUS_MOD_FILE}:/etc/raddb/mods-enabled/kanidm:ro"
        -v "${RADIUS_DEFAULT_SITE_FILE}:/etc/raddb/sites-available/default:ro"
        -v "${RADIUS_INNER_SITE_FILE}:/etc/raddb/sites-available/inner-tunnel:ro"
    )
    DOCKER_CMD_ARGS+=(-f -l stdout)
fi

docker run "${DOCKER_RUN_ARGS[@]}" "${IMAGE}" "${DOCKER_CMD_ARGS[@]}" >/dev/null

log "Waiting for FreeRADIUS readiness"
for _ in $(seq 1 60); do
    if docker logs "${RADIUS_CONTAINER_NAME}" 2>&1 | grep -q "Ready to process requests"; then
        break
    fi
    if ! docker ps --format '{{.Names}}' | grep -qx "${RADIUS_CONTAINER_NAME}"; then
        die "FreeRADIUS container exited unexpectedly"
    fi
    sleep 2
done
if ! docker logs "${RADIUS_CONTAINER_NAME}" 2>&1 | grep -q "Ready to process requests"; then
    die "FreeRADIUS did not become ready in time"
fi

positive_output="$(assert_radtest_result "positive auth" "${RADIUS_TEST_USER}" "${RADIUS_USER_SECRET}" "Access-Accept")"
if [[ "${ASSERT_VLAN}" == "1" ]]; then
    if ! echo "${positive_output}" | grep -q "Tunnel-Private-Group-ID"; then
        die "Expected Tunnel-Private-Group-ID in positive response"
    fi
fi
assert_radtest_result "negative bad secret" "${RADIUS_TEST_USER}" "not-the-secret" "Access-Reject" >/dev/null

log "Removing ${RADIUS_TEST_USER} from ${RADIUS_GROUP} for authorization test"
"${KANIDM_CMD[@]}" group remove-members "${RADIUS_GROUP}" "${RADIUS_TEST_USER}" -D "${IDM_ADMIN_SPN}"
assert_radtest_result "negative missing group" "${RADIUS_TEST_USER}" "${RADIUS_USER_SECRET}" "Access-Reject" >/dev/null

log "Re-adding ${RADIUS_TEST_USER} to ${RADIUS_GROUP}"
"${KANIDM_CMD[@]}" group add-members "${RADIUS_GROUP}" "${RADIUS_TEST_USER}" -D "${IDM_ADMIN_SPN}"
assert_radtest_result "recovery auth" "${RADIUS_TEST_USER}" "${RADIUS_USER_SECRET}" "Access-Accept" >/dev/null

log "Summary: passed=${TESTS_PASSED} failed=${TESTS_FAILED} container=${RADIUS_CONTAINER_NAME} url=${KANIDM_URL}"
if [[ "${TESTS_FAILED}" -gt 0 ]]; then
    die "One or more RADIUS integration assertions failed"
fi

log "RADIUS integration tests completed successfully"
