#!/bin/bash
set -e
set -o pipefail
set +x

readonly PRE_COMMIT_CONFIG=".pre-commit-config.yaml"

function log_info()
{
    echo "[INFO] $*"
}

function log_error()
{
    echo "[ERROR] $*" >&2
}

function die()
{
    log_error "$*"
    exit 1
}

function require_command()
{
    command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

function is_excluded_path()
{
    case "$1" in
        KAEKernelDriver/* | uadk/* | scripts/*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

function print_title()
{
    echo "================================================"
    echo "          KAE Pre-Commit CI Incremental Check"
    echo "================================================"
}

REPO_URL=${REPO_URL:-}
PR_ID=${PR_ID:-}
TARGET_BRANCH=${TARGET_BRANCH:-}

print_title
log_info "REPO_URL=${REPO_URL:-<unset>}"
log_info "PR_ID=${PR_ID:-<unset>}"
log_info "TARGET_BRANCH=${TARGET_BRANCH:-<unset>}"
if [ -n "${GIT_TOKEN:-}" ]; then
    log_info "GIT_TOKEN=<set>"
else
    log_info "GIT_TOKEN=<unset>"
fi

[ -n "${REPO_URL}" ] || die "REPO_URL is required"
[ -n "${PR_ID}" ] || die "PR_ID is required"
[ -n "${TARGET_BRANCH}" ] || die "TARGET_BRANCH is required"

require_command git
require_command python3

WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/kae-pre-commit.XXXXXX")
SOURCE_CODE_DIR="${WORK_ROOT}/source_code"
CREDENTIAL_FILE="${WORK_ROOT}/git-credentials"

function cleanup()
{
    if [ -n "${WORK_ROOT:-}" ] && [ -d "${WORK_ROOT}" ]; then
        rm -rf -- "${WORK_ROOT}"
    fi
}
trap cleanup EXIT

GIT_COMMAND=(git)
if [ -n "${GIT_TOKEN:-}" ]; then
    if [[ ! "${REPO_URL}" =~ ^https://([^/]+)/ ]]; then
        die "GIT_TOKEN authentication requires an HTTPS REPO_URL"
    fi

    REPO_DOMAIN="${BASH_REMATCH[1]}"
    umask 077
    printf 'https://oauth2:%s@%s\n' "${GIT_TOKEN}" "${REPO_DOMAIN}" > "${CREDENTIAL_FILE}"
    GIT_COMMAND=(git -c "credential.helper=store --file=${CREDENTIAL_FILE}")
fi

log_info "Cloning target branch"
"${GIT_COMMAND[@]}" clone --single-branch --branch "${TARGET_BRANCH}" -- "${REPO_URL}" "${SOURCE_CODE_DIR}"
cd "${SOURCE_CODE_DIR}"

git config user.email "openLingCI@gitcode.com"
git config user.name "openlibing.ci"
git config core.quotePath false

LOCAL_SOURCE_BRANCH="pr_${PR_ID}"
log_info "Fetching PR source: refs/merge-requests/${PR_ID}/head"
"${GIT_COMMAND[@]}" fetch origin \
    "refs/merge-requests/${PR_ID}/head:${LOCAL_SOURCE_BRANCH}"

"${GIT_COMMAND[@]}" pull
git checkout "${LOCAL_SOURCE_BRANCH}"
log_info "Merging target branch before checking"
if ! git merge "${TARGET_BRANCH}" --no-edit; then
    die "PR source cannot be merged with ${TARGET_BRANCH}"
fi

if [ ! -f "${PRE_COMMIT_CONFIG}" ]; then
    log_info "${PRE_COMMIT_CONFIG} was not found; check passed"
    exit 0
fi

CHANGED_FILES=()
EXCLUDED_FILES=()
while IFS= read -r -d '' file; do
    if is_excluded_path "${file}"; then
        EXCLUDED_FILES+=("${file}")
        continue
    fi
    CHANGED_FILES+=("${file}")
done < <(git diff --name-only --diff-filter=ACMR -z "origin/${TARGET_BRANCH}" HEAD)

if [ "${#EXCLUDED_FILES[@]}" -gt 0 ]; then
    log_info "Skipped ${#EXCLUDED_FILES[@]} file(s) under KAEKernelDriver/, uadk/, or scripts/"
fi

if [ "${#CHANGED_FILES[@]}" -eq 0 ]; then
    log_info "No checkable files changed; check passed"
    exit 0
fi

log_info "Checking ${#CHANGED_FILES[@]} changed file(s):"
printf '  %s\n' "${CHANGED_FILES[@]}"

PRE_COMMIT_COMMAND=(pre-commit)
if ! command -v pre-commit >/dev/null 2>&1; then
    PYPI_INDEX_URL="${PYPI_INDEX_URL:-https://repo.huaweicloud.com/repository/pypi/simple}"
    log_info "Installing pre-commit from ${PYPI_INDEX_URL}"
    python3 -m pip install --index-url "${PYPI_INDEX_URL}" pre-commit
    PRE_COMMIT_COMMAND=(python3 -m pre_commit)
fi

"${PRE_COMMIT_COMMAND[@]}" --version
log_info "Running pre-commit against PR changes only"

if "${PRE_COMMIT_COMMAND[@]}" run --show-diff-on-failure --files "${CHANGED_FILES[@]}"; then
    log_info "Pre-commit checks passed"
    exit 0
else
    CHECK_RESULT=$?
fi

log_error "Pre-commit checks failed"
echo "[INFO] Reproduce locally with:"
printf 'pre-commit run --show-diff-on-failure --files'
printf ' %q' "${CHANGED_FILES[@]}"
printf '\n'

exit "${CHECK_RESULT}"
