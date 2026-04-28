#!/bin/bash
# Common configuration and functions for KAE build scripts

# NOTE: This file is sourced by multiple build scripts.
# Keep it POSIX-ish bash and avoid exiting unexpectedly unless explicitly requested.
set -o pipefail

# Get the directory of the current script (scripts/buildScript/)
# Use a unique variable name to avoid conflict with sourcing scripts
COMMON_SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# SRC_PATH is the parent directory of parent directory of COMMON_SCRIPT_DIR (KAE/)
SRC_PATH="$(dirname "$(dirname "$COMMON_SCRIPT_DIR")")"

KAE_KERNEL_DIR=""
KAE_SPEC_FILE=""
OPENSSL_CONFIGURE_FLAG=""
KAE_UADK_DIR=${SRC_PATH}/uadk
KAE_OPENSSL_DIR=${SRC_PATH}/KAEOpensslEngine
KAE_ZLIB_DIR=${SRC_PATH}/KAEZlib
KAE_ZSTD_DIR=${SRC_PATH}/KAEZstd
KAE_LZ4_DIR=${SRC_PATH}/KAELz4
KAE_GZIP_DIR=${SRC_PATH}/KAEGzip
KAE_SNAPPY_DIR=${SRC_PATH}/KAESnappy

KAE_BUILD=${SRC_PATH}/kae_build/
KAE_BUILD_LIB=${SRC_PATH}/kae_build/lib
KAE_BUILD_HEAD=${SRC_PATH}/kae_build/head

IMPLEMENTER=""
CPUPART=""

function kae_info() { echo "[KAE][INFO] $*"; }
function kae_warn() { echo "[KAE][WARN] $*" 1>&2; }
function kae_err()  { echo "[KAE][ERROR] $*" 1>&2; }
function kae_die()  { kae_err "$*"; exit 1; }

function kae_jobs()
{
    if [ -n "${BUILD_JOBS:-}" ]; then
        echo "${BUILD_JOBS}"
        return 0
    fi
    if command -v nproc >/dev/null 2>&1; then
        nproc
        return 0
    fi
    echo 4
}

function kae_prepare_dir_clean()
{
    local dir="$1"
    if [ -z "$dir" ]; then
        kae_die "kae_prepare_dir_clean: empty dir"
    fi
    if [ -d "$dir" ]; then
        rm -rf "$dir"/*
    else
        mkdir -p "$dir"
    fi
}

function kae_require_cmd()
{
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || kae_die "missing required command: $cmd"
}

function kae_apply_patch_file()
{
    # Make patch application idempotent:
    # - First try reverse quietly (ignore failure)
    # - Then apply with -N (ignore already-applied)
    local patch_file="$1"
    [ -f "$patch_file" ] || kae_die "patch not found: $patch_file"
    patch --no-backup-if-mismatch -p1 -R -s --forward < "$patch_file" || true
    patch --no-backup-if-mismatch -p1 -N -s --forward < "$patch_file"
}

function kae_apply_uadk_patches()
{
    ( 
        cd "${SRC_PATH}" || exit 1
        kae_apply_patch_file "./scripts/patches/0001-uadk-add-ctr-mode.patch"
        kae_apply_patch_file "./scripts/patches/0003-fix-uadk-openssl3-bug.patch"
        kae_apply_patch_file "./scripts/patches/0005-add-uadk-ecc-and-comp-header-for-kae.patch"
        kae_apply_patch_file "./scripts/patches/0007-uadk-support-lz77-only-for-kaelz4.patch"
        kae_apply_patch_file "./scripts/patches/0008-uadk-support-sgl-zero-copy-for-kaelz4.patch"
        kae_apply_patch_file "./scripts/patches/0009-uadk-optimizations-to-zip-module.patch"
    )
}

function build_check_OS_version()
{
    local KERNEL_VERSION=""
    if command -v rpm >/dev/null 2>&1; then
        KERNEL_VERSION=`rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' kernel-devel 2>/dev/null | head -n 1 || true`
    fi
    if [ -z "$KERNEL_VERSION" ]; then
        KERNEL_VERSION=`uname -r`
    fi

    if [[ "$KERNEL_VERSION" == 6.6.* ]]; then
        KAE_KERNEL_DIR=${SRC_PATH}/KAEKernelDriver/KAEKernelDriver-OLK-6.6
        KAE_SPEC_FILE=${SRC_PATH}/scripts/specFile/kae_openeuler2403.spec
        OPENSSL_CONFIGURE_FLAG="--libdir=/usr/local/lib/engines-3.0 --enable-kae --enable-engine --with-openssl_install_dir=/usr/"
    elif [[ "$KERNEL_VERSION" == 5.15.* ]]; then
        KAE_KERNEL_DIR=${SRC_PATH}/KAEKernelDriver/KAEKernelDriver-OLK-5.10
        KAE_SPEC_FILE=${SRC_PATH}/scripts/specFile/kae.spec
        OPENSSL_CONFIGURE_FLAG="--libdir=/usr/local/lib/engines-1.1/ --enable-kae"
    elif [[ "$KERNEL_VERSION" == 5.10.* ]]; then
        KAE_KERNEL_DIR=${SRC_PATH}/KAEKernelDriver/KAEKernelDriver-OLK-5.10
        KAE_SPEC_FILE=${SRC_PATH}/scripts/specFile/kae.spec
        OPENSSL_CONFIGURE_FLAG="--libdir=/usr/local/lib/engines-1.1/ --enable-kae"
    elif [[ "$KERNEL_VERSION" == 5.4.* ]]; then
        KAE_KERNEL_DIR=${SRC_PATH}/KAEKernelDriver/KAEKernelDriver-OLK-5.4
        KAE_SPEC_FILE=${SRC_PATH}/scripts/specFile/kae.spec
        OPENSSL_CONFIGURE_FLAG="--libdir=/usr/local/lib/engines-1.1/ --enable-kae"
    elif [[ "$KERNEL_VERSION" == 4.19.* ]]; then
        KAE_KERNEL_DIR=${SRC_PATH}/KAEKernelDriver/KAEKernelDriver-OLK-4.19
        KAE_SPEC_FILE=${SRC_PATH}/scripts/specFile/kae.spec
        OPENSSL_CONFIGURE_FLAG="--libdir=/usr/local/lib/engines-1.1/ --enable-kae"
    else
        kae_die "unsupported kernel version: $KERNEL_VERSION"
    fi
}

function check_environment()
{
    if [ ! -r /proc/cpuinfo ]; then
        kae_warn "/proc/cpuinfo not available; skip Kunpeng CPU check"
        return 0
    fi
    # Use awk directly (without grep|awk pipe) to avoid silent exit under set -e/pipefail
    IMPLEMENTER=$(awk -F: '/^CPU implementer/{gsub(/^[[:space:]]+/, "", $2); print $2; exit}' /proc/cpuinfo)
    CPUPART=$(awk -F: '/^CPU part/{gsub(/^[[:space:]]+/, "", $2); print $2; exit}' /proc/cpuinfo)
    if [ "${IMPLEMENTER}" != "0x48" ]; then
        if [ "${KAE_ALLOW_NON_KUNPENG_BUILD:-0}" = "1" ]; then
            kae_warn "Non-Kunpeng build override enabled by KAE_ALLOW_NON_KUNPENG_BUILD=1; detected implementer=${IMPLEMENTER:-unknown}, part=${CPUPART:-unknown}"
            return 0
        fi
        kae_die "Only supported on Kunpeng CPUs (implementer 0x48); got ${IMPLEMENTER:-unknown}. Set KAE_ALLOW_NON_KUNPENG_BUILD=1 to override for build scenarios."
    fi
}

function kae_is_zip_optional_component_unsupported_cpu()
{
    # When override is enabled, skip all CPU-model based build gating.
    if [ "${KAE_ALLOW_NON_KUNPENG_BUILD:-0}" = "1" ]; then
        return 1
    fi

    if [ "${IMPLEMENTER}" = "0x48" ] && [ "${CPUPART}" = "0xd01" ]; then
        return 0
    fi

    return 1
}
