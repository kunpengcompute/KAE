#!/bin/bash
set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "${SCRIPT_DIR}/common.sh"

function build_all_comp_sva()
{
    kae_prepare_dir_clean "$KAE_BUILD"

    mkdir -p "$KAE_BUILD_LIB"
    mkdir -p "$KAE_BUILD_HEAD"
    # 编译Kernel
    cd "${KAE_KERNEL_DIR}"
    make -j"$(kae_jobs)"

    cp "${KAE_KERNEL_DIR}/hisilicon/sec2/hisi_sec2.ko" "$KAE_BUILD_LIB"
    cp "${KAE_KERNEL_DIR}/hisilicon/hpre/hisi_hpre.ko" "$KAE_BUILD_LIB"
    cp "${KAE_KERNEL_DIR}/hisilicon/hisi_qm.ko" "$KAE_BUILD_LIB"
    cp "${KAE_KERNEL_DIR}/uacce/uacce.ko" "$KAE_BUILD_LIB"
    cp "${KAE_KERNEL_DIR}/hisilicon/zip/hisi_zip.ko" "$KAE_BUILD_LIB"

    # 编译uadk
    cd "$KAE_UADK_DIR"
    bash autogen.sh
    bash conf.sh
    make -j"$(kae_jobs)"

    cp "${KAE_UADK_DIR}"/.libs/lib* "$KAE_BUILD_LIB"
    mkdir -p "$KAE_BUILD_HEAD/uadk"
    mkdir -p "$KAE_BUILD_HEAD/uadk/v1"
    cp -r "${KAE_UADK_DIR}/include/"* "$KAE_BUILD_HEAD/uadk"
        
    cp -r "${KAE_UADK_DIR}/v1/"*.h "$KAE_BUILD_HEAD/uadk/v1"

    # 编译openssl
    cd "$KAE_OPENSSL_DIR"
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
    autoreconf -i
    ./configure --libdir=/usr/local/lib/engines-1.1/
    make -j"$(kae_jobs)"

    cp "$KAE_OPENSSL_DIR"/src/.libs/*kae*so* "$KAE_BUILD_LIB"

    # 编译zlib
    cd "$KAE_ZLIB_DIR"
    bash setup.sh devbuild KAE2

    cp "$KAE_ZLIB_DIR"/lib* "$KAE_BUILD_LIB"
    cp "$KAE_ZLIB_DIR"/open_source/zlib-1.2.11/lib* "$KAE_BUILD_LIB"

    # 编译zstd
    cd "$KAE_ZSTD_DIR"
    bash build.sh devbuild

    cp "$KAE_ZSTD_DIR"/lib* "$KAE_BUILD_LIB"
    cp "$KAE_ZSTD_DIR"/open_source/zstd/programs/zstd "$KAE_BUILD_LIB"
    cp "$KAE_ZSTD_DIR"/open_source/zstd/programs/zstdgrep "$KAE_BUILD_LIB"
    cp "$KAE_ZSTD_DIR"/open_source/zstd/programs/zstdless "$KAE_BUILD_LIB"
    cp "$KAE_ZSTD_DIR"/open_source/zstd/lib/libzstd.so* "$KAE_BUILD_LIB"
    cp "$KAE_ZSTD_DIR"/open_source/zstd/lib/libzstd.a "$KAE_BUILD_LIB"
}

source "$SCRIPT_DIR/build_package_components.sh"

function build_rpm()
{
    local kernel_version
    kae_require_cmd rpm
    if ! kernel_version=$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' kernel-devel); then
        kae_die "failed to query kernel-devel; check the RPM database and install the development package matching the target kernel"
    fi
    kernel_version=${kernel_version%%$'\n'*}
    [ -n "$kernel_version" ] || kae_die "kernel-devel query returned an empty version; check the installed development package"
    build_package_components "$kernel_version"
}

function build_rpmpack()
{
    local version work spec
    version=$(sh "$SRC_PATH/scripts/kae-version.sh")
    mkdir -p "$KAE_BUILD/rpmpack"
    work=$(mktemp -d "$KAE_BUILD/rpmpack/run.XXXXXX")
    mkdir -p "$work"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
    spec="$work/SPECS/$(basename "$KAE_SPEC_FILE")"
    sed "s/@KAE_VERSION@/$version/g" "$KAE_SPEC_FILE" > "$spec"
    printf 'RPM build tree and packages: %s\n' "$work"
    # Exclude previous build products, including libraries from an older VERSION.
    tar -C "$SRC_PATH" --exclude=.git --exclude=kae_build --exclude=kae_output --exclude=.vscode \
        --exclude=.DS_Store --exclude='._*' \
        --exclude='*.o' --exclude='*.ko' --exclude='*.a' --exclude='*.so' \
        --exclude='*.so.*' --exclude='*.lo' --exclude='*.la' \
        --exclude=.libs --exclude=.deps --exclude=autom4te.cache \
        --exclude=config.status --exclude=config.cache \
        -czf "$work/SOURCES/kae-$version.tar.gz" .
    rpmbuild -ba "$spec" --define "_topdir $work" \
        --define "kae_allow_non_kunpeng ${KAE_ALLOW_NON_KUNPENG_BUILD:-0}"
    cp "$work"/RPMS/aarch64/kae-*.rpm "$KAE_BUILD/"
}

# Main execution logic
check_environment
build_check_OS_version

ACTION=$1

case "$ACTION" in
    "rpm")  
        build_rpm  
        ;;
    "rpmpack")  
        build_rpmpack
        ;;
    "all_sva")
        build_all_comp_sva
        ;;
    *)
        echo "Usage: $0 {rpm|rpmpack|all_sva}"
        exit 1
        ;;
esac
