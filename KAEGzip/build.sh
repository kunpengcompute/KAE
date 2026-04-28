#!/bin/bash
set -e
SRC_PATH=$(pwd)
TARGET_DIR="/usr/local/kaegzip"

KAE_BUILD_HEAD=${SRC_PATH}/../kae_build/head
UADK_LIB=${SRC_PATH}/../kae_build/uadk/lib

function kaegzip_run_configure()
{
    local libs="$1"
    local cflags="$2"
    local ldflags="$3"

    if [ "${KAE_ALLOW_NON_KUNPENG_BUILD:-0}" = "1" ]; then
        HOST_TRIPLET="$(${CC:-gcc} -dumpmachine)"   # e.g. aarch64-redhat-linux-gnu
        BUILD_TRIPLET="aarch64-pc-linux-gnu"        # 同CPU, 不同vendor, 用于跳过conftest

        if [ -z "${HOST_TRIPLET}" ]; then
            echo "[KAEGzip][ERROR] failed to detect HOST_TRIPLET from \${CC:-gcc} -dumpmachine"
            return 1
        fi

        echo "[KAEGzip][WARN] KAE_ALLOW_NON_KUNPENG_BUILD=1, run configure in cross mode to skip conftest runtime."
        echo "[KAEGzip][INFO] host=${HOST_TRIPLET} build=${BUILD_TRIPLET}"

        LIBS="${libs}" CFLAGS="${cflags}" LDFLAGS="${ldflags}" \
            ./configure --host="${HOST_TRIPLET}" --build="${BUILD_TRIPLET}"
    else
        LIBS="${libs}" CFLAGS="${cflags}" LDFLAGS="${ldflags}" ./configure
    fi
}

function install_gzip()
{
    cd "${SRC_PATH}"/open_source
    rm -rf gzip-1.13
    tar -zxvf gzip-1.13.tar.gz
    cd "${SRC_PATH}"/open_source/gzip-1.13/

    patch -Np1 < ../../patch/kaegzip_for_gzip-1.13.patch

    chmod +x configure
    chmod +x ./build-aux/git-version-gen
    
    local libs='-lwd -lkaezip -lz'
    local cflags='-O2 -I/usr/local/include/uadk/ -I/usr/local/kaezip/include'
    local ldflags='-L/usr/local/kaezip/lib -L/usr/local/lib -Wl,-rpath=/usr/local/kaezip/lib'

    kaegzip_run_configure "${libs}" "${cflags}" "${ldflags}"
    make

    cd "${SRC_PATH}"
    ln -s ./open_source/gzip-1.13/gzip gzip

    if [ -d "${TARGET_DIR}" ]; then
        rm -rf "${TARGET_DIR}"
    fi

    mkdir -p "${TARGET_DIR}"
    cp ./open_source/gzip-1.13/gzip "${TARGET_DIR}"
    echo "install kaegzip success"
}

function dev_build_kaegzip()
{
    cd "${SRC_PATH}"/open_source
    rm -rf gzip-1.13
    tar -zxvf gzip-1.13.tar.gz
    cd "${SRC_PATH}"/open_source/gzip-1.13/

    patch -Np1 < ../../patch/kaegzip_for_gzip-1.13.patch

    chmod +x configure
    chmod +x ./build-aux/git-version-gen

    local libs="-lwd -lz -lkaezip"
    local cflags="-O2 -I${KAE_BUILD_HEAD}/uadk -I${SRC_PATH}/../kae_build/kaezip/include"
    local ldflags="-L${UADK_LIB} -L${SRC_PATH}/../kae_build/kaezip/lib"
    ldflags="${ldflags} -Wl,-rpath=/usr/local/kaezip/lib:/usr/local/lib:${SRC_PATH}/../kae_build/kaezip/lib:${UADK_LIB}"

    kaegzip_run_configure "${libs}" "${cflags}" "${ldflags}"
    make
}

function uninstall_gzip()
{
    cd "${SRC_PATH}"/open_source/gzip-1.13/
    make clean
    make uninstall

    cd "${SRC_PATH}"/open_source
    rm -rf "${SRC_PATH}"/open_source/gzip-1.13/
    
    cd "${SRC_PATH}"
    rm gzip

    rm -rf "${TARGET_DIR}"

    echo "uninstall kaegzip success"
    # hash -r
}

function Operate()
{
    case "$1" in 
        install)
            install_gzip
            ;;
        uninstall)
            uninstall_gzip
            ;;
        devbuild)
            dev_build_kaegzip
            ;;
    esac
}

function main()
{
    Operate    "$1" "$2"
}

main "$@"
exit $?
