set -e
SRC_PATH=$(pwd)
TARGET_DIR="/usr/local/kaegzip"

function install_gzip()
{
    cd "${SRC_PATH}"/open_source
    rm -rf gzip-1.13
    tar -zxvf gzip-1.13.tar.gz
    cd "${SRC_PATH}"/open_source/gzip-1.13/

    patch -Np1 < ../../patch/kaegzip_for_gzip-1.13.patch

    chmod +x configure
    chmod +x ./build-aux/git-version-gen

    LIBS='-lwd -lkaezip -lz' CFLAGS='-O2 -I/usr/local/include/uadk/' LDFLAGS='-L/usr/local/kaezip/lib -L/usr/local/lib -Wl,-rpath=/usr/local/kaezip/lib' ./configure
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
    esac
}

function main()
{
    Operate    "$1" "$2"
}

main "$@"
exit $?
