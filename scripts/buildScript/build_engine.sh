#!/bin/bash
set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "${SCRIPT_DIR}/common.sh"

function build_engine_log()
{
    touch /var/log/kae.cnf
    chmod 666 /var/log/kae.cnf
    touch /var/log/kae.log
    chmod 666 /var/log/kae.log
}

function engine_log_clean()
{
    rm -rf /var/log/kae.log
}

function build_engine()
{
    openssl_install_path=$1
    if [ "$1" = "" ];then
        openssl_install_path=$(which openssl | awk -F'/bin' '{print $1}')
    fi
    openssl_install_path=${openssl_install_path%/}

    cd ${SRC_PATH}/KAEOpensslEngine
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
    autoreconf -i
    ./configure --libdir=/usr/local/lib/engines-1.1/ --enable-kae --with-openssl_install_dir=$openssl_install_path CFLAGS="-Wl,-z,relro,-z,now -fstack-protector-strong"
    make -j"$(kae_jobs)"
    make install
    # build_engine_log
}

function build_engine_asm()
{
    openssl_install_path=$1
    if [ "$1" = "" ];then
        openssl_install_path=$(which openssl | awk -F'/bin' '{print $1}')
    fi
    openssl_install_path=${openssl_install_path%/}

    enable_asm="--enable-kae-asm"
    if ! lscpu | grep -q sm4; then
        enable_asm=""
    fi

    cd ${SRC_PATH}/KAEOpensslEngine
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
    autoreconf -i
    ./configure --libdir=/usr/local/lib/engines-1.1/ --enable-kae $enable_asm --with-openssl_install_dir=$openssl_install_path CFLAGS="-Wl,-z,relro,-z,now -fstack-protector-strong"
    make -j"$(kae_jobs)"
    make install
    # build_engine_log
}

function engine_clean()
{
    cd ${SRC_PATH}/KAEOpensslEngine
    make uninstall
    make clean
    rm -rf /usr/local/lib/engines-1.1
    # engine_log_clean
}

function build_engine_openssl3()
{
    openssl3_install_path=$1
    if [ "$1" = "" ];then
        openssl3_install_path=$(which openssl | awk -F'/bin' '{print $1}')
    fi
    openssl3_install_path=${openssl3_install_path%/}
    
    cd ${SRC_PATH}/KAEOpensslEngine
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
    autoreconf -i

    if [ ! -f "$openssl3_install_path/include/openssl/opensslv.h" ]; then  
        echo "openssl3 install path is wrong, $openssl3_install_path/include/openssl/opensslv.h is not exist."  
        exit 1  
    else  
        if $openssl3_install_path/bin/openssl version | grep -q "OpenSSL 3."; then    
            echo "OpenSSL version is 3.x."    
        elif $openssl3_install_path/bin/openssl version | grep -q "OpenSSL 1."; then    
            $openssl3_install_path/bin/openssl version  
            echo "OpenSSL version is 1.x, please use openssl3.0 install path"    
            exit 1
        else 
            $openssl3_install_path/bin/openssl version 
            echo "OpenSSL version is not support"   
            exit 1
        fi
    fi

    ./configure --libdir=/usr/local/lib/engines-3.0 --enable-kae --enable-engine --with-openssl_install_dir=$openssl3_install_path  #/usr/local/ssl3 
    make -j"$(kae_jobs)"
    make install
    # build_engine_log
}

function build_engine_openssl3_asm()
{
    openssl3_install_path=$1
    if [ "$1" = "" ];then
        openssl3_install_path=$(which openssl | awk -F'/bin' '{print $1}')
    fi
    openssl3_install_path=${openssl3_install_path%/}

    enable_asm="--enable-kae-asm"
    if ! lscpu | grep -q sm4; then
        enable_asm=""
    fi
    
    cd ${SRC_PATH}/KAEOpensslEngine
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
    autoreconf -i

    if [ ! -f "$openssl3_install_path/include/openssl/opensslv.h" ]; then  
        echo "openssl3 install path is wrong, $openssl3_install_path/include/openssl/opensslv.h is not exist."  
        exit 1  
    else  
        if $openssl3_install_path/bin/openssl version | grep -q "OpenSSL 3."; then    
            echo "OpenSSL version is 3.x."    
        elif $openssl3_install_path/bin/openssl version | grep -q "OpenSSL 1."; then    
            $openssl3_install_path/bin/openssl version  
            echo "OpenSSL version is 1.x, please use openssl3.0 install path"    
            exit 1
        else 
            $openssl3_install_path/bin/openssl version 
            echo "OpenSSL version is not support"   
            exit 1
        fi
    fi

    ./configure --libdir=/usr/local/lib/engines-3.0 --enable-kae $enable_asm --enable-engine --with-openssl_install_dir=$openssl3_install_path  #/usr/local/ssl3 
    make -j"$(kae_jobs)"
    make install
    # build_engine_log
}

function engine_clean_openssl3()
{
    cd ${SRC_PATH}/KAEOpensslEngine
    make uninstall
    make clean
    rm -rf /usr/local/lib/engines-3.0
    # engine_log_clean
}

function build_engine_gmssl()
{
    gmssl_install_path=$1
    if [ "$1" = "" ];then
        gmssl_install_path=$(which openssl | awk -F'/bin' '{print $1}')
    fi
    gmssl_install_path=${gmssl_install_path%/}

    cd ${SRC_PATH}/KAEOpensslEngine
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
    autoreconf -i
    # gmssl当前仅支持no-sva设备
    ./configure --libdir=/usr/local/gmssl/lib/engines-1.1 --enable-kae --enable-kae-gmssl --with-openssl_install_dir=$gmssl_install_path  CFLAGS="-Wl,-z,relro,-z,now -fstack-protector-strong -I/usr/local/gmssl/include/" 
    make -j"$(kae_jobs)"
    make install
    # build_engine_log
}

function engine_clean_gmssl()
{
    cd ${SRC_PATH}/KAEOpensslEngine
    make uninstall
    make clean
    rm -rf /usr/local/gmssl/lib/engines-1.1
    # engine_log_clean
}

function build_engine3_tongsuo()
{
    tongsuo_install_path=$1
    if [ "$1" = "" ];then
        tongsuo_install_path=$(which openssl | awk -F'/bin' '{print $1}')
    fi
    tongsuo_install_path=${tongsuo_install_path%/}
    
    cd ${SRC_PATH}/KAEOpensslEngine
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
    autoreconf -i

    if [ ! -f "$tongsuo_install_path/include/openssl/opensslv.h" ]; then  
        echo "Tongsuo install path is wrong, $tongsuo_install_path/include/openssl/opensslv.h is not exist."  
        exit 1  
    else  
        if $tongsuo_install_path/bin/openssl version | grep -q "OpenSSL 3."; then    
            echo "Tongsuo's openssl version is 3.x."    
        else 
            $tongsuo_install_path/bin/openssl version 
            echo "Tongsuo's openssl version is not support"   
            exit 1
        fi
    fi

    ./configure --libdir=/usr/local/tongsuo/lib/engines-3.0 --enable-kae --enable-engine --enable-kae-tongsuo --with-openssl_install_dir=$tongsuo_install_path
    make -j"$(kae_jobs)"
    make install
    # build_engine_log
}

function engine3_clean_tongsuo()
{
    cd ${SRC_PATH}/KAEOpensslEngine
    make uninstall
    make clean
    rm -rf /usr/local/tongsuo/lib/engines-3.0
    # engine_log_clean
}

function build_engine_boringssl()
{
    boringssl_install_path=$1
    if [ "$1" = "" ];then
        boringssl_install_path=$(which bssl | awk -F'/bin' '{print $1}')
    fi
    boringssl_install_path=${boringssl_install_path%/}
    
    echo $boringssl_install_path
    cd ${SRC_PATH}/KAEOpensslEngine
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
    autoreconf -i

    ./configure --libdir=/usr/local/boringssl/lib/engines-1.1 --enable-kae --enable-engine --enable-kae-boringssl --with-openssl_install_dir=$boringssl_install_path
    make -j"$(kae_jobs)"
    make install
    # build_engine_log
}

function engine_clean_boringssl()
{
    cd ${SRC_PATH}/KAEOpensslEngine
    make uninstall
    make clean
    rm -rf /usr/local/boringssl/lib/engines-1.1
    # engine_log_clean
}

# Main execution logic
check_environment
build_check_OS_version

ACTION=$1
OPTION=$2
PATH_ARG=$2 # For engine3/gmssl path argument

case "$ACTION" in
    "engine")  
        if [ "$OPTION" = "clean" ]; then  
            engine_clean
        else  
            build_engine $PATH_ARG
        fi  
        ;;
    "engine_asm")  
        if [ "$OPTION" = "clean" ]; then  
            engine_clean
        else  
            build_engine_asm $PATH_ARG
        fi  
        ;; 
    "engine3")
        if [ "$OPTION" = "clean" ]; then
            engine_clean_openssl3
        else
            build_engine_openssl3 $PATH_ARG
        fi
        ;;
    "engine3_asm")
        if [ "$OPTION" = "clean" ]; then
            engine_clean_openssl3
        else
            build_engine_openssl3_asm $PATH_ARG
        fi
        ;;
    "engine_gmssl")  
        if [ "$OPTION" = "clean" ]; then  
            engine_clean_gmssl
        else  
            build_engine_gmssl $PATH_ARG
        fi  
        ;;
    "engine3_tongsuo")
        if [ "$OPTION" = "clean" ]; then
            engine3_clean_tongsuo
        else
            build_engine3_tongsuo $PATH_ARG
        fi
        ;;    
    "engine_boringssl")
        if [ "$OPTION" = "clean" ]; then
            engine_clean_boringssl
        else
            build_engine_boringssl $PATH_ARG
        fi
        ;;
    *)
        echo "Usage: $0 {engine|engine_asm|engine3|engine3_asm|engine_gmssl|engine3_tongsuo|engine_boringssl} [clean|<install_path>]"
        exit 1
        ;;
esac
