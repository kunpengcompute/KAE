#!/bin/sh
set -e

function main()
{
	echo $1
	if [ "$1" = "all" ];then
		echo "build all"
	        cd kae_driver
                make -j
                make install
                cd ../uadk
                sh autogen.sh
                sh conf.sh
                make -j
                make install
                cd ../kae_engine
		export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
                autoreconf -i
                ./configure --libdir=/usr/local/lib/engines-1.1/ --enable-kae
                make -j
                make install
	elif [ "$1" = "cleanup" ];then
		echo "cleanup all"
	        cd kae_driver
                make uninstall
                cd ../uadk
                make uninstall
                cd ../kae_engine
                make uninstall

	else
		echo "not support cmd, please input all/cleanup"
	fi
}

main "$@"
exit $?
