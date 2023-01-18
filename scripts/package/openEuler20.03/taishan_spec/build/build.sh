#!/bin/bash
set -e
MAKE_PATH=$(pwd)

OUTPUT_PATH=$MAKE_PATH/../output
SRC_PATH=$MAKE_PATH/../../hisi_acc
KAE_SPEC_PATH="/home/taishan/kae.spec"
VBUILDVERSION=$(cat $KAE_SPEC_PATH | grep 'Version:' | awk '{print substr($0, 15, 7)}')
BUILDVERSION=$(eval echo $VBUILDVERSION)

ZLIB_PATH="/home/taishan/zlib-1.2.11.tar.gz"
KAEDRIVER_SPEC_PATH="/home/taishan/kae_driver.spec"
WARPDRIVER_SPEC_PATH="/home/taishan/libwd.spec"
KAEZIP_SPEC_PATH="/home/taishan/kaezip.spec"

if [ $2 == "sles15.1" ];then
    RPM_PATH=/usr/src/packages/RPMS/aarch64
else
    RPM_PATH=/root/rpmbuild/RPMS/aarch64
fi:::

function build_targets_hisi()
{
    cd $SRC_PATH/KAEdriver

    cp $KAEDRIVER_SPEC_PATH kae_driver
    cp $WARPDRIVER_SPEC_PATH warpdrive

    tar -czf $OUTPUT_PATH/kae_driver-"$BUILDVERSION".tar.gz  kae_driver
    rpmbuild -tb $OUTPUT_PATH/kae_driver-"$BUILDVERSION".tar.gz
    tar -czf $OUTPUT_PATH/libwd-"$BUILDVERSION".tar.gz  warpdrive
    rpmbuild -tb $OUTPUT_PATH/libwd-"$BUILDVERSION".tar.gz
    
    local rpm_info=$(rpm -qi libwd | grep "$BUILDVERSION")
    if [[ -n $rpm_info ]];then
        rpm -e libwd
    fi
    rpm -ivh $RPM_PATH/libwd-"$BUILDVERSION"*

    cd $SRC_PATH

    cp $KAE_SPEC_PATH KAE
    cp $KAEZIP_SPEC_PATH KAEzip
    
    tar -czf $OUTPUT_PATH/libkae-"$BUILDVERSION".tar.gz  KAE
    rpmbuild -tb $OUTPUT_PATH/libkae-"$BUILDVERSION".tar.gz
    cp $ZLIB_PATH ./KAEzip/open_source
    tar -czf $OUTPUT_PATH/libkaezip-"$BUILDVERSION".tar.gz  KAEzip
    rpmbuild -tb $OUTPUT_PATH/libkaezip-"$BUILDVERSION".tar.gz

    cp -f $RPM_PATH/*.rpm  $OUTPUT_PATH
    rm -rf $RPM_PATH/*.rpm
    cd $RPM_PATH/../../BUILD
    rm -rf kae_driver* libwd* libkae*

    rpm_info=$(rpm -qi libwd | grep "$BUILDVERSION")
    if [[ -n $rpm_info ]];then
        rpm -e libwd
    fi
}

function main()
{
    build_targets_hisi
    if [ $? -ne 0 ];then
        exit 1
    fi
}

main $@
exit $?
