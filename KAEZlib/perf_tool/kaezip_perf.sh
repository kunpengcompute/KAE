#!/bin/bash

# 测试文件路径
RESFILE="res.txt"

# zstd可执行文件路径
zlib_executable="./zip_perf"
kaezlib_executable="./kaezip_perf"
EXE="$zlib_executable $kaezlib_executable"

# 压缩级别
compression_level="1 2 3 4 5 6 7 8 9"

# 测试文件名称
# test_file_name="itemdata"
BASE_TESTDATA_ADD="/home/zip_test_data/"
test_file_name="itemdata ooffice osdb samba webster xml x-ray"

# 测试函数
function run_test() {
    local filename="$1"
    local exe="$2"
    local compression_level="$3"
    # local win="$4"
    local RESDATA
    local COMPRESS_SPEED
    local COMPRESS_RATE
    local UNCOMPRESS_SPEED
    local LOOPTIME
    if [ $exe == "./zip_perf" ]; then
        LOOPTIME=2
    elif [ $exe == "./kaezip_perf" ]; then
        LOOPTIME=50
    fi

    # echo "./kaezip_perf -f $filename -n 5 -l $compression_level"
    RESDATA=$(./$exe -f ${BASE_TESTDATA_ADD}${filename} -n $LOOPTIME -l $compression_level)

    COMPRESS_SPEED=$(echo $RESDATA | awk '{print $(27)}')
    UNCOMPRESS_SPEED=$(echo $RESDATA | awk '{print $(43)}')
    COMPRESS_RATE=$(echo $RESDATA | awk '{print $(32)}')

    echo $exe $filename $compression_level $COMPRESS_SPEED $UNCOMPRESS_SPEED $COMPRESS_RATE >> $RESFILE


}


function main(){
    # clear
    echo "EXE文件 , 压缩文件 , Level , CompressSpeed(MB/s) , UncompressSpeed(MB/s) , CompressRate" > $RESFILE
    for exe in $EXE
    do
        for filename in $test_file_name
        do
            for level in $compression_level
            do
                run_test $filename $exe $level
            done
        done
    done


}

main "$@"
exit $?
