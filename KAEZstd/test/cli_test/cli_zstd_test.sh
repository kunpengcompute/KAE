#!/bin/bash
# 测试文件路径
RESFILE="res.txt"

# zstd可执行文件路径
zstd_executable="/usr/bin/zstd"
kaezstd_executable="/usr/local/kaezstd/bin/zstd"
EXE="$zstd_executable $kaezstd_executable"

# 压缩级别
compression_level="1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20"

# 测试文件名称
# test_file_name="itemdata"
BASE_TESTDATA_ADD="../../../scripts/compressTestDataset/"
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
    local compressrate

    echo "KAE_ZSTD_LEVEL=$compression_level $exe -b$compression_level $BASE_TESTDATA_ADD$filename"
    RESDATA=$(KAE_ZSTD_LEVEL=$compression_level $exe -b$compression_level $BASE_TESTDATA_ADD$filename 2>&1 | tr -d '\r')
    # RESDATA=$(KAE_ZSTD_LEVEL=$compression_level $exe -b$compression_level $BASE_TESTDATA_ADD$filename 2>&1)
    
    if [ $exe == $zstd_executable ]; then
        COMPRESS_SPEED=$(echo $RESDATA | awk '{print $(59)}')
        UNCOMPRESS_SPEED=$(echo $RESDATA | awk '{print $(62)}')
        COMPRESS_RATE=$(echo $RESDATA | awk '{print $(58)}')
    elif [ $exe == $kaezstd_executable ]; then
        COMPRESS_SPEED=$(echo $RESDATA | rev | awk '{print $(5)}' | rev)
        UNCOMPRESS_SPEED=$(echo $RESDATA | rev | awk '{print $(3)}' | rev)
        COMPRESS_RATE=$(echo $RESDATA | rev | awk '{print $(6)}' | rev)
    fi

    # compressrate=$(echo "$COMPRESS_RATE" | awk -F'\[(x),]' '{print $2}')
    compressrate=$(echo "$COMPRESS_RATE" | awk '{gsub(/[^0-9.]/, ""); print}')

    echo $exe $filename $compression_level $COMPRESS_SPEED $UNCOMPRESS_SPEED $compressrate >> $RESFILE


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
