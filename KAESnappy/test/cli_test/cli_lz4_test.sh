#!/bin/bash
# lz4可执行文件路径
lz4_executable="/usr/bin/lz4"
kaelz4_executable="/usr/local/kaelz4/bin/lz4"
EXE="$lz4_executable $kaelz4_executable"

# 压缩级别
compression_level="1"

SRC_PATH=$(pwd)

# 测试文件名称
BASE_TESTDATA_ADD="${SRC_PATH}/../../../scripts/compressTestDataset/"
test_file_name="ooffice osdb samba webster xml x-ray"
blocksize="4 5 6 7"

# 测试函数
function run_test() {
    local filename="$1"
    local exe="$2"
    local compression_level="$3"
    local blocksize="$4"
    local RESDATA
    local COMPRESS_SPEED
    local COMPRESS_RATE
    local UNCOMPRESS_SPEED
    local compressrate

    echo "KAE_LZ4_LEVEL=$compression_level $exe -b$compression_level -B$blocksize $BASE_TESTDATA_ADD$filename"
    $exe -b$compression_level -B$blocksize $BASE_TESTDATA_ADD$filename
    
    #if [ $exe == $lz4_executable ]; then
    #    COMPRESS_SPEED=$(echo $RESDATA | awk '{print $(59)}')
    #    UNCOMPRESS_SPEED=$(echo $RESDATA | awk '{print $(62)}')
    #    COMPRESS_RATE=$(echo $RESDATA | awk '{print $(58)}')
    #elif [ $exe == $kaelz4_executable ]; then
    #    COMPRESS_SPEED=$(echo $RESDATA | rev | awk '{print $(5)}' | rev)
    #    UNCOMPRESS_SPEED=$(echo $RESDATA | rev | awk '{print $(3)}' | rev)
    #    COMPRESS_RATE=$(echo $RESDATA | rev | awk '{print $(6)}' | rev)
    #fi

    # compressrate=$(echo "$COMPRESS_RATE" | awk -F'\[(x),]' '{print $2}')
    compressrate=$(echo "$COMPRESS_RATE" | awk '{gsub(/[^0-9.]/, ""); print}')

    echo $exe $filename $compression_level $COMPRESS_SPEED $UNCOMPRESS_SPEED $compressrate
}

function main(){
    # clear
    echo "EXE文件 , 压缩文件 , Level , CompressSpeed(MB/s) , UncompressSpeed(MB/s) , CompressRate"
    for exe in $EXE
    do
        for filename in $test_file_name
        do
            for level in $compression_level
            do
                for blksize in $blocksize
                do
                    run_test $filename $exe $level $blksize
                done
            done
        done
    done
}

main "$@"
exit $?
