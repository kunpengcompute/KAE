#!/bin/bash

# 测试文件路径
test_file="test_file.txt"
Decompression_file="test_file_decop.txt"
RESFILE="res.txt"

# zstd可执行文件路径
zstd_executable="/usr/bin/zstd"
kaezstd_executable="/usr/local/kaezstd/bin/zstd"
EXE="$zstd_executable $kaezstd_executable"

# 压缩级别
# compression_level="1 4 6 8 10 12 14 16 17 20 22"
compression_level="1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22"

# 测试文件名称
# test_file_name="itemdata"
test_file_name="itemdata ooffice osdb samba webster xml x-ray"

function generate_test_file() {
    if [ $# -ne 1 ]; then
        echo "Usage: generate_file <size_in_M>"
        return 1
    fi

    size=$1
    dd if=/dev/urandom of=$test_file bs=1M count=$size
}

function compare_files() {
    if diff -q "$1" "$2" >/dev/null 2>&1; then
        echo "TRUE"
    else
        echo "FALSE"
    fi
}

# 测试函数
function run_test() {
    local filename="$1"
    local exe="$2"
    local compression_level="$3"
    # local win="$4"
    local compress_time
    local decompress_time
    local real_time
    local user_time
    local sys_time
    local compress_rate
    local COMPARE
    local comp_file_size
    local decomp_file_size
    local RES="$1"
    comp_file_size=$(stat -c %s $filename)
    RES="$RES , $exe , $compression_level  , $comp_file_size"

    # 压缩测试
    TIMEFORMAT='%R %U %S'
    echo "$exe -$compression_level $filename -o $filename.zst"
    compress_time=$(time (KAE_ZSTD_LEVEL=$compression_level $exe -$compression_level $filename -o $filename.zst >/dev/null) 2>&1)
    real_time=$(echo $compress_time | awk '{print $(NF-2)}')
    user_time=$(echo $compress_time | awk '{print $(NF-1)}')
    sys_time=$(echo $compress_time | awk '{print $(NF-0)}')
    echo "compress finished."
    # 压缩后文件大小 压缩比
    decomp_file_size=$(stat -c %s $filename.zst)
    RES="$RES , $decomp_file_size , $(echo "scale=4; $comp_file_size/$decomp_file_size" | bc)"
    # 压缩耗时 压缩效率
    RES="$RES , $real_time , $user_time , $sys_time , $(echo "scale=3; $comp_file_size/1024/1024/$real_time" | bc)"

    # printf "%lf %lf %lf" $real $user $sys >> $RESFILE

    TIMEFORMAT='%R %U %S'
    decompress_time=$(time ($exe -d $filename.zst -o $Decompression_file >/dev/null) 2>&1)
    real_time=$(echo $decompress_time | awk '{print $(NF-2)}')
    user_time=$(echo $decompress_time | awk '{print $(NF-1)}')
    sys_time=$(echo $decompress_time | awk '{print $(NF-0)}')
    RES="$RES , $real_time , $user_time , $sys_time , $(echo "scale=3; $decomp_file_size/1024/1024/$real_time" | bc)"

    COMPARE=`compare_files $filename $Decompression_file`
    RES="$RES , $COMPARE"
    echo $RES >> $RESFILE

    rm $filename.zst
    rm $Decompression_file
}

function clear(){
    rm $test_file*
    rm $Decompression_file
}

function main(){
    # clear
    echo "测试文件名称 , 可执行文件  ,  压缩等级  ,  压缩原始文件大小  ,  压缩后文件大小 , 压缩比 , 压缩real_time ,  压缩user_time  , 压缩 sys_time , 压缩效率M/s ,  解压缩real_time ,  解压缩user_time  , 解压缩 sys_time , 解压效率M/s , 一致性检查" > $RESFILE
    
    for exe in $EXE
    do
        for filename in $test_file_name
        do
            for level in $compression_level
            do
                echo "[debug]run_test $filename $exe $level"
                run_test $filename $exe $level
            done
        done
    done

}

main "$@"
exit $?
