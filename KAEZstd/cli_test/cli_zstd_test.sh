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
compression_level="1 2 3 4 5 6 7 8 9 10 15 20"

# 测试文件大小(M)
test_file_size="1 10 20 30 40 50 100 500 1000"

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
    local test_file="$1"
    local exe="$2"
    local compression_level="$3"
    # local testfilesize="$4"
    local conpress_time
    local deconpress_time
    local real_time
    local user_time
    local sys_time
    local compress_rate
    local COMPARE
    local RES=""

    RES="$exe , $compression_level , $(stat -c %s $test_file)"

    # 压缩测试
    TIMEFORMAT='%R %U %S'
    conpress_time=$(time ($exe -$compression_level $test_file -o $test_file.zst >/dev/null ) 2>&1)
    real_time=$(echo $conpress_time | awk '{print $(NF-2)}')
    user_time=$(echo $conpress_time | awk '{print $(NF-1)}')
    sys_time=$(echo $conpress_time | awk '{print $(NF-0)}')

    RES="$RES , $(stat -c %s $test_file.zst) , $real_time , $user_time , $sys_time"

    # printf "%lf %lf %lf" $real $user $sys >> $RESFILE

    TIMEFORMAT='%R %U %S'
    deconpress_time=$(time ($exe -d $test_file.zst -o $Decompression_file) 2>&1 >/dev/null)
    real_time=$(echo $deconpress_time | awk '{print $(NF-2)}')
    user_time=$(echo $deconpress_time | awk '{print $(NF-1)}')
    sys_time=$(echo $deconpress_time | awk '{print $(NF-0)}')
    RES="$RES , $real_time , $user_time , $sys_time"

    COMPARE=`compare_files $test_file $Decompression_file`
    RES="$RES , $COMPARE"
    echo $RES >> $RESFILE
}

function clear(){
    rm $test_file*
    rm $Decompression_file
}

function main(){
    clear
    echo "可执行文件  ,  压缩等级  ,  压缩原始文件大小  ,  压缩后文件大小 , 压缩real_time ,  压缩user_time  , 压缩 sys_time ,  解压缩real_time ,  解压缩user_time  , 解压缩 sys_time ，一致性检查" > $RESFILE
    
    for exe in $EXE
    do
        for size in $test_file_size
        do
            for level in $compression_level
            do
                # 生成压缩文件
                generate_test_file $size
                # 测试压缩性能
                run_test $test_file $exe $level $size
                # 清除测试数据
                clear
            done
        done
    done

}

main "$@"
exit $?
