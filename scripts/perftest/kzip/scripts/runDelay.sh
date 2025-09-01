export LD_LIBRARY_PATH=/usr/local/kaelz4/lib/:/usr/local/kaezstd/lib/:/usr/local/kaezip/lib/:$LD_LIBRARY_PATH
export KAE_LZ4_WINTYPE=8
export KAE_LZ4_COMP_TYPE=8
export KAE_LZ4_ASYNC_THREAD_NUM=12
export KAE_LZ4_ASYNC_DC_THREAD_NUM=10
export PRINT_TABLE_DATA=1
export KZIP_QAT_USE_DEV_NUM=1 # 测试单个QAT能力

buildParams="kae"
Algthm=()
ThreadNum=("12" "8" "7" "6" "5" "4" "3" "2" "1")

if [[ -d "/usr/local/kaelz4" ]]; then
    Algthm+=("kaelz4" "kaelz4_frame" "kaelz4async_block" "kaelz4async_frame" "kaelz4async_lz77" "kaelz4async_lz77_frame")
fi
if [[ -d "/usr/local/kaezip" ]]; then
    Algthm+=("kaezlib_deflate" "kaezlibasync_deflate")
fi

sh build.sh $buildParams


Datasets=("calgary.tar" "silesia.tar")
inflateNum=("1" "4" "8" "16" "64") # 单IO 单核测试
BlockSize=("4" "8" "16" "32" "64")
Multi=("1")

# 后台进程的分片大小，由执行脚本时的第2个参数控制。仅在第1个参数为with_full_compress 或 with_full_uncompress 时有效
BackProcessBlockSize=$2 
BackProcessInflight=$3 # 后台进程的inflight大小。仅在第1个参数为with_full_compress 或 with_full_uncompress 时有效
BackProcessBlockSize=${BackProcessBlockSize:=0}
BackProcessInflight=${BackProcessInflight:=0}

current_time=$(date +"%Y-%m-%d_%H-%M-%S")
LogFile=kzip-delay.log.$current_time.withBackProcess.blocksize-$BackProcessBlockSize.inflight-$BackProcessInflight
testFilePath=../../../scripts/compressTestDataset

diffFile() {
    local testFile=$1
    local testFileOrigin=$2
    if [[ ! -f "$testFile" ]]; then
        echo "Error: 压缩异常!未成功压缩文件"
        exit 1
    fi
    if [[ ! -f "$testFileOrigin" ]]; then
        echo "Error: 解压异常!未成功解压文件"
        exit 1
    fi
    diffRes=$(diff $testFile $testFileOrigin)
    if [[ -n "$diffRes" ]] ; then
        echo "Error: 解压后数据与原始数据比对不通过！！"
    else
        echo "Success: 测试通过 解压数据校验通过"
    fi
}


is_testing_with_full_compress=0;  # 是否测试压缩打满时的表现
is_testing_with_full_uncompress=0; # 是否测试解压打满时的表现
is_testing_multi_when_inflight16=0;

case "$1" in
  "with_full_compress")
    is_testing_with_full_compress=1
    echo "开启压缩打满测试"
    ;;
  "with_full_uncompress")
    is_testing_with_full_uncompress=1
    echo "开启解压打满测试"
    ;;
  "with_multi")
    is_testing_multi_when_inflight16=1
    echo "开启inflight=16时的多并发测试"
    ;;
  *)
    ;;
esac


check_and_start_backend_process(){
    # 背景压力：压缩或解压"打满"硬件带宽。保持压缩压力和解压压力大致为 7:3
    backfile="$testFilePath/itemdata"
    backfileComped="$backfile.compressed"
    backfileOrigin="$backfile.origin"

    if [[ "$is_testing_with_full_compress" == "1" ]]; then
        backInflightNum=$BackProcessInflight
        backBlockSize=$BackProcessBlockSize

        echo "后台压缩进程启动: 压缩压力:解压压力 =  $backInflightNum : $inum. 后台压力的分片大小 $backBlockSize"  >> $LogFile
        echo "taskset -c 0-79 ./kzip -A $alg -m 1 -p1 -g1 -f $backfile -o $backfileComped -n 60000000 -s $backBlockSize -i $backInflightNum &"  >> $LogFile
        taskset -c 0-79 ./kzip -A $alg -m 1 -p1 -g1 -f $backfile -o $backfileComped -n 60000000 -s $backBlockSize -i $backInflightNum &
        loop1=2
        sleep 1 # 让打满带宽的进程彻底跑起来
    fi
    if [[ "$is_testing_with_full_uncompress" == "1" ]]; then
        backInflightNum=$BackProcessInflight
        backBlockSize=$BackProcessBlockSize
        echo "后台解压进程启动 压缩压力:解压压力 =  $inum : $backInflightNum. 后台压力的分片大小 $backBlockSize"  >> $LogFile
        echo "taskset -c 0-79 ./kzip -d -A $alg -m 1 -p1 -g1 -f $backfileComped -o $backfileOrigin -n 600000 -s $backBlockSize -i $backInflightNum  &"  >> $LogFile
        # 准备解压数据
        taskset -c 0-79 ./kzip -A $alg -m 1 -p1 -g1 -f $backfile -o $backfileComped -n 1 -s $backBlockSize -i $backInflightNum 1>/dev/null
        taskset -c 0-79 ./kzip -d -A $alg -m 1 -p1 -g1 -f $backfileComped -o $backfileOrigin -n 600000 -s $backBlockSize -i $backInflightNum  &
        loop2=2
        sleep 1 # 让打满带宽的进程彻底跑起来
    fi
}
check_and_stop_backend_process(){
    sleep 1
    if [[ "$is_testing_with_full_compress" == "1" || "$is_testing_with_full_uncompress" == "1" ]]; then
        killall -9 kzip # 杀掉可能的后台压力进程
        sleep 3
    fi
}

compute_confortable_looptimes(){
    loop=300 # silesia.tar 压缩循环 300；10并发解压循环3000、inflight1的时候600
    if [[ "$da" == "calgary.tar" ]]; then
        loop=21000 # calgary.tar 循环 22000 次
        if [[ "$inum" == "1" ]]; then
            loop=7200 # 降低单IO测试时间
        fi
    fi

    if [[ "$is_testing_with_full_compress" == "1" || "$is_testing_with_full_uncompress" == "1" ]]; then
        loop=$((loop / 3)) # 背后有满带宽进程，QAT下速率降低，减少测试时间。 KAE压缩解压互不影响
    fi
    loop1=$loop
    loop2=$loop

    if [[ "$is_testing_with_full_compress" == "1" ]]; then
        loop1=2 # 压缩数据不准，尽快结束
    fi
    if [[ "$is_testing_with_full_uncompress" == "1" ]]; then
        loop2=2 # 解压数据不准尽快结束
    fi
}

format_multi_arr(){
    # 追加测试 inflate为16时，多进程并发的表现
    if [[ "$is_testing_multi_when_inflight16" == "1" ]]; then
        Multi=("1")
        if [[ "$inum" == "16" ]]; then
            Multi=("1" "2" "3" "4")
        fi
    fi
}

for kaenum in "${ThreadNum[@]}"; do
    export KAE_LZ4_ASYNC_THREAD_NUM=$kaenum

    for alg in "${Algthm[@]}"; do
        for da in "${Datasets[@]}"; do
            for inum in "${inflateNum[@]}"; do
                format_multi_arr
                for m in "${Multi[@]}"; do
                    for bs in "${BlockSize[@]}"; do
                        loop1=100
                        loop2=100
                        compute_confortable_looptimes

                        echo "Executing: comp-level or kae-threads:$kaenum   $da  $alg  $bs kb chunk. multi:$m, inflateNum: $inum testing"
                        testFile="$testFilePath/$da"
                        testFileComped="$testFile.compressed"
                        testFileOrigin="$testFile.origin"
                        rm -rf $testFileComped
                        rm -rf $testFileOrigin
                        rm -rf $testFileComped.meta
                        rm -rf $testFileOrigin.meta
                        echo "Executing: comp-level or kae-threads:$kaenum   $da  $alg  $bs kb chunk. multi:$m, inflateNum: $inum testing"  >> $LogFile
                        date   >> $LogFile

                        check_and_start_backend_process

                        taskset -c 0-79 ./kzip -A $alg -m $m -p1 -g1 -f $testFile -o $testFileComped -n $loop1 -s $bs -i $inum     >> $LogFile # 压缩测试
                        date     >> $LogFile
                        taskset -c 0-79 ./kzip -d -A $alg -m $m -p1 -g1 -f $testFileComped -o $testFileOrigin -n $loop2 -s $bs -i $inum     >> $LogFile # 压缩测试
                        diffFile $testFile $testFileOrigin     >> $LogFile

                        check_and_stop_backend_process
                    done
                done
            done
        done
    done
done
echo "时延测试结束"