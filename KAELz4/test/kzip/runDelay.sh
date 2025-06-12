export LD_LIBRARY_PATH=/usr/local/kaelz4/lib/:/usr/local/kaezstd/lib/:/usr/local/kaezip/lib/:$LD_LIBRARY_PATH
export KAE_LZ4_WINTYPE=8
export KAE_LZ4_COMP_TYPE=8
export KAE_LZ4_ASYNC_THREAD_NUM=12
export KAE_LZ4_ASYNC_DC_THREAD_NUM=10
export PRINT_TABLE_DATA=1

sh build.sh kaelz4

ThreadNum=("12" "8" "7" "6" "5" "4" "3" "2" "1")
Algthm=("kaelz4async_block" "kaelz4async_frame")
Datasets=("calgary.tar" "silesia.tar")
inflateNum=("1" "8" "16" "64" "128")
BlockSize=("4" "8" "16" "64")

current_time=$(date +"%Y-%m-%d_%H-%M-%S")
LogFile=kaelz4-delay.log.$current_time
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

for kaenum in "${ThreadNum[@]}"; do
    export KAE_LZ4_ASYNC_THREAD_NUM=$kaenum
    for alg in "${Algthm[@]}"; do
        for da in "${Datasets[@]}"; do
            for inum in "${inflateNum[@]}"; do
                for bs in "${BlockSize[@]}"; do
                    loop=300 # silesia.tar 压缩循环 300；10并发解压循环3000、inflight1的时候600
                    if [[ "$da" == "calgary.tar" ]]; then
                        loop=22000 # calgary.tar 循环 22000 次  
                    fi

                    echo "Executing: kae-threads:$kaenum   $da  $alg  $bs kb chunk. inflateNum: $inum testing"
                    testFile="$testFilePath/$da"
                    testFileComped="$testFile.compressed"
                    testFileOrigin="$testFile.origin"
                    rm -rf $testFileComped
                    rm -rf $testFileOrigin
                    rm -rf $testFileComped.meta
                    rm -rf $testFileOrigin.meta
                    echo "Executing: kae-threads:$kaenum   $da  $alg  $bs kb chunk. inflateNum: $inum testing" >> $LogFile
                    date   >> $LogFile
                    taskset -c 0-79 ./kzip -A $alg -m 1 -f $testFile -o $testFileComped -n $loop -s $bs -i $inum    >> $LogFile # 压缩测试
                    date   >> $LogFile
                    taskset -c 0-79 ./kzip -d -A $alg -m 1 -f $testFileComped -o $testFileOrigin -n $loop -s $bs -i $inum    >> $LogFile # 压缩测试
                    diffFile $testFile $testFileOrigin   >> $LogFile
                done
            done
        done
    done
done
echo "时延测试结束"