export LD_LIBRARY_PATH=/usr/local/kaelz4/lib/:/usr/local/kaezstd/lib/:/usr/local/kaezip/lib/:$LD_LIBRARY_PATH
export KAE_LZ4_WINTYPE=8
export KAE_LZ4_COMP_TYPE=8

buildParams="kae"
Algthm=()
if [[ -d "/usr/local/kaelz4" ]]; then
    Algthm+=("kaelz4" "kaelz4_frame" "kaelz4async_block" "kaelz4async_frame" "kaelz4async_lz77" "kaelz4async_lz77_frame")
fi
if [[ -d "/usr/local/kaezip" ]]; then
    Algthm+=("kaezlib_deflate" "kaezlibasync_deflate")
fi

sh build.sh $buildParams

Datasets=("calgary" "itemdata" "dickens" "mozilla" "mr" "nci" "ooffice" "osdb" "reymont" "samba" "sao" "webster" "xml" "x-ray")
Datasets=("calgary" "itemdata" "ooffice" "osdb"  "samba" "webster" "xml" "x-ray")
BlockSize=("4" "8" "16" "64" "128" "2090"  "8192" "10244" "0")
Polling=("1" "0")


current_time=$(date +"%Y-%m-%d_%H-%M-%S")
LogFile=kaelz4-function.log.$current_time
testFilePath=../../../scripts/compressTestDataset
passCnt=0
failCnt=0

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
        failCnt=`expr $failCnt + 1`
    else
        echo "Success: 测试通过 解压数据校验通过"
        passCnt=`expr $passCnt + 1`
    fi
}

for da in "${Datasets[@]}"; do
    for alg in "${Algthm[@]}"; do
        for bs in "${BlockSize[@]}"; do
            for polling in "${Polling[@]}"; do
                echo "Executing:  $da  $alg  $bs kb chunk polling mode: $polling testing"
                testFile="$testFilePath/$da"
                testFileComped="$testFile.compressed"
                testFileOrigin="$testFile.origin"
                rm -rf $testFileComped
                rm -rf $testFileOrigin
                rm -rf $testFileComped.meta
                rm -rf $testFileOrigin.meta
                ./kzip -A $alg -m 1 -f $testFile -o $testFileComped -n 2 -s $bs -i 256 -p $polling  >> $LogFile # 压缩测试
                ./kzip -d -A $alg -m 1 -f $testFileComped -o $testFileOrigin -n 2 -s $bs -i 256 -p $polling  >> $LogFile # 压缩测试
                diffFile $testFile $testFileOrigin
            done
        done
        sleep 1
    done
done

echo "test pass: $passCnt, failed: $failCnt."
echo "功能测试结束"