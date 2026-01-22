#!/bin/bash
#
# 脚本名称: runLogfunc.sh
# 描述: 日志功能测试脚本

export LD_LIBRARY_PATH=/usr/local/kaelz4/lib/:/usr/local/kaezstd/lib/:/usr/local/kaezip/lib/:$LD_LIBRARY_PATH
export KAE_LZ4_WINTYPE=8
export KAE_LZ4_COMP_TYPE=8
export KAELZ4_CONF_ENV=/var/log/
export KAEZIP_CONF_ENV=/var/log/

buildParams="kae"
sh build.sh $buildParams

KAELz4_Algthm=("kaelz4async_block" "kaelz4async_frame")
KAEZlib_Algthm=("kaezlibasync_deflate")
Datasets=("calgary" "itemdata")
BlockSize=("4" "16" "64" "128" "512" "1024")

current_time=$(date +"%Y-%m-%d_%H-%M-%S")
LogFile=kae-logfunction.log.$current_time
testFilePath=../../../scripts/compressTestDataset
search_content="do polling" # debug等级日志信息里，异步压缩回收硬件压缩结果标志
KAELZ4_FILE_PATH="/var/log/kaelz4.log" # 日志文件路径
KAEZIP_FILE_PATH="/var/log/kaezip.log" # 日志文件路径

echo "KAELz4日志测试开始"
rm -f /var/log/kaelz4.cnf
cp ./kaelz4.cnf /var/log/
for da in "${Datasets[@]}"; do
    for alg in "${KAELz4_Algthm[@]}"; do
        for bs in "${BlockSize[@]}"; do
            echo "Executing:  $da  $alg  $bs testing"
            testFile="$testFilePath/$da"
            testFileComped="$testFile.compressed"
            testFileOrigin="$testFile.origin"
            rm -rf $testFileComped
            rm -rf $testFileOrigin
            rm -rf $testFileComped.meta
            rm -rf $testFileOrigin.meta
            echo " " > $KAELZ4_FILE_PATH

            ./kzip -A $alg -m 1 -f $testFile -o $testFileComped -n 2 -s $bs -i 256  >> $LogFile # 压缩测试

            if [ ! -f "$KAELZ4_FILE_PATH" ]; then
                echo "压缩日志文件 $KAELZ4_FILE_PATH 不存在！"
                exit 1
            fi

            if grep -q "$search_content" "$KAELZ4_FILE_PATH"; then
                sleep 0.1
            else
                echo "日志文件中不包含指定内容：$search_content"
                exit 1
            fi
            wait
        done
    done
done
rm -f /var/log/kaelz4.cnf
echo "KAELz4日志功能正常"


echo "KAEZlib日志测试开始"
rm -f /var/log/kaezip.cnf
cp ./kaelz4.cnf /var/log/kaezip.cnf
for da in "${Datasets[@]}"; do
    for alg in "${KAEZlib_Algthm[@]}"; do
        for bs in "${BlockSize[@]}"; do
            echo "Executing:  $da  $alg  $bs testing"
            testFile="$testFilePath/$da"
            testFileComped="$testFile.compressed"
            testFileOrigin="$testFile.origin"
            rm -rf $testFileComped
            rm -rf $testFileOrigin
            rm -rf $testFileComped.meta
            rm -rf $testFileOrigin.meta
            echo " " > $KAEZIP_FILE_PATH

            ./kzip -A $alg -m 1 -f $testFile -o $testFileComped -n 2 -s $bs -i 256  >> $LogFile # 压缩测试

            if [ ! -f "$KAEZIP_FILE_PATH" ]; then
                echo "压缩日志文件 $KAEZIP_FILE_PATH 不存在！"
                exit 1
            fi

            if grep -q "$search_content" "$KAEZIP_FILE_PATH"; then
                sleep 0.1
            else
                echo "日志文件中不包含指定内容：$search_content"
                exit 1
            fi
            wait
        done
    done
done
rm -f /var/log/kaezip.cnf
echo "KAEZlib日志功能正常"
