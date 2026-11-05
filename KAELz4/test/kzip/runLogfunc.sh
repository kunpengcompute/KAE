# Copyright (c) 2026 Huawei Technologies Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

export LD_LIBRARY_PATH=/usr/local/kaelz4/lib/:/usr/local/kaezstd/lib/:/usr/local/kaezip/lib/:$LD_LIBRARY_PATH
export KAE_LZ4_WINTYPE=8
export KAE_LZ4_COMP_TYPE=8
export KAELZ4_CONF_ENV=/var/log/

sh build.sh kaelz4

Algthm=("kaelz4async_block" "kaelz4async_frame")
Datasets=("calgary" "itemdata" "dickens" "mozilla" "mr" "nci" "osdb" "reymont" "samba" "sao" "webster" "xml" "x-ray")
Datasets=("calgary" "itemdata" "osdb"  "samba" "webster" "xml" "x-ray")
BlockSize=("4" "8" "16" "60" "64" "68" "128" "512" "1024" "2090" "10244")

current_time=$(date +"%Y-%m-%d_%H-%M-%S")
LogFile=kaelz4-logfunction.log.$current_time
testFilePath=../../../scripts/compressTestDataset
search_content="do polling" # debug等级日志信息里，异步压缩回收硬件压缩结果标志
FILE_PATH="/var/log/kaelz4.log" # 日志文件路径

echo "日志测试开始"

rm -f /var/log/kaelz4.cnf 
cp ./kaelz4.cnf /var/log/

for da in "${Datasets[@]}"; do
    for alg in "${Algthm[@]}"; do
        for bs in "${BlockSize[@]}"; do
            echo "Executing:  $da  $alg  $bs testing"
            testFile="$testFilePath/$da"
            testFileComped="$testFile.compressed"
            testFileOrigin="$testFile.origin"
            rm -rf $testFileComped
            rm -rf $testFileOrigin
            rm -rf $testFileComped.meta
            rm -rf $testFileOrigin.meta
            echo " " > $FILE_PATH

            ./kzip -A $alg -m 1 -f $testFile -o $testFileComped -n 2 -s $bs -i 256  >> $LogFile # 压缩测试

            if [ ! -f "$FILE_PATH" ]; then
                echo "压缩日志文件 $FILE_PATH 不存在！"
                exit 1
            fi

            if grep -q "$search_content" "$FILE_PATH"; then
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
echo "日志功能正常，日志测试结束"
