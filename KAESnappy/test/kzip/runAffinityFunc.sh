export LD_LIBRARY_PATH=/usr/local/kaelz4/lib/:/usr/local/kaezstd/lib/:/usr/local/kaezip/lib/:$LD_LIBRARY_PATH
export KAE_LZ4_WINTYPE=8
export KAE_LZ4_COMP_TYPE=8
export KAE_LZ4_ASYNC_THREAD_NUM=6

echo "亲和性测试开始"
sh build.sh kaelz4

Algthm=("kaelz4async_block" "kaelz4async_frame")
Datasets=("calgary" "itemdata" "ooffice" "osdb"  "samba" "webster" "xml" "x-ray")
BlockSize=("4" "8" "60""128" "512" "1024")
Cpu_core_ranges=("0-20" "40-79" "0-79" "120-159")

current_time=$(date +"%Y-%m-%d_%H-%M-%S")
LogFile=kaelz4-function.log.$current_time
testFilePath=../../../scripts/compressTestDataset


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
            for cpu_cores in "${Cpu_core_ranges[@]}"; do
                echo "Binding CPU : $cpu_cores  Testing"
                taskset -c "$cpu_cores" ./kzip -A $alg -m 1 -f $testFile -n 30000 -s $bs -i 16 >> $LogFile & # 压缩测试
                disown # 丢弃后台进程在被kill时的bash报错
                sleep 0.5
                pid=$!
                numa0=0 # 自适应亲和性测试记录KAE线程所处的numa
                numa1=0
                for thread in $(ls /proc/$pid/task); do
                    thread_id=$(basename $thread)
                    current_core=$(cat "/proc/$pid/task/$thread_id/stat" | awk '{print $39}')

                    start_core=$(echo "$cpu_cores" | cut -d'-' -f1)
                    end_core=$(echo "$cpu_cores" | cut -d'-' -f2)
                    if [[ "$current_core" -ge "$start_core" && "$core" -le "$end_core" ]]; then
                        echo "$thread running in $current_core, pass"
                    else
                        echo "Error: $thread set in $cpu_cores ,runing in $current_core"
                        echo "$alg, Dataset : $da, BlockSize : $bs"
                        exit 1
                    fi
                    # 自适应亲和性测试。计算0-79绑核时，KAE线程落在2个numa上的数量
                    if [[ "$cpu_cores" == "0-79" ]]; then
                        # 主进程不参与计算
                        if [[ "$thread" -ne "$pid" && $current_core -ge 0 && $current_core -le 39 ]]; then
                            ((numa0++))
                        elif [[ "$thread" -ne "$pid" && $current_core -ge 40 && $current_core -le 79 ]]; then
                            ((numa1++))
                        fi
                    fi
                done
                if [[  "$cpu_cores" == "0-79"  ]]; then
                    echo "SUCCESS: all threads running in $cpu_cores."
                    if [[ "$numa0" -eq "$numa1" ]]; then
                        echo "SUCCESS: KAE threads average test: $numa0 in numa0, $numa1 in numa1."
                    else
                        echo "Warning: KAE threads: $numa0 in numa0, $numa1 in numa1."
                    fi
                else
                    echo "SUCCESS: all threads running in $cpu_cores"
                fi
                kill -9 $pid
            done
        done
    done
done

echo "亲和性测试结束"