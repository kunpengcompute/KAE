export LD_LIBRARY_PATH=/usr/local/kaelz4/lib/:/usr/local/kaezstd/lib/:/usr/local/kaezip/lib/:$LD_LIBRARY_PATH
export KAE_LZ4_WINTYPE=8
export KAE_LZ4_COMP_TYPE=8
# export KAE_LZ4_ASYNC_THREAD_NUM=12 # default is 12
export KAE_LZ4_ASYNC_DC_THREAD_NUM=10

# 使用 getopts 解析命令行参数
while getopts "m:l:n:w:f:o:v:A:h:g:s:c:i:t:p:k:r:P:" opt; do
  case $opt in
    A)  # 要测试的算法
      Alg="$OPTARG"
      ;;
    m)  # 支持的进程数量
      multiProcess="$OPTARG"
      ;;
    s)  # 文件分片处理. 默认0kb
      fileChunk="$OPTARG"
      ;;
    n)  # 循环压缩次数处理。 默认100次
      loppTimes="$OPTARG"
      ;;
    i)
      inflightNum="$OPTARG"
      ;;
    t)
      threadsNum="$OPTARG"
      ;;
    f)
      testFile="$OPTARG"
      ;;
    k)
      useKAENum="$OPTARG"
      ;;
    r)
      isTestCrc="$OPTARG"
      ;;
    p)
      isTestPolling="$OPTARG"
      ;;
    *)
      echo "Usage: all params  m:l:n:w:f:o:v:A:h:s:c:"
      exit 1
      ;;
  esac
done

Alg=${Alg:=kaezip}
multiProcess=${multiProcess:=2}
fileChunk=${fileChunk:=0}
loppTimes=${loppTimes:=1}
inflightNum=${inflightNum:=64}
threadsNum=${threadsNum:=1}
testFile=${testFile:="../../../scripts/compressTestDataset/calgary"}
useKAENum=${useKAENum:=2}
isTestCrc=${isTestCrc:=0}
isTestPolling=${isTestPolling:=0}

buildParams="kaelz4"
sh build.sh $buildParams

numa_nodes=$(lscpu | grep -i "numa node(s)" | awk '{print $NF}')
threads_per_core=$(lscpu | grep -i "Thread(s) per core" | awk '{print $NF}')
cpu_range=$(lscpu | grep -i "NUMA node0 CPU(s)" | awk '{print $NF}')
cpu_count_per_numa=40
if [[ $cpu_range =~ ([0-9]+)-([0-9]+) ]]; then
    start_cpu=${BASH_REMATCH[1]}
    end_cpu=${BASH_REMATCH[2]}
    cpu_count_per_numa=$((end_cpu - start_cpu + 1))
fi
cpu1_range=$(lscpu | grep -i "NUMA node1 CPU(s)" | awk '{print $NF}')
if [[ $cpu1_range =~ ([0-9]+)-([0-9]+) ]]; then
    cpu1_start_cpu=${BASH_REMATCH[1]}
    cpu1_end_cpu=${BASH_REMATCH[2]}
fi
useEngineNumsForThisTest=$useKAENum # 本次测试使用的加速器的数量
# 本次测试使用的CPU配置。  机器中numa总量-单个numa的cpu核心数量-超线程的单核线程倍数-本次测试使用的加速器数量
cpuConfigStr="$numa_nodes-$cpu_count_per_numa-$threads_per_core-$useEngineNumsForThisTest"
# 获取使用前两个Numa的话，CPU的绑核范围
bindCpu0AndCpu1="$start_cpu-$cpu1_end_cpu"
if [[ $useEngineNumsForThisTest == 1 ]]; then
  bindCpu0AndCpu1="$start_cpu-$end_cpu"
fi


testFileComped="$testFile.compressed"
testFileOrigin="$testFile.origin"
rm -rf $testFileComped
rm -rf $testFileOrigin
rm -rf $testFileComped.meta
rm -rf $testFileOrigin.meta

echo "taskset -c $bindCpu0AndCpu1 ./kzip -A $Alg -m $multiProcess -f $testFile -o $testFileComped -c $cpuConfigStr -n $loppTimes -s $fileChunk -i $inflightNum -t $threadsNum -r $isTestCrc -p $isTestPolling"
echo "taskset -c $bindCpu0AndCpu1 ./kzip -d -A $Alg -m $multiProcess -f $testFileComped -o $testFileOrigin -c $cpuConfigStr -n $loppTimes -s $fileChunk -i $inflightNum -t $threadsNum -r $isTestCrc"

date
# gdb --args
taskset -c $bindCpu0AndCpu1 ./kzip -A $Alg -m $multiProcess -f $testFile -o $testFileComped -c $cpuConfigStr -n $loppTimes -s $fileChunk -i $inflightNum -t $threadsNum -r $isTestCrc -p $isTestPolling
date

# sleep 1
taskset -c $bindCpu0AndCpu1 ./kzip -d -A $Alg -m $multiProcess -f $testFileComped -o $testFileOrigin -c $cpuConfigStr -n $loppTimes -s $fileChunk -i $inflightNum -t $threadsNum -r $isTestCrc
date
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
    echo "Success: 解压数据校验通过"
fi
