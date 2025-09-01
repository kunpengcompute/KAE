export LD_LIBRARY_PATH=/usr/local/kaelz4/lib/:/usr/local/kaezstd/lib/:/usr/local/kaezip/lib/:$LD_LIBRARY_PATH
export KAE_LZ4_WINTYPE=8
export KAE_LZ4_COMP_TYPE=8

# 异常以及可靠性测试
# 1、KAE硬件队列资源消耗完时，自动切软算。
# 2、K异步接口在KAE资源不可用时，自动切软算。

uninstall_driver()
{
    rmmod hisi_zip
}
install_driver()
{
    modprobe hisi_zip perf_mode=1 uacce_mode=2 pf_q_num=256
}

set_driver_less_and_runout()
{
    rmmod hisi_zip
    sleep 1
    modprobe hisi_zip  uacce_mode=2 pf_q_num=2
    sleep 1
    taskset -c 300-312 ./kzip -A kaelz4 -m 8 -n 400000000 -s 4 1>/dev/null 2>/dev/null &
}
reset_driver()
{
    rmmod hisi_zip
    modprobe hisi_zip perf_mode=1 uacce_mode=2 pf_q_num=256
}

do_compress_and_decompress_and_diff()
{
    buildParams="kae"
    sh build.sh $buildParams
    Algthm=("kaelz4async_block" "kaelz4async_frame")
    Datasets=("calgary" "itemdata" "ooffice" "osdb"  "samba" "webster" "xml" "x-ray")
    Datasets=("calgary" "itemdata")
    BlockSize=("4" "8" "16" "60" "64")

    current_time=$(date +"%Y-%m-%d_%H-%M-%S")
    LogFile=kaelz4-function.log.$current_time
    testFilePath=../../../scripts/compressTestDataset

    diffFile() {
        local testFile=$1
        local testFileOrigin=$2
        if [[ ! -f "$testFile" ]]; then
            echo "Error: 压缩异常!未成功压缩文件"
        fi
        if [[ ! -f "$testFileOrigin" ]]; then
            echo "Error: 解压异常!未成功解压文件"
        fi
        diffRes=$(diff $testFile $testFileOrigin)
        if [[ -n "$diffRes" ]] ; then
            echo "Error: 解压后数据与原始数据比对不通过！！"
        else
            echo "Success: 测试通过 解压数据校验通过"
        fi
    }

    for da in "${Datasets[@]}"; do
        for alg in "${Algthm[@]}"; do
            for bs in "${BlockSize[@]}"; do
                echo "Executing:  $da  $alg  $bs kb testing"
                testFile="$testFilePath/$da"
                testFileComped="$testFile.compressed"
                testFileOrigin="$testFile.origin"
                rm -rf $testFileComped
                rm -rf $testFileOrigin
                rm -rf $testFileComped.meta
                rm -rf $testFileOrigin.meta
                ./kzip -A $alg -m 2 -f $testFile -o $testFileComped -n 2 -s $bs -i 256  >> $LogFile # 压缩测试
                ./kzip -d -A $alg -m 1 -f $testFileComped -o $testFileOrigin -n 2 -s $bs -i 256  >> $LogFile # 压缩测试
                diffFile $testFile $testFileOrigin
            done
        done
    done
}

test_func_ok_when_run_out_of_KAE()
{
    echo "start testing async lz4 compress when hardware queue is run out>>>>>>>>>>>>>>>"
    set_driver_less_and_runout
    sleep 2
    echo "hardware queue left 0. start tesing  when data is less than 64k>>>>>>>>>>>>>>>"
    do_compress_and_decompress_and_diff 2>/dev/null
    echo "all testing done>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
    sleep 2
    killall kzip
    reset_driver
    echo "env is reset."
}
test_func_ok_when_unavaliable_of_KAE() {
    echo "start testing async lz4 compress when hardware queue is unavaliable>>>>>>>>>>>>>"
    uninstall_driver
    echo "hardware queue no exists. start tesing  when data is less than 64k>>>>>>>>>>>>>>>"
    do_compress_and_decompress_and_diff 2>/dev/null
    echo "all testing done>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
    install_driver
    echo "env is reset."
}

main()
{
    test_func_ok_when_run_out_of_KAE

    sleep 5

    test_func_ok_when_unavaliable_of_KAE
}

main
