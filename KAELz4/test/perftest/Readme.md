# 本目录用于KAELz4单P带宽能力测试和基于lzbench工具的性能测试

# 1.单p带宽测试
# step1:执行下列命令
# export LD_LIBRARY_PATH=/usr/local/kaelz4/lib/:$LD_LIBRARY_PATH
# export LD_LIBRARY_PATH=/usr/local/lib/:$LD_LIBRARY_PATH
# step2.在本目录执行make，即可得到kaelz4_perf可执行文件，根据提示输入参数可测试单P下KAELz4带宽上限

# 2.执行脚本lzbench_test.sh，即可获得lzbench可执行文件，根据指定测试命令即可测试KAELz4性能：
# 2.1 开源LZ4基线性能测试：（lzbench-master-raw目录）
# （1）block模式测试命令
# numactl -C 1 ./lzbench -relz4 -b128 -i1 -j -m1024 /数据集目录
# （2）frame模式测试命令
# numactl -C 1 ./lzbench -relz4frame -b128 -i1 -j -m1024 /数据集目录

# 2.1 KAELz4性能测试：（lzbench-master目录）
# （1）block模式测试命令
# numactl -C 1 ./lzbench -relz4 -b128 -i1 -j -m1024 /数据集目录
# （2）frame模式测试命令
# numactl -C 1 ./lzbench -relz4frame -b128 -i1 -j -m1024 /数据集目录

# 注：执行上述性能测试前，请确保kaelz4已安装完成