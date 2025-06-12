# KAELz4功能测试通过复用开源lz4测试功能实现
# 具体通过执行kaelz4安装，而后至KAELz4/open_source/lz4-1.9.4/tests目录，并执行make
# 1.blcok模式的功能测试：通过执行生成的可执行文件fuzzer，以及脚本test_custom_blocksizes.sh实现
# 2.frame模式的功能测试：通过执行生成的可执行文件frametest，以及脚本test-lz4-list.py实现

# 注：执行上述功能测试前，请确保kaelz4已安装完成

# unit test

~~~
sh run.sh
~~~