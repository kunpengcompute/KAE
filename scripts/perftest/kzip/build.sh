export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/kaelz4/lib:/usr/local/kaezstd/lib:/usr/local/kaezip/lib:$LD_LIBRARY_PATH
export C_INCLUDE_PATH=/usr/local/include:/usr/local/kaelz4/include:/usr/local/kaezip/include:$C_INCLUDE_PATH

# echo "测试kaezip 和 kaelz4，请使用 sh build.sh kaelz4, 默认kaelz4"
# echo "测试kaezip 和 kaezstd，请使用 sh build.sh kaezstd"

TestEnv=$1
TestEnv=${TestEnv:=kae}
echo "build kzip for $TestEnv..."

# 检测内核页面大小
KERNEL_PAGE_SIZE=$(getconf PAGE_SIZE 2>/dev/null || echo "4096")
if [ "$KERNEL_PAGE_SIZE" = "65536" ]; then
    echo "检测到64KB内核页面大小"
    PAGE_SHIFT=16
    CONFIG_PAGE_SIZE="64K"
else
    echo "检测到4KB内核页面大小（默认）"
    PAGE_SHIFT=12
    CONFIG_PAGE_SIZE="4K"
fi

# 检测可用的大页类型
HUGE_PAGE_SIZE=""
HUGE_PAGE_KB=""
HUGE_PAGE_MASK=""
NODE0_HUGEPAGES_DIR="/sys/devices/system/node/node0/hugepages"

# 优先检测512MB大页（64k内核）
if [ -d "${NODE0_HUGEPAGES_DIR}/hugepages-524288kB" ]; then
    HUGE_PAGE_SIZE="512MB"
    HUGE_PAGE_KB="524288"
    HUGE_PAGE_MASK="MAP_HUGE_512MB"
    echo "检测到512MB大页支持"
# 检测1GB大页（4k内核）
elif [ -d "${NODE0_HUGEPAGES_DIR}/hugepages-1048576kB" ]; then
    HUGE_PAGE_SIZE="1GB"
    HUGE_PAGE_KB="1048576"
    HUGE_PAGE_MASK="MAP_HUGE_1GB"
    echo "检测到1GB大页支持"
else
    # 默认使用1GB大页（向后兼容）
    echo "警告: 未检测到大页目录，使用默认1GB大页配置"
    HUGE_PAGE_SIZE="1GB"
    HUGE_PAGE_KB="1048576"
    HUGE_PAGE_MASK="MAP_HUGE_1GB"
fi

echo "配置: 内核页面=${CONFIG_PAGE_SIZE}, 大页=${HUGE_PAGE_SIZE}"

case "$TestEnv" in
    kae)
        make clean
	    make MODULES="kaelz4 kaezlib" PAGE_SHIFT=$PAGE_SHIFT HUGE_PAGE_SIZE="$HUGE_PAGE_SIZE" HUGE_PAGE_KB="$HUGE_PAGE_KB" HUGE_PAGE_MASK="$HUGE_PAGE_MASK"
        ;;
    *)
        make clean
	    make MODULES=$TestEnv PAGE_SHIFT=$PAGE_SHIFT HUGE_PAGE_SIZE="$HUGE_PAGE_SIZE" HUGE_PAGE_KB="$HUGE_PAGE_KB" HUGE_PAGE_MASK="$HUGE_PAGE_MASK"
        ;;
esac

echo "build kzip done"
