export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/kaelz4/lib:/usr/local/kaezstd/lib:/usr/local/kaezip/lib:$LD_LIBRARY_PATH
export C_INCLUDE_PATH=/usr/local/include:/usr/local/kaelz4/include:/usr/local/kaezip/include:$C_INCLUDE_PATH

# echo "测试kaezip 和 kaelz4，请使用 sh build.sh kaelz4, 默认kaelz4"
# echo "测试kaezip 和 kaezstd，请使用 sh build.sh kaezstd"

TestEnv=$1
TestEnv=${TestEnv:=kae}
echo "build kzip for $TestEnv..."
case "$TestEnv" in
    kae)
    make clean
	make MODULES="kaelz4 kaezlib"
    ;;
    *)
    make clean
	make MODULES=$TestEnv
    ;;
esac

echo "build kzip done"
