export LD_LIBRARY_PATH=/usr/local/kaelz4/lib:/usr/local/kaezstd/lib:/usr/local/kaezip/lib:$LD_LIBRARY_PATH
export C_INCLUDE_PATH=/usr/local/kaelz4/include:/usr/local/kaezip/include:$C_INCLUDE_PATH

# echo "测试kaezip 和 kaelz4，请使用 sh build.sh kaelz4, 默认kaelz4"
# echo "测试kaezip 和 kaezstd，请使用 sh build.sh kaezstd"
# echo "测试qat，请使用 sh build.sh qat"

TestEnv=$1
TestEnv=${TestEnv:=kaelz4}
echo "build kzip for $TestEnv..."
case "$TestEnv" in
    kaelz4)
    gcc -g -o kzip main.c delayRecord.c datagen.c alg/manage.c alg/*/*.c scene_test_functions/*c -lz -lnuma -lrt -L/usr/local/kaelz4/lib -llz4 -lkaelz4 -L/usr/local/kaezip/lib -lkaezip -DBUILD_ENV=$TestEnv -DBUILD_ENV_KAELZ4=1 -O3 -fstack-protector-all -Wall -Werror -lpthread
    ;;
    *)
    ;;
esac

echo "build kzip done"
