function main()
###
 # @Author: l00584920 liuyang645@huawei.com
 # @Date: 2024-07-30 17:12:00
 # @LastEditors: l00584920 liuyang645@huawei.com
 # @LastEditTime: 2024-07-30 17:25:20
 # @FilePath: \KAE_kae2\KAE\KAEOpensslEngine\test\func_demo\src\build.sh
 # @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
### 
{
    if [ "$1" == "clean" ]; then
        make clean
    else
        make clean
        make KAE_DEMO_CIPHER=y 
    fi

    return 1
}

main "$@"
exit $?
