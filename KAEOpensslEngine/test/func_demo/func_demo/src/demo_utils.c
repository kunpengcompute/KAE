/*
 * @Author: l00584920 liuyang645@huawei.com
 * @Date: 2024-07-30 20:49:22
 * @LastEditors: l00584920 liuyang645@huawei.com
 * @LastEditTime: 2024-07-31 14:50:10
 * @FilePath: \KAE_kae2\KAE\KAEOpensslEngine\test\func_demo\src\demo_utils.c
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#include "demo_utils.h"
#include <fcntl.h>

int rand_buffer(unsigned char *buf, unsigned long len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        printf("can't open /dev/urandom\n");
        return -1;
    }
    if (read(fd, buf, len) < 0) {
        printf("[%s][%d] read from /dev/urandom failed\n", __FUNCTION__, __LINE__);
    }
    close(fd);

    return 0;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}