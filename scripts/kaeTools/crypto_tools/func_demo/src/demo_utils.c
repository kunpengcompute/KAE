/*
 * @Date: 2024-07-30 20:49:22
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

void PRINTMSG(unsigned char *msg, int size) {  
    if (msg == NULL || size <= 0) return; // 检查有效性  

    for (int i = 0; i < size; i++) {  
         printf("0x%02X ", msg[i]); // 打印每个字符  
    }  
    putchar('\n'); // 打印换行符  
} 

void generateRandomASCII(char* msg, int size) {  
    if (size <= 0 || msg == NULL) return; // 检查有效性  

    // 设置随机数种子  
    srand((unsigned int)time(NULL));  

    for (int i = 0; i < size; i++) {  
        // 生成随机字符：范围为可打印的ASCII字符（32到126）  
        msg[i] = (char)(rand() % (126 - 32 + 1) + 32);  
    }  
    msg[size] = '\0'; // 添加字符串结束符  
}  