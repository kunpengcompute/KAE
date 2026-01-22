
#include "manage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MAX_ALGORITHMS 10  // 支持最多 10 种算法

static compression_algorithm_t *algorithm_list[MAX_ALGORITHMS];
static int algorithm_count = 0;

// 注册算法
void register_algorithm(compression_algorithm_t *algorithm) {
    if (algorithm_count < MAX_ALGORITHMS) {
        algorithm_list[algorithm_count++] = algorithm;
    } else {
        fprintf(stderr, "Error: Too many compression algorithms registered.\n");
    }
}

// 查找算法
compression_algorithm_t *get_algorithm(const char *name)
{
    for (int i = 0; i < algorithm_count; i++) {
        if (strcmp(algorithm_list[i]->name, name) == 0) {
            return algorithm_list[i];
        }
    }
    return NULL;
}
int vaild_algorithm(const char *name)
{
    for (int i = 0; i < algorithm_count; i++) {
        if (strcmp(algorithm_list[i]->name, name) == 0) {
            return 0;
            break;
        }
    }
    printf("Error: Invalid compression algorithm: %s\n", name);
    return -1;
}

// 初始化所有算法
void initialize_algorithms(void) {
#ifdef CONFIG_KAELZ4
    register_lz4_algorithm();
    register_lz4_frame_algorithm();
    register_lz4async_block_algorithm();
    register_lz4async_frame_algorithm();
    register_lz4async_lz77_algorithm();
    register_lz4async_lz77_frame_algorithm();
#endif

#ifdef CONFIG_KAEZLIB
    register_zlib_algorithm();
    register_zlib_deflate_algorithm();
    register_zlibasync_block_algorithm();
#endif

}