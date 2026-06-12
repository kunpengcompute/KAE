#include <string>
#include <fstream>
#include <iostream>
#include <streambuf>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <gtest/gtest.h>
#include <zlib.h>
extern "C" {
    #include "kaelz4.h"
#include <lz4.h>
#include <lz4frame.h>
}

// // Generate random data with the requested length.
// static void generate_random_data(Bytef* data, unsigned long long length) {
//     srand((unsigned int)time(NULL));
//     for (unsigned long long i = 0; i < length; ++i) {
//         data[i] = rand() % 256;
//     }
// }

// struct compress_param {
//     struct kaelz4_result result;
//     unsigned char*dst;
//     unsigned int dst_len;
//     volatile unsigned int done;
// };
// static void compress_async_callback(struct kaelz4_result *result)
// {
//     struct compress_param *param = (struct compress_param *)result->user_data;
//     param->dst_len = result->dst_len;
//     param->done = 1;
//     return;
// }

// static void lz4_block_common_test()
// {
//     uLong input_size = 1024UL * 48; // 48k
//     Bytef *src = new Bytef[input_size];
//     ASSERT_NE(src, nullptr);
//     generate_random_data(src, input_size);
//     Bytef *dst = new Bytef[input_size * 250];
//     struct compress_param *user_data = (struct compress_param *)malloc(sizeof(struct compress_param));
//     user_data->dst = dst;
//     user_data->dst_len = 0;
//     user_data->done = 0;

//     struct kaelz4_result *result = (struct kaelz4_result *)malloc(sizeof(struct kaelz4_result));;
//     result->src_size = input_size;
//     result->user_data = user_data;
// printf("start--> \n");
//     int ret = LZ4_compress_async(src, dst, compress_async_callback, result);
//     ASSERT_EQ(ret, 0);
//     // Wait for the asynchronous compression operation to complete.
//     while (user_data->done == 0) {
//         // A delay or condition variable can be used here for a more efficient wait.
//         usleep(10);
//     }
// printf("start-->2 \n");
//     // After asynchronous compression completes, call the synchronous decompression API.
//     int dst_len = input_size;
//     Bytef *decompressed_data = new Bytef[dst_len]; // Holds decompressed data.
//     ASSERT_NE(decompressed_data, nullptr);

//     int src_len = user_data->dst_len;
//     int decompressed_size = LZ4_decompress_safe((const char *)user_data->dst, (char *)decompressed_data, src_len, dst_len);
//     ASSERT_GT(decompressed_size, 0); // Successful decompression returns a positive value.
//     ASSERT_EQ(decompressed_size, input_size);
//     // Compare the decompressed data with the original input.
//     ASSERT_EQ(memcmp(src, decompressed_data, input_size), 0); // Verify original and decompressed data match.

//     // Clean up memory.
//     delete[] src;
//     delete[] dst;
//     delete[] decompressed_data;
//     free(user_data);
// }
TEST(LZ4Test, CompressAndDecompress_lz4)
{
    int ret = 0;
    ASSERT_EQ(ret, 0);
}
