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
    #include "kaezip.h"
}
using namespace testing;
using namespace std;

// 测试压缩和解压缩空数据
TEST(ZlibTest, CompressAndDecompress_empty_data)
{
    const uLongf data_length = 0;
    Bytef* data = nullptr;

    // 压缩数据
    const uLongf compressed_data_length = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_data_length];
    int result = compress2(compressed_data, (uLongf*)&compressed_data_length, 
        data, data_length, Z_BEST_COMPRESSION);
    EXPECT_EQ(result, Z_OK);

    // 解压缩数据
    const uLongf decompressed_data_length = data_length;
    Bytef* decompressed_data = new Bytef[decompressed_data_length];
    result = uncompress(decompressed_data, (uLongf*)&decompressed_data_length, 
        compressed_data, compressed_data_length);
    EXPECT_EQ(result, Z_OK);
    EXPECT_EQ(data_length, decompressed_data_length);

    delete[] compressed_data;
    delete[] decompressed_data;
}

// 测试压缩和解压缩1字节数据
TEST(ZlibTest, CompressAndDecompress_1byte_data)
{
    const uLongf data_length = 1;
    Bytef* data = new Bytef[data_length];
    data[0] = 0x01;

    // 压缩数据
    const uLongf compressed_data_length = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_data_length];
    int result = compress2(compressed_data, (uLongf*)&compressed_data_length, 
        data, data_length, Z_BEST_COMPRESSION);
    EXPECT_EQ(result, Z_OK);

    // 解压缩数据
    const uLongf decompressed_data_length = data_length;
    Bytef* decompressed_data = new Bytef[decompressed_data_length];
    result = uncompress(decompressed_data, (uLongf*)&decompressed_data_length, 
        compressed_data, compressed_data_length);
    EXPECT_EQ(result, Z_OK);
    EXPECT_EQ(data_length, decompressed_data_length);
    EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

// 测试刚好达到压缩边界的数据
TEST(ZlibTest, CompressAndDecompress_bound_data)
{
    const uLongf data_length = 1024UL * 1024 * 1024 * 5; // 5G
    Bytef* data = new Bytef[data_length];
    // generate_random_data(data, data_length);

    // 压缩数据
    const uLongf compressed_data_length = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_data_length];
    int result = compress2(compressed_data, (uLongf*)&compressed_data_length, 
        data, data_length, Z_BEST_COMPRESSION);
    EXPECT_EQ(result, Z_OK);

    // 解压缩数据
    const uLongf decompressed_data_length = data_length;
    Bytef* decompressed_data = new Bytef[decompressed_data_length];
    result = uncompress(decompressed_data, (uLongf*)&decompressed_data_length, 
        compressed_data, compressed_data_length);
    EXPECT_EQ(result, Z_OK);
    EXPECT_EQ(data_length, decompressed_data_length);
    EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

// 测试压缩过程中内存不足的情况
TEST(ZlibTest, Compress_memory_error)
{
    const uLongf data_length = 1024;
    Bytef* data = new Bytef[data_length];
    // generate_random_data(data, data_length);

    // 分配一个过小的压缩缓冲区
    const uLongf compressed_data_length = 1;
    Bytef* compressed_data = new Bytef[compressed_data_length];
    int result = compress2(compressed_data, (uLongf*)&compressed_data_length, 
        data, data_length, Z_BEST_COMPRESSION);
    EXPECT_EQ(result, Z_MEM_ERROR);

    delete[] data;
    delete[] compressed_data;
}

// 测试解压缩过程中数据损坏的情况
TEST(ZlibTest, Decompress_data_error)
{
    const uLongf data_length = 1024;
    Bytef* data = new Bytef[data_length];
    // generate_random_data(data, data_length);

    // 压缩数据
    const uLongf compressed_data_length = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_data_length];
    int result = compress2(compressed_data, (uLongf*)&compressed_data_length, 
        data, data_length, Z_BEST_COMPRESSION);
    EXPECT_EQ(result, Z_OK);

    // 修改压缩数据以模拟损坏
    compressed_data[0] = 0xFF;

    // 解压缩数据
    const uLongf decompressed_data_length = data_length;
    Bytef* decompressed_data = new Bytef[decompressed_data_length];
    result = uncompress(decompressed_data, (uLongf*)&decompressed_data_length, 
        compressed_data, compressed_data_length);
    EXPECT_EQ(result, Z_DATA_ERROR);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

// 测试不同的压缩级别
TEST(ZlibTest, Compress_different_levels)
{
    const uLongf data_length = 1024;
    Bytef* data = new Bytef[data_length];
    // generate_random_data(data, data_length);

    // 测试不同的压缩级别
    int compression_levels[] = {Z_NO_COMPRESSION, Z_BEST_SPEED, Z_DEFAULT_COMPRESSION, Z_BEST_COMPRESSION};
    for (int level : compression_levels) {
        const uLongf compressed_data_length = compressBound(data_length);
        Bytef* compressed_data = new Bytef[compressed_data_length];
        int result = compress2(compressed_data, (uLongf*)&compressed_data_length, 
            data, data_length, level);
        EXPECT_EQ(result, Z_OK);

        // 解压缩数据
        const uLongf decompressed_data_length = data_length;
        Bytef* decompressed_data = new Bytef[decompressed_data_length];
        result = uncompress(decompressed_data, (uLongf*)&decompressed_data_length, 
            compressed_data, compressed_data_length);
        EXPECT_EQ(result, Z_OK);
        EXPECT_EQ(data_length, decompressed_data_length);
        EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

        delete[] compressed_data;
        delete[] decompressed_data;
    }

    delete[] data;
}

// 测试输入数据为nullptr的情况
TEST(ZlibTest, Compress_null_data)
{
    const uLongf data_length = 1024;
    Bytef* data = nullptr;

    // 压缩数据
    const uLongf compressed_data_length = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_data_length];
    int result = compress2(compressed_data, (uLongf*)&compressed_data_length, 
        data, data_length, Z_BEST_COMPRESSION);
    EXPECT_EQ(result, Z_OK);

    // 解压缩数据
    const uLongf decompressed_data_length = data_length;
    Bytef* decompressed_data = new Bytef[decompressed_data_length];
    result = uncompress(decompressed_data, (uLongf*)&decompressed_data_length, 
        compressed_data, compressed_data_length);
    EXPECT_EQ(result, Z_OK);
    EXPECT_EQ(data_length, decompressed_data_length);

    delete[] compressed_data;
    delete[] decompressed_data;
}

// 测试输出缓冲区不足的情况
TEST(ZlibTest, Decompress_small_buffer)
{
    const uLongf data_length = 1024;
    Bytef* data = new Bytef[data_length];
    // generate_random_data(data, data_length);

    // 压缩数据
    const uLongf compressed_data_length = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_data_length];
    int result = compress2(compressed_data, (uLongf*)&compressed_data_length, 
        data, data_length, Z_BEST_COMPRESSION);
    EXPECT_EQ(result, Z_OK);

    // 分配一个过小的解压缩缓冲区
    const uLongf decompressed_data_length = 1;
    Bytef* decompressed_data = new Bytef[decompressed_data_length];
    result = uncompress(decompressed_data, (uLongf*)&decompressed_data_length, 
        compressed_data, compressed_data_length);
    EXPECT_EQ(result, Z_BUF_ERROR);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}