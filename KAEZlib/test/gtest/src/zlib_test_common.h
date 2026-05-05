#ifndef ZLIB_TEST_COMMON_H
#define ZLIB_TEST_COMMON_H

#include <string>
#include <fstream>
#include <iostream>
#include <streambuf>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <gtest/gtest.h>
#include <zlib.h>
#include <cstring>
#include <cmath>
#include <vector>
extern "C" {
    #include "kaezip.h"
}

using namespace testing;
using namespace std;

static const int g_windowBitsArr[] = {-15, 15, 31};
static const string g_testfiles_name[] = {"itemdata", "ooffice", "osdb", "samba", "webster", "xml", "x-ray"};

static void generate_random_data(Bytef* data, unsigned long long length)
{
    srand((unsigned int)time(NULL));
    for (unsigned long long i = 0; i < length; ++i) {
        data[i] = rand() % 256;
    }
}

static void generate_text_data(Bytef* data, unsigned long long length)
{
    const char* sample_text =
        "The quick brown fox jumps over the lazy dog. "
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
        "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
        "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. "
        "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore. ";
    unsigned long long sample_len = strlen(sample_text);
    for (unsigned long long i = 0; i < length; ++i) {
        data[i] = sample_text[i % sample_len];
    }
}

static void generate_repeated_data(Bytef* data, unsigned long long length, Bytef pattern)
{
    memset(data, pattern, length);
}

static void generate_mixed_pattern_data(Bytef* data, unsigned long long length)
{
    unsigned long long pos = 0;
    while (pos < length) {
        Bytef pattern = (Bytef)(pos % 256);
        unsigned long long run_len = 1 + (pos % 128);
        if (pos + run_len > length) run_len = length - pos;
        memset(data + pos, pattern, run_len);
        pos += run_len;
    }
}

static void generate_data_with_ratio(Bytef* data, unsigned long long length,
                                      double target_ratio, unsigned int seed = 42)
{
    if (length == 0) return;

    if (target_ratio <= 0.0) {
        memset(data, 0, length);
        return;
    }
    if (target_ratio >= 1.0) {
        srand(seed);
        for (unsigned long long i = 0; i < length; ++i) {
            data[i] = rand() % 256;
        }
        return;
    }

    const unsigned long long BLOCK_SIZE = 4096;
    unsigned long long num_blocks = (length + BLOCK_SIZE - 1) / BLOCK_SIZE;
    unsigned long long random_block_count = (unsigned long long)(target_ratio * num_blocks + 0.5);
    if (random_block_count < 1) random_block_count = 1;
    if (random_block_count > num_blocks - 1) random_block_count = num_blocks - 1;

    srand(seed);
    for (unsigned long long b = 0; b < num_blocks; ++b) {
        unsigned long long start = b * BLOCK_SIZE;
        unsigned long long end = (start + BLOCK_SIZE > length) ? length : start + BLOCK_SIZE;
        unsigned long long block_len = end - start;

        bool is_random = (b * random_block_count / num_blocks !=
                          (b + 1) * random_block_count / num_blocks);

        if (is_random) {
            for (unsigned long long i = 0; i < block_len; ++i) {
                data[start + i] = rand() % 256;
            }
        } else {
            memset(data + start, 0x00, block_len);
        }
    }
}

static uLong read_inputFile(Bytef* &input, const char* fileName)
{
    FILE* sourceFile = fopen(fileName, "r");
    if (sourceFile == NULL) {
        fprintf(stderr, "%s not exist!\n", fileName);
        return 0;
    }
    int fd = fileno(sourceFile);
    struct stat fs;
    (void)fstat(fd, &fs);

    uLong input_size = fs.st_size;
    input = new Bytef[input_size];
    if (input == nullptr) {
        fclose(sourceFile);
        return 0;
    }
    (void)fread(input, 1, input_size, sourceFile);
    fclose(sourceFile);

    return input_size;
}

static void common_compress(int windowBits, int level, Bytef* input, const uLong input_size,
    Bytef* output, uLong& output_size)
{
    z_stream stream;
    stream.zalloc    = Z_NULL;
    stream.zfree     = Z_NULL;
    stream.opaque    = Z_NULL;
    stream.avail_in  = input_size;
    stream.next_in   = input;
    stream.avail_out = output_size;
    stream.next_out  = output;
    ASSERT_EQ(deflateInit2(&stream, level, Z_DEFLATED, windowBits, 8, Z_DEFAULT_STRATEGY), Z_OK);
    ASSERT_EQ(deflate(&stream, Z_FINISH), Z_STREAM_END);
    ASSERT_EQ(deflateEnd(&stream), Z_OK);
    output_size = stream.total_out;
}

static void common_uncompress(int windowBits, Bytef* input, const uLong input_size,
    Bytef* output, uLong& output_size)
{
    z_stream stream;
    stream.zalloc    = Z_NULL;
    stream.zfree     = Z_NULL;
    stream.opaque    = Z_NULL;
    stream.avail_in  = input_size;
    stream.next_in   = input;
    stream.avail_out = output_size;
    stream.next_out  = output;
    ASSERT_EQ(inflateInit2(&stream, windowBits), Z_OK);
    ASSERT_EQ(inflate(&stream, Z_FINISH), Z_STREAM_END);
    ASSERT_EQ(inflateEnd(&stream), Z_OK);
    output_size = stream.total_out;
}

static int try_compress(int windowBits, int level, Bytef* input, const uLong input_size,
    Bytef* output, uLong& output_size)
{
    z_stream stream;
    stream.zalloc    = Z_NULL;
    stream.zfree     = Z_NULL;
    stream.opaque    = Z_NULL;
    stream.avail_in  = input_size;
    stream.next_in   = input;
    stream.avail_out = output_size;
    stream.next_out  = output;
    int ret = deflateInit2(&stream, level, Z_DEFLATED, windowBits, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) return ret;
    ret = deflate(&stream, Z_FINISH);
    if (ret != Z_STREAM_END) {
        deflateEnd(&stream);
        return ret;
    }
    output_size = stream.total_out;
    return deflateEnd(&stream);
}

static int try_uncompress(int windowBits, Bytef* input, const uLong input_size,
    Bytef* output, uLong& output_size)
{
    z_stream stream;
    stream.zalloc    = Z_NULL;
    stream.zfree     = Z_NULL;
    stream.opaque    = Z_NULL;
    stream.avail_in  = input_size;
    stream.next_in   = input;
    stream.avail_out = output_size;
    stream.next_out  = output;
    int ret = inflateInit2(&stream, windowBits);
    if (ret != Z_OK) return ret;
    ret = inflate(&stream, Z_FINISH);
    if (ret != Z_STREAM_END) {
        inflateEnd(&stream);
        return ret;
    }
    output_size = stream.total_out;
    return inflateEnd(&stream);
}

static double get_time_diff_us(struct timeval& start, struct timeval& end)
{
    return (end.tv_sec - start.tv_sec) * 1e6 + (end.tv_usec - start.tv_usec);
}

#endif
