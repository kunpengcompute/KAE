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

const int g_windowBitsArr[] = {-8, 15, 31};
const string g_testfiles_name[] = {"itemdata", "ooffice", "osdb", "samba", "webster", "xml", "x-ray"};

// 随机生成指定长度的数据
static void generate_random_data(Bytef* data, unsigned long long length) {
    srand((unsigned int)time(NULL));
    for (unsigned long long i = 0; i < length; ++i) {
        data[i] = rand() % 256;
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
        return 0;
    }
    (void)fread(input, 1, input_size, sourceFile);
    fclose(sourceFile);

    return input_size;
}

//  通用压缩接口
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
#ifdef Z_DEBUG
    fprintf(stdout, "compress : in_size is %lu, outsize_bound is %lu, real_output_size is %lu\n", input_size,
        output_size, stream.total_out);
#endif
    output_size = stream.total_out;
}

//  通用压缩接口
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
#ifdef Z_DEBUG
    fprintf(stdout, "uncomoress : in_size is %lu, outsize_bound is %lu, read_output_size is %lu\n\n", input_size,
        output_size, stream.total_out);
#endif
    output_size = stream.total_out;
}

static void common_test(int windowBits, int level, bool is_pref = false, ofstream* ostrm = nullptr)
{
    Bytef* input;
    Bytef* compress_data;
    Bytef* uncompress_data;
    struct timeval start, end;
    for (auto fileName : g_testfiles_name) {
        if (ostrm) {
            (*ostrm) << fileName << "," << windowBits << "," << level << ",";
        }
        input = compress_data = uncompress_data = nullptr;
        uLong input_size = read_inputFile(input, fileName.c_str());
        ASSERT_NE(input_size, 0);

        uLong compress_size = compressBound(input_size);
        compress_data = new Bytef[compress_size];
        ASSERT_NE(compress_data, nullptr);

        gettimeofday(&start, NULL);
        common_compress(windowBits, level, input, input_size, compress_data, compress_size);
        gettimeofday(&end, NULL);
        if (is_pref) {
            uLong time_comp = (end.tv_sec - start.tv_sec) * 1e6 + (end.tv_usec - start.tv_usec);
            double rate_comp = 1.0 * compress_size / input_size * 100.0;
            double speed_comp = (input_size * 1.0 / 1e9) / (1.0 * time_comp / 1e6);
            if (ostrm) {
                (*ostrm) << input_size << "," << compress_size << "," << rate_comp << "%%," << time_comp << "," << speed_comp << ",";
            }
        }

        uLong uncompress_size = compressBound(input_size);
        uncompress_data = new Bytef[uncompress_size];
        ASSERT_NE(uncompress_data, nullptr);
        gettimeofday(&start, NULL);
        common_uncompress(windowBits, compress_data, compress_size, uncompress_data, uncompress_size);
        gettimeofday(&end, NULL);
        if (is_pref) {
            uLong time_uncomp = (end.tv_sec - start.tv_sec) * 1e6 + (end.tv_usec - start.tv_usec);
            double rate_uncomp = 1.0 * uncompress_size / compress_size * 100.0;
            double speed_uncomp = (compress_size * 1.0 / 1e9) / (1.0 * time_uncomp / 1e6);
            (*ostrm) << uncompress_size << "," << rate_uncomp << "%%," << time_uncomp << "," << speed_uncomp << ",";
        }

        bool flag1 = (input_size == uncompress_size);
        bool flag2 = (memcmp(input, uncompress_data, input_size) == 0);
        ASSERT_EQ(flag1, true);
        ASSERT_EQ(flag2, true);
        if (is_pref && ostrm) {
            (*ostrm) << ((flag1 && flag2) ? "TRUE" : "FALSE") << endl;
        }

        delete[] input;
        delete[] compress_data;
        delete[] uncompress_data;
    }
}

// data_size less than 64K case(deflate, zlib, gzip)
TEST(ZlibTest, CompressAndDecompress_SmallCase)
{
    uLong input_size = 1024UL * 48; // 48k
    Bytef *input = new Bytef[input_size];
    ASSERT_NE(input, nullptr);
    generate_random_data(input, input_size);

    Bytef* compress_data = new Bytef[compressBound(input_size)]();
    ASSERT_NE(compress_data, nullptr);

    Bytef* uncompress_data = new Bytef[compressBound(input_size)]();
    ASSERT_NE(uncompress_data, nullptr);
    
    for (int windowBits : g_windowBitsArr) {
#ifndef KP920B
        if (windowBits < 0) {
            continue;
        }
#endif
#ifdef Z_DEBUG
        fprintf(stdout, "windowBits : %d\n", windowBits);
#endif
        uLong compress_size = compressBound(input_size);
        uLong uncompress_size = compressBound(input_size);
        memset(compress_data, 0, compress_size);
        memset(uncompress_data, 0, uncompress_size);   
        common_compress(windowBits, 9, input, input_size, compress_data, compress_size);
        common_uncompress(windowBits, compress_data, compress_size, uncompress_data, uncompress_size);
        ASSERT_EQ(input_size, uncompress_size);
        ASSERT_EQ(memcmp(input, uncompress_data, input_size), 0);
    }
    delete[] input;
    delete[] compress_data;
    delete[] uncompress_data;
}

// data_size large than 1G case(deflate, zlib, gzip)
TEST(ZlibTest, CompressAndDecompress_LargeCase)
{
    uLong input_size = 1024UL * 1024 * 1024 * 3; // 3G
    Bytef *input = new Bytef[input_size];
    ASSERT_NE(input, nullptr);
    generate_random_data(input, input_size);

    Bytef* compress_data = new Bytef[compressBound(input_size)]();     // init all 0
    ASSERT_NE(compress_data, nullptr);

    Bytef* uncompress_data = new Bytef[compressBound(input_size)]();   // init all 0
    ASSERT_NE(uncompress_data, nullptr);
    
    for (int windowBits : g_windowBitsArr) {
#ifndef KP920B
        if (windowBits < 0) {
            continue;
        }
#endif
#ifdef Z_DEBUG
        fprintf(stdout, "windowBits : %d\n", windowBits);
#endif
        uLong compress_size = compressBound(input_size);
        uLong uncompress_size = compressBound(input_size);
        memset(compress_data, 0, compress_size);
        memset(uncompress_data, 0, uncompress_size);    
        common_compress(windowBits, 9, input, input_size, compress_data, compress_size);
        common_uncompress(windowBits, compress_data, compress_size, uncompress_data, uncompress_size);
        ASSERT_EQ(input_size, uncompress_size);
        ASSERT_EQ(memcmp(input, uncompress_data, input_size), 0);
    }
    delete[] input;
    delete[] compress_data;
    delete[] uncompress_data;
}

#ifdef KP920B
TEST(ZlibTest, CompressAndDecompress_Deflate)
{
    common_test(-8, 6);
}
#endif

TEST(ZlibTest, CompressAndDecompress_Zlib)
{
    common_test(15, 6);
}

TEST(ZlibTest, CompressAndDecompress_Gzip)
{
    common_test(31, 6);
}

// 测试zlib格式压缩和解压缩能力
TEST(ZlibTest, CompressAndDecompress_largedata_5G)
{
    const uLongf data_length = 1024UL * 1024 * 1024 * 5; // 5G
    Bytef* data = new Bytef[data_length];
    // generate_random_data(data, data_length);

    // 压缩数据
    const uLongf compressed_data_length = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_data_length];
    int result = compress2((Bytef*)compressed_data, (uLongf*)&compressed_data_length, 
        (const Bytef*)data, data_length, Z_BEST_COMPRESSION);
    EXPECT_EQ(result, Z_OK);

    // 解压缩数据
    const uLongf decompressed_data_length = data_length;
    Bytef* decompressed_data = new Bytef[decompressed_data_length];
    result = uncompress((Bytef*)decompressed_data, (uLongf*)&decompressed_data_length, 
        (const Bytef*)compressed_data, compressed_data_length);
    EXPECT_EQ(result, Z_OK);
    EXPECT_EQ(data_length, decompressed_data_length);
    EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/*  
    这个测试用例会对zlib库(deflate, zlib, gzip)的压缩和解压缩能力进行全面的测试
*/
TEST(ZlibTest, CompressAndDecompress_level)
{
    // Test deflate, zlib, gzip
    for (int windowBits : g_windowBitsArr) {
#ifndef KP920B
        if (windowBits < 0) {
            continue;
        }
#endif        
        for (int level = 0; level <= 15; level++) {
            common_test(windowBits, level);
        }
    }
}

#ifdef PERF
TEST(ZlibTest, CompressAndDecompress_perf)
{
    string outputName = "zlib_perf_result";
    static int numid = 0;
    pid_t pid_child = 0;
    for (int i = 0; i < ; ++i) {
        pid_child = fork();
        numid++;
        outputName.append(1, numid + '0');
        if (pid_child == 0 || pid_child == -1) {
            break;
        }
    }

    if (pid_child == 0) {
        ofstream ostrm;
        ostrm.open(outputName.append(".csv"), ios::out | ios::trunc);
        ostrm << "fileName" << "," << "windowBits" << "," << "level" << "," << "input_size" << "," 
            << "compress_size" << "," << "compress_rate" << "," << "compress_time" << "," << "compress_speed" << ","
            << "uncompress_size" << "," << "uncompress_rate" << "," << "uncompress_time" << "," << "uncompress_speed" << ","
            << "CHECK" << endl;

        int windowBitsRange[][2] = {{-15, -9}, {9, 15}, {25, 31}};
        // Test deflate, zlib, gzip
        for (int* windowBitsArr : windowBitsRange) {
            for (int windowBits = windowBitsArr[0]; windowBits <= windowBitsArr[1]; ++windowBits) {
        #ifndef KP920B
                if (windowBits < 0) {
                    continue;
                }
        #endif        
                for (int level = 1; level <= 9; level++) {
                    common_test(windowBits, level, true, &ostrm);
                }
            }
        }
        ostrm.close();
    } else if (pid_child > 0) {
        int ret = -1;
        while (true) {
            ret = wait(NULL);
            if (ret == -1) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
        }
    }
}
#endif

#ifndef TEST_OPEN
TEST(ZlibTest, VersionCheck)
{
    KAEZlibVersion ver;
    int ret = kaezlib_get_version(&ver);
    EXPECT_EQ(ret, 0);
    EXPECT_STREQ(ver.productName, "Kunpeng Boostkit");
    EXPECT_STREQ(ver.productVersion, "23.0.RC2");
    EXPECT_STREQ(ver.componentName, "KAEZlib");
    EXPECT_STREQ(ver.componentVersion, "2.0.1");
}
#endif

// 主函数
int main(int argc, char **argv)
{
    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}