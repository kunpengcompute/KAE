#include <gtest/gtest.h>
#include <zlib.h>
#include <string>
#include <fstream>
extern "C" {
    #include "kaezip.h"
}
using namespace testing;

void PRINT_BUF(char* buf, int size) {
    printf("\nbegin=======\n"); 
    for(int i = 0; i < size; i++) {
        printf("%d", buf[i]);
    }
    printf("\nend=======\n");
}

// 随机生成指定长度的数据
void generate_random_data(char* data, long long length) {
    srand((unsigned int)time(NULL));
    for (long long i = 0; i < length; i++) {
        data[i] = rand() % 256;
    }
}

// zlib_case1
TEST(ZlibTest, CompressAndDecompress_case1) {
    const char* input = "Hello, world!";
    const size_t input_size = strlen(input) + 1;
    const size_t buffer_size = compressBound(input_size);
    char* buffer = new char[buffer_size];

    // Compress
    int result = compress2((Bytef*)buffer, (uLongf*)&buffer_size, (const Bytef*)input, input_size, Z_BEST_COMPRESSION);
    ASSERT_EQ(result, Z_OK);

    // Decompress
    char* output = new char[input_size];
    uLongf output_size = input_size;
    result = uncompress((Bytef*)output, &output_size, (const Bytef*)buffer, buffer_size);
    ASSERT_EQ(result, Z_OK);

    // Verify
    ASSERT_STREQ(input, output);

    delete[] buffer;
    delete[] output;
}

// zlib_case2
TEST(ZlibTest, CompressAndDecompress_case2) {
    // 原始数据
    const char* data = "Hello, world!";
    const size_t data_len = strlen(data);

    // 压缩数据
    const size_t compressed_buf_size = compressBound(data_len);
    char* compressed_buf = new char[compressed_buf_size];
    uLongf compressed_len = compressed_buf_size;
    int compress_ret = compress2((Bytef*)compressed_buf, &compressed_len, (const Bytef*)data, data_len, Z_BEST_COMPRESSION);
    ASSERT_EQ(compress_ret, Z_OK);

    // 解压数据
    const size_t decompressed_buf_size = data_len;
    char* decompressed_buf = new char[decompressed_buf_size];
    uLongf decompressed_len = decompressed_buf_size;
    int decompress_ret = uncompress((Bytef*)decompressed_buf, &decompressed_len, (const Bytef*)compressed_buf, compressed_len);
    ASSERT_EQ(decompress_ret, Z_OK);

    // 检查解压后的数据是否与原始数据相同
    ASSERT_EQ(decompressed_len, data_len);
    ASSERT_EQ(memcmp(decompressed_buf, data, data_len), 0);

    delete[] compressed_buf;
    delete[] decompressed_buf;
}

TEST(ZlibTest, CompressAndDecompress_Deflate) {
    const char* input = "Hello, world!";
    const int input_size = strlen(input);

    // Allocate output buffer
    const int output_size = compressBound(input_size);
    char* output = new char[output_size];

    // Compress input
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = input_size;
    stream.next_in = (Bytef*)input;
    stream.avail_out = output_size;
    stream.next_out = (Bytef*)output;
    deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -8, 8, Z_DEFAULT_STRATEGY);
    deflate(&stream, Z_FINISH);
    deflateEnd(&stream);

    // Verify output
    EXPECT_GT(stream.total_out, 0);
    EXPECT_LT(stream.total_out, output_size);

    // Clean up
    delete[] output;
}

// 大数据解压缩
TEST(ZlibTest, CompressAndDecompressLargeData) {
    const int input_size = 1024 * 1024 *100; // 1MB
    const int buffer_size = compressBound(input_size);
    char* input = new char[input_size]; //原始数据buf
    char* buffer = new char[buffer_size];
    char* inflat_buf = new char[input_size]; //解压后数据buf

    // generate random data
    for (int i = 0; i < input_size; i++) {
        input[i] = rand() % 256;
    }

    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = input_size; // 待解压
    stream.next_in = (Bytef*)input; // 待解压
    stream.avail_out = buffer_size; // 压缩后
    stream.next_out = (Bytef*)buffer; // 压缩后
    ASSERT_EQ(deflateInit(&stream, Z_DEFAULT_COMPRESSION), Z_OK); // zlib压缩方法
    ASSERT_EQ(deflate(&stream, Z_FINISH), Z_STREAM_END);
    ASSERT_EQ(deflateEnd(&stream), Z_OK);
    const int compressed_size = stream.total_out;

    // decompress
    z_stream stream2;
    stream2.zalloc = Z_NULL;
    stream2.zfree = Z_NULL;
    stream2.opaque = Z_NULL;
    stream2.avail_in = compressed_size; // 压缩数据
    stream2.next_in = (Bytef*)buffer; // 压缩数据
    stream2.avail_out = input_size; // 解压后数据
    stream2.next_out = (Bytef*)inflat_buf; // 解压后数据
    ASSERT_EQ(inflateInit(&stream2), Z_OK);
    ASSERT_EQ(inflate(&stream2, Z_FINISH), Z_STREAM_END);
    ASSERT_EQ(inflateEnd(&stream2), Z_OK);

    // check result
    for (int i = 0; i < input_size; i++) {
        ASSERT_EQ(input[i], inflat_buf[i]);
    }

    delete[] input;
    delete[] buffer;
}

// 通用解压缩用例
TEST(ZlibTest, CompressAndDecompress_common) {
    const int windowBitsArr[] = {-8, 15, 31};   // deflate, zlib, gzip
    for (auto windowBit : windowBitsArr) {
        std::string input = "Hello, world!";
        std::string compressed;
        std::string decompressed;

        // 压缩数据
        z_stream stream;
        stream.zalloc = Z_NULL;
        stream.zfree = Z_NULL;
        stream.opaque = Z_NULL;
        deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, windowBit, 8, Z_DEFAULT_STRATEGY);
        stream.avail_in = input.size();
        stream.next_in = (Bytef*)input.data();
        do {
            char buffer[1024];
            stream.avail_out = sizeof(buffer);
            stream.next_out = (Bytef*)buffer;
            deflate(&stream, Z_FINISH);
            compressed.append(buffer, sizeof(buffer) - stream.avail_out);
        } while (stream.avail_out == 0);
        deflateEnd(&stream);

        // 解压数据
        stream.zalloc = Z_NULL;
        stream.zfree = Z_NULL;
        stream.opaque = Z_NULL;
        inflateInit2(&stream, windowBit);
        stream.avail_in = compressed.size();
        stream.next_in = (Bytef*)compressed.data();
        do {
            char buffer[1024];
            stream.avail_out = sizeof(buffer);
            stream.next_out = (Bytef*)buffer;
            inflate(&stream, Z_NO_FLUSH);
            decompressed.append(buffer, sizeof(buffer) - stream.avail_out);
        } while (stream.avail_out == 0);
        inflateEnd(&stream);

        // 验证解压后的数据是否与原始数据相同
        EXPECT_EQ(input, decompressed);
    }
}


// 测试zlib格式压缩和解压缩能力
TEST(ZlibTest, CompressionAndDecompression_largedata_5G) {
    const unsigned long long data_length = 1024 * 1024 * 1024 * 5; // 5G
    char* data = new char[data_length];
    generate_random_data(data, data_length);

    // 压缩数据
    const unsigned long long compressed_data_length = compressBound(data_length);
    char* compressed_data = new char[compressed_data_length];
    int result = compress2((Bytef*)compressed_data, (uLongf*)&compressed_data_length, (const Bytef*)data, data_length, Z_BEST_COMPRESSION);
    EXPECT_EQ(result, Z_OK);

    // 解压缩数据
    const unsigned long long decompressed_data_length = data_length;
    char* decompressed_data = new char[decompressed_data_length];
    result = uncompress((Bytef*)decompressed_data, (uLongf*)&decompressed_data_length, (const Bytef*)compressed_data, compressed_data_length);
    EXPECT_EQ(result, Z_OK);

    // 验证解压缩后的数据与原始数据一致
    for (unsigned long long i = 0; i < data_length; i++) {
        EXPECT_EQ(data[i], decompressed_data[i]);
    }

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/* 这个测试用例会对zlib库的压缩和解压缩能力进行全面的测试，包括所有的压缩等级和zlib格式与gzip格式的差别。如果测试通过，就可以保证zlib库的压缩和解压缩能力是安全可靠的。*/
TEST(ZlibTest, CompressAndDecompress) {
    const char* input = "Hello, world!";
    const int input_size = strlen(input);

    // Test zlib format
    for (int level = Z_NO_COMPRESSION; level <= Z_BEST_COMPRESSION; level++) {
        // Compress
        char compressed[1024] = {0};
        uLongf compressed_size = sizeof(compressed);
        int result = compress2((Bytef*)compressed, &compressed_size, (const Bytef*)input, input_size, level);
        ASSERT_EQ(result, Z_OK);

        // Decompress
        char decompressed[1024] = {0};
        uLongf decompressed_size = sizeof(decompressed);
        result = uncompress((Bytef*)decompressed, &decompressed_size, (const Bytef*)compressed, compressed_size);
        ASSERT_EQ(result, Z_OK);

        // Check result
        ASSERT_EQ(decompressed_size, input_size);
        ASSERT_STREQ(decompressed, input);
    }

    // Test gzip format
    for (int level = Z_NO_COMPRESSION; level <= Z_BEST_COMPRESSION; level++) {
        // Compress
        char compressed[1024];
        uLongf compressed_size = sizeof(compressed);
        z_stream stream;
        stream.zalloc = Z_NULL;
        stream.zfree = Z_NULL;
        stream.opaque = Z_NULL;
        deflateInit2(&stream, level, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
        stream.avail_in = input_size;
        stream.next_in = (Bytef*)input;
        stream.avail_out = compressed_size;
        stream.next_out = (Bytef*)compressed;
        int result = deflate(&stream, Z_FINISH);
        ASSERT_EQ(result, Z_STREAM_END);
        compressed_size = stream.total_out;
        deflateEnd(&stream);

        // Decompress
        char decompressed[1024];
        uLongf decompressed_size = sizeof(decompressed);
        stream.zalloc = Z_NULL;
        stream.zfree = Z_NULL;
        stream.opaque = Z_NULL;
        inflateInit2(&stream, 31);
        stream.avail_in = compressed_size;
        stream.next_in = (Bytef*)compressed;
        stream.avail_out = decompressed_size;
        stream.next_out = (Bytef*)decompressed;
        result = inflate(&stream, Z_NO_FLUSH);
        ASSERT_EQ(result, Z_STREAM_END);
        decompressed_size = stream.total_out;
        inflateEnd(&stream);

        // Check result
        ASSERT_EQ(decompressed_size, input_size);
        ASSERT_STREQ(decompressed, input);
    }
}

TEST(ZlibTest, VersionCheck)
{
    KAEZlibVersion ver;
    int ret = kaezlib_get_version(&ver);
    EXPECT_EQ(ret, 0);
    EXPECT_STREQ(ver.productName, "Kunpeng Boostkit");
    EXPECT_STREQ(ver.productVersion, "23.0.RC2");
    EXPECT_STREQ(ver.componentName, "KAEZlib");
    EXPECT_STREQ(ver.componentVersion, "2.0.0");
}

// 主函数
int main(int argc, char **argv)
{
    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}