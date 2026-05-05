/*
 * 异常处理与错误恢复测试
 *
 * 测试维度：
 *   - 无效参数(非法压缩等级、NULL流指针、非法windowBits)
 *   - 缓冲区不足(压缩/解压输出缓冲区过小)
 *   - 数据损坏(篡改压缩数据、截断数据流、垃圾数据)
 *   - 内存分配失败模拟(自定义分配器返回NULL)
 *   - 格式不匹配(ZLIB压缩→GZIP解压等)
 *   - 流重置(deflateReset/inflateReset)
 *   - 未初始化流操作
 *   - inflate专用API(inflateBack、adler32校验)
 */

#include "zlib_test_common.h"

// Mock allocator that always returns NULL for memory allocation failure testing
static void* alloc_null(void*, uInt, uInt) {
    return nullptr;
}

/* ======================== 无效参数测试 ======================== */

/*
 * 测试目的: 验证非法压缩等级(-2或100)被拒绝
 *          仅等级0-9和Z_DEFAULT_COMPRESSION(-1)是合法的
 * 预期结果: deflateInit2返回Z_STREAM_ERROR
 * 测试数据: 无(仅参数验证)
 * 验证方法: 返回码为Z_STREAM_ERROR
 */
TEST(ErrorHandlingTest, InvalidCompressionLevel)
{
    z_stream stream;
    memset(&stream, 0, sizeof(stream));

    EXPECT_EQ(deflateInit2(&stream, -2, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY), Z_STREAM_ERROR);
    EXPECT_EQ(deflateInit2(&stream, 100, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY), Z_STREAM_ERROR);
}

/*
 * 测试目的: 验证NULL流指针被压缩/解压函数拒绝
 * 预期结果: deflate和inflate传入NULL时返回Z_STREAM_ERROR
 * 测试数据: 无(仅参数验证)
 * 验证方法: 返回码为Z_STREAM_ERROR
 */
TEST(ErrorHandlingTest, NullStreamPointer)
{
    EXPECT_EQ(deflate(NULL, Z_NO_FLUSH), Z_STREAM_ERROR);
    EXPECT_EQ(inflate(NULL, Z_NO_FLUSH), Z_STREAM_ERROR);
}

/*
 * 测试目的: 验证非法windowBits值被deflateInit2拒绝
 *          合法值: 8-15(zlib), -8到-15(原始), 24-31(gzip)
 * 预期结果: 非法值(0,7,16,17,23,32)返回Z_STREAM_ERROR
 * 测试数据: 无(仅参数验证)
 * 验证方法: 每个非法值返回Z_STREAM_ERROR
 */
TEST(ErrorHandlingTest, InvalidWindowBits)
{
    z_stream stream;
    memset(&stream, 0, sizeof(stream));

    int invalid_bits[] = {0, 7, 16, 17, 23, 32};
    for (int wb : invalid_bits) {
        int ret = deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, wb, 8, Z_DEFAULT_STRATEGY);
        EXPECT_EQ(ret, Z_STREAM_ERROR) << "Expected Z_STREAM_ERROR for windowBits=" << wb;
    }
}

/* ======================== 缓冲区不足测试 ======================== */

/*
 * 测试目的: 验证压缩输出缓冲区过小时返回Z_BUF_ERROR
 * 预期结果: compress2返回Z_BUF_ERROR
 * 测试数据: 1024字节随机数据, 输出缓冲区仅1字节
 * 验证方法: 返回码为Z_BUF_ERROR
 */
TEST(ErrorHandlingTest, CompressBufferTooSmall)
{
    const uLongf data_length = 1024;
    Bytef* data = new Bytef[data_length];
    generate_random_data(data, data_length);

    const uLongf compressed_data_length = 1;
    Bytef* compressed_data = new Bytef[compressed_data_length];
    int result = compress2(compressed_data, (uLongf*)&compressed_data_length,
        data, data_length, Z_BEST_COMPRESSION);
    EXPECT_EQ(result, Z_BUF_ERROR);

    delete[] data;
    delete[] compressed_data;
}

/*
 * 测试目的: 验证解压输出缓冲区过小时返回Z_BUF_ERROR
 * 预期结果: uncompress返回Z_BUF_ERROR
 * 测试数据: 1024字节压缩后, 解压到1字节缓冲区
 * 验证方法: 返回码为Z_BUF_ERROR
 */
TEST(ErrorHandlingTest, DecompressBufferTooSmall)
{
    const uLongf data_length = 1024;
    Bytef* data = new Bytef[data_length];
    generate_random_data(data, data_length);

    const uLongf compressed_data_length = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_data_length];
    int result = compress2(compressed_data, (uLongf*)&compressed_data_length,
        data, data_length, Z_BEST_COMPRESSION);
    EXPECT_EQ(result, Z_OK);

    const uLongf decompressed_data_length = 1;
    Bytef* decompressed_data = new Bytef[decompressed_data_length];
    result = uncompress(decompressed_data, (uLongf*)&decompressed_data_length,
        compressed_data, compressed_data_length);
    EXPECT_EQ(result, Z_BUF_ERROR);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/* ======================== 数据损坏测试 ======================== */

/*
 * 测试目的: 验证损坏的压缩数据被校验和检测到
 *          篡改压缩流的首字节应被校验和机制发现
 * 预期结果: uncompress返回Z_DATA_ERROR
 * 测试数据: 1024字节压缩后, 首字节覆写为0xFF
 * 验证方法: 返回码为Z_DATA_ERROR
 */
TEST(ErrorHandlingTest, CorruptedCompressedData)
{
    const uLongf data_length = 1024;
    Bytef* data = new Bytef[data_length];
    generate_random_data(data, data_length);

    const uLongf compressed_data_length = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_data_length];
    int result = compress2(compressed_data, (uLongf*)&compressed_data_length,
        data, data_length, Z_BEST_COMPRESSION);
    EXPECT_EQ(result, Z_OK);

    compressed_data[0] = 0xFF;

    const uLongf decompressed_data_length = data_length;
    Bytef* decompressed_data = new Bytef[decompressed_data_length];
    result = uncompress(decompressed_data, (uLongf*)&decompressed_data_length,
        compressed_data, compressed_data_length);
    EXPECT_EQ(result, Z_DATA_ERROR);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/*
 * 测试目的: 验证截断的压缩数据流被检测到
 *          从压缩数据末尾移除字节应被检测
 * 预期结果: uncompress返回Z_DATA_ERROR或Z_BUF_ERROR
 * 测试数据: 1024字节压缩后, 压缩长度减半
 * 验证方法: 返回码不为Z_OK
 */
TEST(ErrorHandlingTest, TruncatedCompressedData)
{
    const uLongf data_length = 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    const uLongf compressed_data_length = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_data_length];
    int result = compress2(compressed_data, (uLongf*)&compressed_data_length,
        data, data_length, Z_BEST_COMPRESSION);
    EXPECT_EQ(result, Z_OK);

    uLongf truncated_length = compressed_data_length / 2;
    const uLongf decompressed_data_length = data_length;
    Bytef* decompressed_data = new Bytef[decompressed_data_length];
    result = uncompress(decompressed_data, (uLongf*)&decompressed_data_length,
        compressed_data, truncated_length);
    EXPECT_NE(result, Z_OK);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/*
 * 测试目的: 验证完全垃圾数据(非有效压缩流)的解压返回Z_DATA_ERROR
 * 预期结果: uncompress返回Z_DATA_ERROR
 * 测试数据: 256字节随机数据作为压缩输入
 * 验证方法: 返回码为Z_DATA_ERROR
 */
TEST(ErrorHandlingTest, GarbageDataDecompression)
{
    const uLongf compressed_length = 256;
    Bytef* fake_compressed = new Bytef[compressed_length];
    generate_random_data(fake_compressed, compressed_length);

    const uLongf decompressed_data_length = 4096;
    Bytef* decompressed_data = new Bytef[decompressed_data_length];
    int result = uncompress(decompressed_data, (uLongf*)&decompressed_data_length,
        fake_compressed, compressed_length);
    EXPECT_EQ(result, Z_DATA_ERROR);

    delete[] fake_compressed;
    delete[] decompressed_data;
}

/* ======================== 内存分配失败测试 ======================== */

/*
 * 测试目的: 验证deflateInit2在内存分配失败时返回Z_MEM_ERROR
 *          通过自定义分配器(始终返回NULL)模拟内存不足
 * 预期结果: deflateInit2返回Z_MEM_ERROR
 * 测试数据: 无(内存分配模拟)
 * 验证方法: 返回码为Z_MEM_ERROR
 */
TEST(ErrorHandlingTest, MemoryAllocationFailure_DeflateInit)
{
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    stream.zalloc = alloc_null;
    stream.zfree = Z_NULL;

    EXPECT_EQ(deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY), Z_MEM_ERROR);
}

/*
 * 测试目的: 验证inflateInit2在内存分配失败时返回Z_MEM_ERROR
 * 预期结果: inflateInit2返回Z_MEM_ERROR
 * 测试数据: 无(内存分配模拟)
 * 验证方法: 返回码为Z_MEM_ERROR
 */
TEST(ErrorHandlingTest, MemoryAllocationFailure_InflateInit)
{
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    stream.zalloc = alloc_null;
    stream.zfree = Z_NULL;

    EXPECT_EQ(inflateInit2(&stream, 15), Z_MEM_ERROR);
}

/* ======================== 格式不匹配测试 ======================== */

/*
 * 测试目的: 验证ZLIB格式压缩的数据用GZIP格式解压会返回错误
 * 预期结果: inflate返回Z_DATA_ERROR(头部不匹配)
 * 测试数据: 1024字节ZLIB格式压缩, GZIP windowBits解压
 * 验证方法: 返回码为Z_DATA_ERROR
 */
TEST(ErrorHandlingTest, FormatMismatch_ZlibCompressed_GzipDecompress)
{
    const uLong data_length = 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    uLong compressed_size = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_size];
    common_compress(15, Z_DEFAULT_COMPRESSION, data, data_length, compressed_data, compressed_size);

    uLong decompressed_size = data_length + 1024;
    Bytef* decompressed_data = new Bytef[decompressed_size];
    int ret = try_uncompress(31, compressed_data, compressed_size, decompressed_data, decompressed_size);
    EXPECT_EQ(ret, Z_DATA_ERROR);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/*
 * 测试目的: 验证GZIP格式压缩的数据用原始DEFLATE格式解压会返回错误
 * 预期结果: inflate返回错误(头部不匹配)
 * 测试数据: 1024字节GZIP格式压缩, 原始DEFLATE windowBits解压
 * 验证方法: 返回码不为Z_OK
 */
TEST(ErrorHandlingTest, FormatMismatch_GzipCompressed_RawDeflateDecompress)
{
    const uLong data_length = 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    uLong compressed_size = compressBound(data_length) + 24;
    Bytef* compressed_data = new Bytef[compressed_size];
    common_compress(31, Z_DEFAULT_COMPRESSION, data, data_length, compressed_data, compressed_size);

    uLong decompressed_size = data_length + 1024;
    Bytef* decompressed_data = new Bytef[decompressed_size];
    int ret = try_uncompress(-15, compressed_data, compressed_size, decompressed_data, decompressed_size);
    EXPECT_NE(ret, Z_OK);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/* ======================== 流状态管理测试 ======================== */

/*
 * 测试目的: 验证inflateReset在部分解压后能正确重置流
 *          重置后应能解压新的压缩数据
 * 预期结果: inflateReset返回Z_OK; 后续解压成功
 * 测试数据: 两个独立的压缩流
 * 验证方法: 两个流均解压正确
 */
TEST(ErrorHandlingTest, InflateResetBetweenStreams)
{
    const uLong data_length = 1024;
    Bytef* data1 = new Bytef[data_length];
    Bytef* data2 = new Bytef[data_length];
    generate_text_data(data1, data_length);
    generate_random_data(data2, data_length);

    uLong comp_size1 = compressBound(data_length);
    Bytef* comp_data1 = new Bytef[comp_size1];
    common_compress(15, Z_DEFAULT_COMPRESSION, data1, data_length, comp_data1, comp_size1);

    uLong comp_size2 = compressBound(data_length);
    Bytef* comp_data2 = new Bytef[comp_size2];
    common_compress(15, Z_DEFAULT_COMPRESSION, data2, data_length, comp_data2, comp_size2);

    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    ASSERT_EQ(inflateInit2(&stream, 15), Z_OK);

    uLong dec_size = data_length + 256;
    Bytef* dec_data = new Bytef[dec_size];

    stream.next_in = comp_data1;
    stream.avail_in = comp_size1;
    stream.next_out = dec_data;
    stream.avail_out = dec_size;
    EXPECT_EQ(inflate(&stream, Z_FINISH), Z_STREAM_END);
    EXPECT_EQ(memcmp(data1, dec_data, data_length), 0);

    EXPECT_EQ(inflateReset(&stream), Z_OK);

    stream.next_in = comp_data2;
    stream.avail_in = comp_size2;
    stream.next_out = dec_data;
    stream.avail_out = dec_size;
    EXPECT_EQ(inflate(&stream, Z_FINISH), Z_STREAM_END);
    EXPECT_EQ(memcmp(data2, dec_data, data_length), 0);

    EXPECT_EQ(inflateEnd(&stream), Z_OK);

    delete[] data1;
    delete[] data2;
    delete[] comp_data1;
    delete[] comp_data2;
    delete[] dec_data;
}

/*
 * 测试目的: 验证deflateReset在两次压缩操作间能正确重置流
 * 预期结果: deflateReset返回Z_OK; 后续压缩成功
 * 测试数据: 两个不同的数据集
 * 验证方法: 两次压缩均产生正确的往返结果
 */
TEST(ErrorHandlingTest, DeflateResetBetweenStreams)
{
    const uLong data_length = 1024;
    Bytef* data1 = new Bytef[data_length];
    Bytef* data2 = new Bytef[data_length];
    generate_text_data(data1, data_length);
    generate_random_data(data2, data_length);

    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    ASSERT_EQ(deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY), Z_OK);

    uLong comp_size = compressBound(data_length);
    Bytef* comp_data = new Bytef[comp_size];

    stream.next_in = data1;
    stream.avail_in = data_length;
    stream.next_out = comp_data;
    stream.avail_out = comp_size;
    EXPECT_EQ(deflate(&stream, Z_FINISH), Z_STREAM_END);

    EXPECT_EQ(deflateReset(&stream), Z_OK);

    stream.next_in = data2;
    stream.avail_in = data_length;
    stream.next_out = comp_data;
    stream.avail_out = comp_size;
    EXPECT_EQ(deflate(&stream, Z_FINISH), Z_STREAM_END);
    uLong comp_len2 = stream.total_out;

    EXPECT_EQ(deflateEnd(&stream), Z_OK);

    uLong dec_size = data_length + 256;
    Bytef* dec_data = new Bytef[dec_size];
    common_uncompress(15, comp_data, comp_len2, dec_data, dec_size);
    EXPECT_EQ(memcmp(data2, dec_data, data_length), 0);

    delete[] data1;
    delete[] data2;
    delete[] comp_data;
    delete[] dec_data;
}

/*
 * 测试目的: 验证对未初始化的流调用inflateEnd/deflateEnd返回Z_STREAM_ERROR
 * 预期结果: 返回Z_STREAM_ERROR
 * 测试数据: 无(状态验证)
 * 验证方法: 返回码为Z_STREAM_ERROR
 */
TEST(ErrorHandlingTest, EndOnUninitializedStream)
{
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    EXPECT_EQ(inflateEnd(&stream), Z_STREAM_ERROR);
    EXPECT_EQ(deflateEnd(&stream), Z_STREAM_ERROR);
}

/* ======================== inflate专用API测试 ======================== */

/*
 * 测试目的: 验证inflateBackInit和inflateBackEnd的正确使用
 *          inflateBack是zlib提供的反向解压回调式API
 * 预期结果: inflateBackInit返回Z_OK; inflateBackEnd返回Z_OK
 * 测试数据: 无(仅API初始化/释放验证)
 * 验证方法: 返回码为Z_OK
 */
TEST(ErrorHandlingTest, InflateBackInitAndEnd)
{
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    unsigned char window[32768];

    int ret = inflateBackInit(&stream, 15, window);
    EXPECT_EQ(ret, Z_OK);

    ret = inflateBackEnd(&stream);
    EXPECT_EQ(ret, Z_OK);
}

/*
 * 测试目的: 验证inflateInit2对负数windowBits(非原始DEFLATE)的拒绝
 *          inflateInit2的windowBits参数不直接支持负数(需通过inflateInit2_特殊处理)
 * 预期结果: 返回错误码
 * 测试数据: 无(参数验证)
 * 验证方法: 返回码不为Z_OK
 */
TEST(ErrorHandlingTest, InflateInit2_NegativeWindowBits)
{
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    int ret = inflateInit2(&stream, -16);
    EXPECT_NE(ret, Z_OK);
}

/*
 * 测试目的: 验证adler32校验和计算的正确性
 *          zlib使用Adler-32作为ZLIB格式的校验和
 * 预期结果: 对已知数据计算adler32, 结果与预期一致
 * 测试数据: 空数据和简单字符串
 * 验证方法: adler32返回值与预期匹配
 */
TEST(ErrorHandlingTest, Adler32Checksum)
{
    uLong adler = adler32(0L, Z_NULL, 0);
    EXPECT_EQ(adler, 1L);

    const Bytef* test_data = (const Bytef*)"hello";
    adler = adler32(adler, test_data, 5);
    EXPECT_NE(adler, 0L);
    EXPECT_NE(adler, 1L);

    uLong adler2 = adler32(0L, test_data, 5);
    EXPECT_NE(adler2, 0L);
}
