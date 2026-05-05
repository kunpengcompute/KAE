/*
 * 兼容性与互操作性测试 - 标准zlib库API兼容性验证
 *
 * 测试维度：
 *   - 高级API与低级API互操作(compress2↔inflate, deflate↔uncompress)
 *   - ZLIB/GZIP/DEFLATE格式头部验证
 *   - Adler-32/CRC-32校验和正确性
 *   - 高级API全等级验证
 *   - 流式Z_SYNC_FLUSH兼容性
 *   - 增量解压兼容性
 *   - 不同压缩策略(DEFAULT/FILTERED/HUFFMAN_ONLY/RLE)
 *   - uncompress2扩展API
 *   - compressBound最小值验证
 */

#include "zlib_test_common.h"

/* ======================== API互操作测试 ======================== */

/*
 * 测试目的: 验证高级API(compress2)压缩的输出可被低级API(inflate)解压
 *          测试高级压缩输出与低级解压接口的兼容性
 * 预期结果: 解压成功; 解压数据与原始匹配
 * 测试数据: 8KB文本数据
 * 验证方法: 跨API层级的往返正确性
 */
TEST(CompatibilityTest, Compress2Output_InflateDecompress)
{
    const uLong data_length = 8UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    uLongf compressed_size = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_size];
    int result = compress2(compressed_data, &compressed_size,
        data, data_length, Z_DEFAULT_COMPRESSION);
    EXPECT_EQ(result, Z_OK);

    uLong decompressed_size = data_length + 1024;
    Bytef* decompressed_data = new Bytef[decompressed_size];
    common_uncompress(15, compressed_data, compressed_size, decompressed_data, decompressed_size);

    EXPECT_EQ(data_length, decompressed_size);
    EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/*
 * 测试目的: 验证低级API(deflate)压缩的输出可被高级API(uncompress)解压
 * 预期结果: 解压成功; 解压数据与原始匹配
 * 测试数据: 8KB文本数据
 * 验证方法: 跨API层级的往返正确性
 */
TEST(CompatibilityTest, DeflateOutput_UncompressDecompress)
{
    const uLong data_length = 8UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    uLong compressed_size = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_size];
    common_compress(15, Z_DEFAULT_COMPRESSION, data, data_length, compressed_data, compressed_size);

    uLongf decompressed_size = data_length;
    Bytef* decompressed_data = new Bytef[decompressed_size];
    int result = uncompress(decompressed_data, &decompressed_size,
        compressed_data, compressed_size);
    EXPECT_EQ(result, Z_OK);
    EXPECT_EQ(data_length, decompressed_size);
    EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/* ======================== 格式头部验证测试 ======================== */

/*
 * 测试目的: 验证ZLIB格式压缩数据具有正确的头部字节
 *          有效ZLIB流以2字节头开始: CMF(0x78) + FLG
 *          FLG字节中编码了压缩等级信息
 * 预期结果: 压缩数据首字节为0x78; 头部校验(CMF*256+FLG)%31==0
 * 测试数据: 4KB文本数据
 * 验证方法: 首两字节匹配ZLIB头规范
 */
TEST(CompatibilityTest, ZlibHeaderValidation)
{
    const uLong data_length = 4UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    int levels[] = {0, 1, 6, 9};

    for (int level : levels) {
        uLong compressed_size = compressBound(data_length);
        Bytef* compressed_data = new Bytef[compressed_size];
        common_compress(15, level, data, data_length, compressed_data, compressed_size);

        EXPECT_EQ(compressed_data[0], 0x78)
            << "CMF byte mismatch for level " << level;
        EXPECT_EQ(((int)compressed_data[0] * 256 + (int)compressed_data[1]) % 31, 0)
            << "FLG check failed for level " << level;

        delete[] compressed_data;
    }
    delete[] data;
}

/*
 * 测试目的: 验证GZIP格式压缩数据具有正确的头部
 *          有效GZIP流以魔数0x1F 0x8B开始
 * 预期结果: GZIP压缩输出首两字节为0x1F和0x8B
 * 测试数据: 4KB文本数据
 * 验证方法: GZIP魔数存在于压缩输出中
 */
TEST(CompatibilityTest, GzipHeaderValidation)
{
    const uLong data_length = 4UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    uLong compressed_size = compressBound(data_length) + 24;
    Bytef* compressed_data = new Bytef[compressed_size];
    common_compress(31, Z_DEFAULT_COMPRESSION, data, data_length, compressed_data, compressed_size);

    EXPECT_EQ(compressed_data[0], 0x1F);
    EXPECT_EQ(compressed_data[1], 0x8B);

    delete[] data;
    delete[] compressed_data;
}

/*
 * 测试目的: 验证原始DEFLATE输出不含格式头部
 *          原始DEFLATE(windowBits<0)不应有ZLIB或GZIP头部
 * 预期结果: 压缩输出不以ZLIB头(0x78)或GZIP魔数(0x1F 0x8B)开头
 * 测试数据: 4KB文本数据
 * 验证方法: 无格式特定头部
 */
TEST(CompatibilityTest, RawDeflateNoHeader)
{
    const uLong data_length = 4UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    uLong compressed_size = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_size];
    common_compress(-15, Z_DEFAULT_COMPRESSION, data, data_length, compressed_data, compressed_size);

    EXPECT_FALSE(compressed_data[0] == 0x78 && ((int)compressed_data[0] * 256 + (int)compressed_data[1]) % 31 == 0);
    EXPECT_FALSE(compressed_data[0] == 0x1F && compressed_data[1] == 0x8B);

    delete[] data;
    delete[] compressed_data;
}

/* ======================== 校验和验证测试 ======================== */

/*
 * 测试目的: 验证ZLIB格式中Adler-32校验和的正确性
 *          ZLIB格式尾部包含未压缩数据的Adler-32校验和
 *          解压后流的adler字段应与直接计算的校验和匹配
 * 预期结果: 解压流中的adler32与对原始数据计算的adler32一致
 * 测试数据: 4KB文本数据
 * 验证方法: stream.adler == adler32(data)
 */
TEST(CompatibilityTest, Adler32Checksum_ZlibFormat)
{
    const uLong data_length = 4UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    uLong compressed_size = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_size];
    common_compress(15, Z_DEFAULT_COMPRESSION, data, data_length, compressed_data, compressed_size);

    uLong decompressed_size = data_length + 1024;
    Bytef* decompressed_data = new Bytef[decompressed_size];

    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = compressed_size;
    stream.next_in = compressed_data;
    stream.avail_out = decompressed_size;
    stream.next_out = decompressed_data;
    ASSERT_EQ(inflateInit2(&stream, 15), Z_OK);
    ASSERT_EQ(inflate(&stream, Z_FINISH), Z_STREAM_END);
    ASSERT_EQ(inflateEnd(&stream), Z_OK);
    decompressed_size = stream.total_out;

    uLong expected_adler = adler32(1L, data, data_length);
    EXPECT_EQ(stream.adler, expected_adler);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/*
 * 测试目的: 验证GZIP格式中CRC-32校验和的正确性
 *          GZIP格式尾部包含未压缩数据的CRC-32校验和
 * 预期结果: 解压数据的CRC-32与原始数据的CRC-32一致
 * 测试数据: 4KB文本数据
 * 验证方法: crc32(decompressed) == crc32(original)
 */
TEST(CompatibilityTest, CRC32Checksum_GzipFormat)
{
    const uLong data_length = 4UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    uLong compressed_size = compressBound(data_length) + 24;
    Bytef* compressed_data = new Bytef[compressed_size];
    common_compress(31, Z_DEFAULT_COMPRESSION, data, data_length, compressed_data, compressed_size);

    uLong decompressed_size = data_length + 1024;
    Bytef* decompressed_data = new Bytef[decompressed_size];
    common_uncompress(31, compressed_data, compressed_size, decompressed_data, decompressed_size);

    uLong expected_crc = crc32(0L, data, data_length);
    uLong actual_crc = crc32(0L, decompressed_data, decompressed_size);
    EXPECT_EQ(expected_crc, actual_crc);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/* ======================== 高级API验证测试 ======================== */

/*
 * 测试目的: 验证compress2/uncompress高级API在所有压缩等级下的正确性
 * 预期结果: 所有等级通过高级API产生正确的往返
 * 测试数据: 4KB文本数据
 * 验证方法: 每个等级的往返正确性
 */
TEST(CompatibilityTest, HighLevelAPI_AllLevels)
{
    const uLongf data_length = 4UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    for (int level = 0; level <= 9; ++level) {
        uLongf compressed_size = compressBound(data_length);
        Bytef* compressed_data = new Bytef[compressed_size];
        int result = compress2(compressed_data, &compressed_size,
            data, data_length, level);
        EXPECT_EQ(result, Z_OK);

        uLongf decompressed_size = data_length;
        Bytef* decompressed_data = new Bytef[decompressed_size];
        result = uncompress(decompressed_data, &decompressed_size,
            compressed_data, compressed_size);
        EXPECT_EQ(result, Z_OK);
        EXPECT_EQ(data_length, decompressed_size);
        EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

        delete[] compressed_data;
        delete[] decompressed_data;
    }
    delete[] data;
}

/*
 * 测试目的: 验证uncompress2扩展API的正确性
 *          uncompress2额外返回已消耗的压缩字节数
 * 预期结果: 解压成功; 消耗字节数等于压缩尺寸
 * 测试数据: 4KB文本数据
 * 验证方法: 往返正确性; source_len == compressed_size
 */
TEST(CompatibilityTest, Uncompress2API)
{
    const uLongf data_length = 4UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    uLongf compressed_size = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_size];
    int result = compress2(compressed_data, &compressed_size,
        data, data_length, Z_DEFAULT_COMPRESSION);
    EXPECT_EQ(result, Z_OK);

    uLongf decompressed_size = data_length;
    Bytef* decompressed_data = new Bytef[decompressed_size];
    uLongf source_len = compressed_size;
    result = uncompress2(decompressed_data, &decompressed_size,
        compressed_data, &source_len);
    EXPECT_EQ(result, Z_OK);
    EXPECT_EQ(data_length, decompressed_size);
    EXPECT_EQ(source_len, compressed_size);
    EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/*
 * 测试目的: 验证compressBound对非空数据返回值>=13
 *          最小ZLIB流为11字节(头部+空DEFLATE块+Adler-32),
 *          加上compress2的存储块封装至少13字节
 * 预期结果: compressBound返回值>=13
 * 测试数据: 多种输入尺寸(1到1MB)
 * 验证方法: compressBound结果>=13
 */
TEST(CompatibilityTest, CompressBoundMinimumSize)
{
    uLong sizes[] = {1, 10, 100, 1000, 10000, 100000, 1000000};
    for (uLong sz : sizes) {
        uLong bound = compressBound(sz);
        EXPECT_GE(bound, (uLong)13) << "compressBound(" << sz << ") = " << bound << " < 13";
    }
}

/* ======================== 流式与增量处理测试 ======================== */

/*
 * 测试目的: 验证Z_SYNC_FLUSH流式压缩的兼容性
 *          使用Z_SYNC_FLUSH压缩的流应能被标准inflate正确解压
 * 预期结果: 流式压缩产生与一次性压缩相同的解压输出
 * 测试数据: 16KB文本数据, 4KB分块Z_SYNC_FLUSH压缩
 * 验证方法: 往返正确性
 */
TEST(CompatibilityTest, StreamingWithSyncFlush)
{
    const uLong data_length = 16UL * 1024;
    const uLong chunk_size = 4UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    uLong compressed_bound = compressBound(data_length) + 1024;
    Bytef* compressed_data = new Bytef[compressed_bound];

    z_stream c_stream;
    memset(&c_stream, 0, sizeof(c_stream));
    ASSERT_EQ(deflateInit2(&c_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY), Z_OK);

    uLong offset = 0;
    while (offset < data_length) {
        uLong remaining = data_length - offset;
        uLong this_chunk = (remaining > chunk_size) ? chunk_size : remaining;

        c_stream.next_in = data + offset;
        c_stream.avail_in = this_chunk;
        c_stream.next_out = compressed_data + c_stream.total_out;
        c_stream.avail_out = compressed_bound - c_stream.total_out;

        int flush = (offset + this_chunk >= data_length) ? Z_FINISH : Z_SYNC_FLUSH;
        int ret = deflate(&c_stream, flush);
        if (flush == Z_FINISH) {
            EXPECT_EQ(ret, Z_STREAM_END);
        } else {
            EXPECT_EQ(ret, Z_OK);
        }
        offset += this_chunk;
    }
    uLong total_compressed = c_stream.total_out;
    ASSERT_EQ(deflateEnd(&c_stream), Z_OK);

    uLong decompressed_size = data_length + 1024;
    Bytef* decompressed_data = new Bytef[decompressed_size];
    common_uncompress(15, compressed_data, total_compressed, decompressed_data, decompressed_size);

    EXPECT_EQ(data_length, decompressed_size);
    EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/*
 * 测试目的: 验证增量解压(小分块inflate)的兼容性
 *          模拟压缩数据以小包到达的真实场景
 * 预期结果: 增量解压产生与一次性解压相同的结果
 * 测试数据: 16KB文本数据
 * 验证方法: 解压数据与原始匹配
 */
TEST(CompatibilityTest, IncrementalDecompression)
{
    const uLong data_length = 16UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    uLong compressed_size = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_size];
    common_compress(15, Z_DEFAULT_COMPRESSION, data, data_length, compressed_data, compressed_size);

    Bytef* decompressed_data = new Bytef[data_length + 1024];
    uLong total_decompressed = 0;

    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    ASSERT_EQ(inflateInit2(&stream, 15), Z_OK);

    uLong comp_offset = 0;
    const uLong comp_chunk = 256;
    const uLong decomp_chunk = 512;

    int ret = Z_OK;
    while (ret != Z_STREAM_END) {
        if (stream.avail_in == 0 && comp_offset < compressed_size) {
            uLong remaining = compressed_size - comp_offset;
            uLong this_chunk = (remaining > comp_chunk) ? comp_chunk : remaining;
            stream.next_in = compressed_data + comp_offset;
            stream.avail_in = this_chunk;
            comp_offset += this_chunk;
        }

        if (stream.avail_out == 0) {
            stream.next_out = decompressed_data + stream.total_out;
            stream.avail_out = decomp_chunk;
        }

        ret = inflate(&stream, Z_NO_FLUSH);
        ASSERT_TRUE(ret == Z_OK || ret == Z_STREAM_END);
    }

    total_decompressed = stream.total_out;

    ASSERT_EQ(inflateEnd(&stream), Z_OK);
    EXPECT_EQ(data_length, total_decompressed);
    EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/* ======================== 压缩策略测试 ======================== */

/*
 * 测试目的: 验证不同压缩策略产生有效输出
 *          zlib支持Z_DEFAULT_STRATEGY, Z_FILTERED, Z_HUFFMAN_ONLY, Z_RLE
 *          每种策略使用不同内部算法但必须产生有效流
 * 预期结果: 所有策略产生可正确解压的有效压缩数据
 * 测试数据: 8KB文本数据
 * 验证方法: 每种策略的往返正确性
 */
TEST(CompatibilityTest, DifferentCompressionStrategies)
{
    const uLong data_length = 8UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    int strategies[] = {Z_DEFAULT_STRATEGY, Z_FILTERED, Z_HUFFMAN_ONLY, Z_RLE};
    const char* strategy_names[] = {"DEFAULT", "FILTERED", "HUFFMAN_ONLY", "RLE"};

    for (int s = 0; s < 4; ++s) {
        z_stream stream;
        memset(&stream, 0, sizeof(stream));
        stream.zalloc = Z_NULL;
        stream.zfree = Z_NULL;
        stream.opaque = Z_NULL;
        stream.avail_in = data_length;
        stream.next_in = data;
        uLong compressed_size = compressBound(data_length);
        stream.avail_out = compressed_size;
        Bytef* compressed_data = new Bytef[compressed_size];
        stream.next_out = compressed_data;

        ASSERT_EQ(deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15, 8, strategies[s]), Z_OK);
        ASSERT_EQ(deflate(&stream, Z_FINISH), Z_STREAM_END);
        uLong actual_compressed_size = stream.total_out;
        ASSERT_EQ(deflateEnd(&stream), Z_OK);

        uLong decompressed_size = data_length + 1024;
        Bytef* decompressed_data = new Bytef[decompressed_size];
        common_uncompress(15, compressed_data, actual_compressed_size,
                          decompressed_data, decompressed_size);

        EXPECT_EQ(data_length, decompressed_size);
        EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0)
            << "Strategy " << strategy_names[s] << " failed";

        delete[] compressed_data;
        delete[] decompressed_data;
    }
    delete[] data;
}
