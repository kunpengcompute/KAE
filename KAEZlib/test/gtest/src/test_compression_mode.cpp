/*
 * 压缩模式测试 - DEFLATE / ZLIB / GZIP
 *
 * 测试维度：不同压缩格式(windowBits)下的压缩解压缩正确性
 * 覆盖范围：
 *   - 原始DEFLATE (windowBits = -15): 无头部无校验的裸流
 *   - ZLIB格式 (windowBits = 15): 2字节头 + Adler-32尾
 *   - GZIP格式 (windowBits = 31): 10字节头 + CRC-32尾
 *   - 各格式下windowBits合法取值范围的遍历
 *   - 三种格式输出尺寸对比（格式开销递增）
 */

#include "zlib_test_common.h"

/*
 * 测试目的: 验证原始DEFLATE模式的压缩与解压缩(windowBits=-15)
 *          原始DEFLATE产生不带任何头部和校验封装的裸流
 * 预期结果: 压缩和解压缩均成功; 解压数据与原始数据一致
 * 测试数据: 64KB随机二进制数据(低压缩率)
 * 验证方法: memcmp原始数据与解压数据, 尺寸相等
 */
TEST(CompressionModeTest, DeflateMode_RandomData)
{
    const uLong data_length = 64UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_random_data(data, data_length);

    uLong compressed_size = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_size];
    common_compress(-15, Z_DEFAULT_COMPRESSION, data, data_length, compressed_data, compressed_size);

    uLong decompressed_size = data_length + 1024;
    Bytef* decompressed_data = new Bytef[decompressed_size];
    common_uncompress(-15, compressed_data, compressed_size, decompressed_data, decompressed_size);

    EXPECT_EQ(data_length, decompressed_size);
    EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/*
 * 测试目的: 验证ZLIB格式的压缩与解压缩(windowBits=15)
 *          ZLIB格式包含2字节头部和Adler-32校验尾部
 * 预期结果: 压缩和解压缩均成功; 解压数据与原始数据一致
 * 测试数据: 64KB英文文本数据(中等压缩率)
 * 验证方法: memcmp原始数据与解压数据, 尺寸相等
 */
TEST(CompressionModeTest, ZlibMode_TextData)
{
    const uLong data_length = 64UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    uLong compressed_size = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_size];
    common_compress(15, Z_DEFAULT_COMPRESSION, data, data_length, compressed_data, compressed_size);

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
 * 测试目的: 验证GZIP格式的压缩与解压缩(windowBits=31)
 *          GZIP格式包含10字节头部、可选扩展字段和CRC-32尾部
 * 预期结果: 压缩和解压缩均成功; 解压数据与原始数据一致
 * 测试数据: 64KB全零字节(高压缩率)
 * 验证方法: memcmp原始数据与解压数据, 尺寸相等
 */
TEST(CompressionModeTest, GzipMode_RepeatedData)
{
    const uLong data_length = 64UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_repeated_data(data, data_length, 0x00);

    uLong compressed_size = compressBound(data_length) + 24;
    Bytef* compressed_data = new Bytef[compressed_size];
    common_compress(31, Z_DEFAULT_COMPRESSION, data, data_length, compressed_data, compressed_size);

    uLong decompressed_size = data_length + 1024;
    Bytef* decompressed_data = new Bytef[decompressed_size];
    common_uncompress(31, compressed_data, compressed_size, decompressed_data, decompressed_size);

    EXPECT_EQ(data_length, decompressed_size);
    EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/*
 * 测试目的: 验证三种压缩模式产生有效但不同的输出格式
 *          DEFLATE(裸)、ZLIB、GZIP各自添加不同的头部/尾部,
 *          导致相同输入数据产生不同的压缩输出尺寸
 * 预期结果: 三种模式均压缩解压正确; 裸DEFLATE最小, ZLIB次之, GZIP最大
 * 测试数据: 4KB混合模式数据
 * 验证方法: 三种模式均正确往返; 压缩尺寸递增
 */
TEST(CompressionModeTest, AllModes_CompareOutputFormat)
{
    const uLong data_length = 4UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_mixed_pattern_data(data, data_length);

    int modes[] = {-15, 15, 31};
    uLong compressed_sizes[3];
    Bytef* compressed_data[3];
    Bytef* decompressed_data[3];

    for (int i = 0; i < 3; ++i) {
        compressed_sizes[i] = compressBound(data_length) + 24;
        compressed_data[i] = new Bytef[compressed_sizes[i]];
        common_compress(modes[i], Z_DEFAULT_COMPRESSION, data, data_length,
                        compressed_data[i], compressed_sizes[i]);

        uLong dec_size = data_length + 1024;
        decompressed_data[i] = new Bytef[dec_size];
        common_uncompress(modes[i], compressed_data[i], compressed_sizes[i],
                          decompressed_data[i], dec_size);

        EXPECT_EQ(data_length, dec_size);
        EXPECT_EQ(memcmp(data, decompressed_data[i], data_length), 0);
    }

    EXPECT_LT(compressed_sizes[0], compressed_sizes[1]);
    EXPECT_LT(compressed_sizes[1], compressed_sizes[2]);

    for (int i = 0; i < 3; ++i) {
        delete[] compressed_data[i];
        delete[] decompressed_data[i];
    }
    delete[] data;
}

/*
 * 测试目的: 验证ZLIB格式下不同windowBits(9-15)的压缩解压正确性
 *          windowBits影响滑动窗口大小, 进而影响压缩率
 * 预期结果: 所有合法windowBits值均产生正确的压缩解压往返
 * 测试数据: 8KB文本数据
 * 验证方法: 每个windowBits值的往返正确性
 */
TEST(CompressionModeTest, VariousWindowBits_ZlibFormat)
{
    const uLong data_length = 8UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    for (int wb = 9; wb <= 15; ++wb) {
        uLong compressed_size = compressBound(data_length);
        Bytef* compressed_data = new Bytef[compressed_size];
        common_compress(wb, Z_DEFAULT_COMPRESSION, data, data_length, compressed_data, compressed_size);

        uLong decompressed_size = data_length + 1024;
        Bytef* decompressed_data = new Bytef[decompressed_size];
        common_uncompress(wb, compressed_data, compressed_size, decompressed_data, decompressed_size);

        EXPECT_EQ(data_length, decompressed_size);
        EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

        delete[] compressed_data;
        delete[] decompressed_data;
    }
    delete[] data;
}

/*
 * 测试目的: 验证GZIP格式下不同windowBits(25-31)的压缩解压正确性
 * 预期结果: 所有合法GZIP windowBits值均产生正确的压缩解压往返
 * 测试数据: 8KB文本数据
 * 验证方法: 每个windowBits值的往返正确性
 */
TEST(CompressionModeTest, VariousWindowBits_GzipFormat)
{
    const uLong data_length = 8UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    for (int wb = 25; wb <= 31; ++wb) {
        uLong compressed_size = compressBound(data_length) + 24;
        Bytef* compressed_data = new Bytef[compressed_size];
        common_compress(wb, Z_DEFAULT_COMPRESSION, data, data_length, compressed_data, compressed_size);

        uLong decompressed_size = data_length + 1024;
        Bytef* decompressed_data = new Bytef[decompressed_size];
        common_uncompress(wb, compressed_data, compressed_size, decompressed_data, decompressed_size);

        EXPECT_EQ(data_length, decompressed_size);
        EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

        delete[] compressed_data;
        delete[] decompressed_data;
    }
    delete[] data;
}

/*
 * 测试目的: 验证原始DEFLATE格式下不同负数windowBits(-15到-9)的压缩解压正确性
 * 预期结果: 所有合法原始DEFLATE windowBits值均产生正确的压缩解压往返
 * 测试数据: 8KB文本数据
 * 验证方法: 每个windowBits值的往返正确性
 */
TEST(CompressionModeTest, VariousWindowBits_RawDeflateFormat)
{
    const uLong data_length = 8UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    for (int wb = -15; wb <= -9; ++wb) {
        uLong compressed_size = compressBound(data_length);
        Bytef* compressed_data = new Bytef[compressed_size];
        common_compress(wb, Z_DEFAULT_COMPRESSION, data, data_length, compressed_data, compressed_size);

        uLong decompressed_size = data_length + 1024;
        Bytef* decompressed_data = new Bytef[decompressed_size];
        common_uncompress(wb, compressed_data, compressed_size, decompressed_data, decompressed_size);

        EXPECT_EQ(data_length, decompressed_size);
        EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

        delete[] compressed_data;
        delete[] decompressed_data;
    }
    delete[] data;
}
