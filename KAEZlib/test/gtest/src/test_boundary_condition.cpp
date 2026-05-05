/*
 * 边界条件测试 - 空数据/极小数据/页对齐/DEFLATE块边界/大尺寸
 *
 * 测试维度：
 *   - 空数据(0字节)
 *   - 极小数据(1字节、2字节)
 *   - 小尺寸系统遍历(1-256字节)
 *   - 内存页边界(4KB、8KB)
 *   - DEFLATE块边界(65535、65536)
 *   - 中等尺寸(1MB)
 *   - 大尺寸(5GB)
 *   - compressBound充分性验证
 */

#include "zlib_test_common.h"

/*
 * 测试目的: 验证空数据(0字节)的压缩与解压缩
 *          压缩器必须产生有效的空流(仅含头部)
 * 预期结果: 压缩返回Z_OK; 解压成功且输出0字节
 * 测试数据: 0字节(空指针, 长度0)
 * 验证方法: 两个操作均返回Z_OK; 解压长度为0
 */
TEST(BoundaryConditionTest, EmptyData)
{
    const uLongf data_length = 0;
    Bytef* data = nullptr;

    const uLongf compressed_data_length = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_data_length];
    int result = compress2(compressed_data, (uLongf*)&compressed_data_length,
        data, data_length, Z_BEST_COMPRESSION);
    EXPECT_EQ(result, Z_OK);

    const uLongf decompressed_data_length = data_length;
    Bytef* decompressed_data = new Bytef[decompressed_data_length];
    result = uncompress(decompressed_data, (uLongf*)&decompressed_data_length,
        compressed_data, compressed_data_length);
    EXPECT_EQ(result, Z_OK);
    EXPECT_EQ(data_length, decompressed_data_length);

    delete[] compressed_data;
    delete[] decompressed_data;
}

/*
 * 测试目的: 验证1字节数据的压缩解压
 *          测试最小非空数据边界
 * 预期结果: 压缩解压成功; 单字节被正确保留
 * 测试数据: 1字节(值0x42)
 * 验证方法: 往返正确性; 解压数据与原始匹配
 */
TEST(BoundaryConditionTest, SingleByte)
{
    const uLongf data_length = 1;
    Bytef* data = new Bytef[data_length];
    data[0] = 0x42;

    const uLongf compressed_data_length = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_data_length];
    int result = compress2(compressed_data, (uLongf*)&compressed_data_length,
        data, data_length, Z_BEST_COMPRESSION);
    EXPECT_EQ(result, Z_OK);

    const uLongf decompressed_data_length = data_length;
    Bytef* decompressed_data = new Bytef[decompressed_data_length];
    result = uncompress(decompressed_data, (uLongf*)&decompressed_data_length,
        compressed_data, compressed_data_length);
    EXPECT_EQ(result, Z_OK);
    EXPECT_EQ(data_length, decompressed_data_length);
    EXPECT_EQ(data[0], decompressed_data[0]);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/*
 * 测试目的: 验证2字节数据的压缩解压
 *          测试存储块与压缩块之间的边界
 * 预期结果: 压缩解压成功
 * 测试数据: 2字节(0x00, 0xFF)
 * 验证方法: 往返正确性
 */
TEST(BoundaryConditionTest, TwoBytes)
{
    const uLongf data_length = 2;
    Bytef* data = new Bytef[data_length];
    data[0] = 0x00;
    data[1] = 0xFF;

    const uLongf compressed_data_length = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_data_length];
    int result = compress2(compressed_data, (uLongf*)&compressed_data_length,
        data, data_length, Z_BEST_COMPRESSION);
    EXPECT_EQ(result, Z_OK);

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

/*
 * 测试目的: 系统遍历1-256字节的所有小尺寸数据
 *          系统性地测试所有小尺寸以捕获尺寸相关缺陷
 * 预期结果: 每个尺寸从1到256均压缩解压正确
 * 测试数据: 每个尺寸填充顺序字节值
 * 验证方法: 每个尺寸的往返正确性
 */
TEST(BoundaryConditionTest, SmallSizes_1To256)
{
    for (uLong data_length = 1; data_length <= 256; ++data_length) {
        Bytef* data = new Bytef[data_length];
        for (uLong i = 0; i < data_length; ++i) {
            data[i] = (Bytef)(i % 256);
        }

        uLong compressed_size = compressBound(data_length);
        Bytef* compressed_data = new Bytef[compressed_size];
        common_compress(15, Z_DEFAULT_COMPRESSION, data, data_length, compressed_data, compressed_size);

        uLong decompressed_size = data_length + 256;
        Bytef* decompressed_data = new Bytef[decompressed_size];
        common_uncompress(15, compressed_data, compressed_size, decompressed_data, decompressed_size);

        EXPECT_EQ(data_length, decompressed_size);
        EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

        delete[] data;
        delete[] compressed_data;
        delete[] decompressed_data;
    }
}

/*
 * 测试目的: 验证4KB页边界数据的压缩解压
 *          内存页边界有时会暴露对齐相关的缺陷
 * 预期结果: 压缩解压成功
 * 测试数据: 恰好4096字节文本数据
 * 验证方法: 往返正确性
 */
TEST(BoundaryConditionTest, PageSizeBoundary_4K)
{
    const uLong data_length = 4096;
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
 * 测试目的: 验证DEFLATE单存储块最大边界(65535字节)
 *          65535是DEFLATE格式中单个存储块的最大尺寸
 * 预期结果: 压缩解压成功
 * 测试数据: 恰好65535字节混合数据
 * 验证方法: 往返正确性
 */
TEST(BoundaryConditionTest, DeflateBlockMaxBoundary_64KMinus1)
{
    const uLong data_length = 65535;
    Bytef* data = new Bytef[data_length];
    generate_mixed_pattern_data(data, data_length);

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
 * 测试目的: 验证DEFLATE块分割边界(65536字节)
 *          此边界处DEFLATE必须将数据分割为多个块
 * 预期结果: 压缩解压成功
 * 测试数据: 恰好65536字节文本数据
 * 验证方法: 往返正确性
 */
TEST(BoundaryConditionTest, DeflateBlockBoundary_64K)
{
    const uLong data_length = 65536;
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
 * 测试目的: 验证1MB数据在三种模式下的压缩解压
 *          测试中等尺寸数据处理
 * 预期结果: 三种模式均压缩解压成功
 * 测试数据: 1MB文本数据
 * 验证方法: 每种模式的往返正确性
 */
TEST(BoundaryConditionTest, MediumSize_1MB)
{
    const uLong data_length = 1024UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    int modes[] = {-15, 15, 31};
    for (int m = 0; m < 3; ++m) {
        uLong compressed_size = compressBound(data_length) + 24;
        Bytef* compressed_data = new Bytef[compressed_size];
        common_compress(modes[m], Z_DEFAULT_COMPRESSION, data, data_length,
                        compressed_data, compressed_size);

        uLong decompressed_size = data_length + 1024;
        Bytef* decompressed_data = new Bytef[decompressed_size];
        common_uncompress(modes[m], compressed_data, compressed_size,
                          decompressed_data, decompressed_size);

        EXPECT_EQ(data_length, decompressed_size);
        EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

        delete[] compressed_data;
        delete[] decompressed_data;
    }
    delete[] data;
}

/*
 * 测试目的: 验证5GB大尺寸数据的压缩解压(使用高级API)
 *          测试极限尺寸下的压缩解压能力
 * 预期结果: 压缩解压成功; 解压数据与原始一致
 * 测试数据: 5GB零初始化数据
 * 验证方法: 往返正确性
 */
TEST(BoundaryConditionTest, LargeSize_5GB)
{
    const uLongf data_length = 1024UL * 1024 * 1024 * 5;
    Bytef* data = new Bytef[data_length];

    const uLongf compressed_data_length = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_data_length];
    int result = compress2((Bytef*)compressed_data, (uLongf*)&compressed_data_length,
        (const Bytef*)data, data_length, Z_BEST_COMPRESSION);
    EXPECT_EQ(result, Z_OK);

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
 * 测试目的: 验证compressBound返回值始终足够容纳压缩输出
 *          无论数据特征如何, 实际压缩尺寸不应超过compressBound
 * 预期结果: 实际压缩尺寸 <= compressBound(输入尺寸)
 * 测试数据: 多种数据类型和尺寸
 * 验证方法: compressed_size <= compressBound(input_size)
 */
TEST(BoundaryConditionTest, CompressBoundSufficiency)
{
    const uLong sizes[] = {1, 100, 4096, 65536, 256UL * 1024};

    for (int i = 0; i < 5; ++i) {
        Bytef* data = new Bytef[sizes[i]];
        if (i < 2) {
            generate_random_data(data, sizes[i]);
        } else if (i < 4) {
            generate_text_data(data, sizes[i]);
        } else {
            generate_repeated_data(data, sizes[i], 0x00);
        }

        uLong bound = compressBound(sizes[i]);
        uLong compressed_size = bound;
        Bytef* compressed_data = new Bytef[compressed_size];

        int ret = try_compress(15, Z_DEFAULT_COMPRESSION, data, sizes[i],
                               compressed_data, compressed_size);
        EXPECT_EQ(ret, Z_OK);
        EXPECT_LE(compressed_size, bound);

        delete[] data;
        delete[] compressed_data;
    }
}
