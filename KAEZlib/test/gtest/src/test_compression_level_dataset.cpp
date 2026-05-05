/*
 * 压缩等级与数据集测试 - Level 0-9 + 多样化数据样本
 *
 * 测试维度：
 *   - 压缩等级0(不压缩)到9(最佳压缩)的正确性
 *   - 压缩率单调性验证(高等级产生更小输出)
 *   - 等级×模式矩阵测试(10等级×3模式)
 *   - 低压缩率数据(随机二进制)
 *   - 中压缩率数据(英文文本)
 *   - 高压缩率数据(全零/重复字节)
 *   - 标准Calgary/Canterbury语料库文件
 *   - 特殊模式数据(交替字节、全字节值覆盖)
 */

#include "zlib_test_common.h"

/* ======================== 压缩等级测试 ======================== */

/*
 * 测试目的: 验证压缩等级0(不压缩/存储模式)
 *          等级0下数据不进行压缩, 仅添加格式头部/尾部封装
 * 预期结果: 压缩成功; 解压数据与原始一致; 压缩尺寸>=原始尺寸
 * 测试数据: 4KB文本数据
 * 验证方法: 往返正确性; 压缩尺寸>=输入尺寸
 */
TEST(CompressionLevelTest, Level0_NoCompression)
{
    const uLong data_length = 4UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    uLong compressed_size = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_size];
    common_compress(15, 0, data, data_length, compressed_data, compressed_size);

    uLong decompressed_size = data_length + 1024;
    Bytef* decompressed_data = new Bytef[decompressed_size];
    common_uncompress(15, compressed_data, compressed_size, decompressed_data, decompressed_size);

    EXPECT_EQ(data_length, decompressed_size);
    EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);
    EXPECT_GE(compressed_size, data_length);

    delete[] data;
    delete[] compressed_data;
    delete[] decompressed_data;
}

/*
 * 测试目的: 验证压缩等级1-9及Z_DEFAULT_COMPRESSION的正确性
 *          所有等级均应产生正确的压缩解压往返
 * 预期结果: 每个等级压缩解压均成功; 解压数据与原始一致
 * 测试数据: 32KB混合模式数据
 * 验证方法: 每个等级的往返正确性
 */
TEST(CompressionLevelTest, AllLevels_RoundTrip)
{
    const uLong data_length = 32UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    for (int level = 0; level <= 9; ++level) {
        uLong compressed_size = compressBound(data_length);
        Bytef* compressed_data = new Bytef[compressed_size];
        common_compress(15, level, data, data_length, compressed_data, compressed_size);

        uLong decompressed_size = data_length + 1024;
        Bytef* decompressed_data = new Bytef[decompressed_size];
        common_uncompress(15, compressed_data, compressed_size, decompressed_data, decompressed_size);

        EXPECT_EQ(data_length, decompressed_size);
        EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

        delete[] compressed_data;
        delete[] decompressed_data;
    }
    delete[] data;
}

/*
 * 测试目的: 验证高压缩等级产生更小的输出(压缩率单调性)
 *          对可压缩数据, 等级9输出<=等级6输出<=等级1输出
 *          等级0输出最大(不压缩)
 * 预期结果: size_level0 > size_level1 >= size_level6 >= size_level9
 * 测试数据: 16KB文本数据(高可压缩性)
 * 验证方法: 比较各等级压缩尺寸
 */
TEST(CompressionLevelTest, MonotonicCompressionRatio)
{
    const uLong data_length = 16UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    uLong size_level0, size_level1, size_level6, size_level9;
    uLong cs = compressBound(data_length);
    Bytef* buf = new Bytef[cs];

    uLong sz = cs;
    common_compress(15, 0, data, data_length, buf, sz);
    size_level0 = sz;

    sz = cs;
    common_compress(15, 1, data, data_length, buf, sz);
    size_level1 = sz;

    sz = cs;
    common_compress(15, 6, data, data_length, buf, sz);
    size_level6 = sz;

    sz = cs;
    common_compress(15, 9, data, data_length, buf, sz);
    size_level9 = sz;

    EXPECT_GT(size_level0, size_level1);
    EXPECT_GE(size_level1, size_level6);
    EXPECT_GE(size_level6, size_level9);

    delete[] data;
    delete[] buf;
}

/*
 * 测试目的: 验证所有压缩等级(0-9)与所有压缩模式(DEFLATE/ZLIB/GZIP)的矩阵组合
 * 预期结果: 每种(等级,模式)组合均产生正确的压缩解压往返
 * 测试数据: 8KB文本数据
 * 验证方法: 每种组合的往返正确性
 */
TEST(CompressionLevelTest, AllLevels_AllModes_Matrix)
{
    const uLong data_length = 8UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_text_data(data, data_length);

    int modes[] = {-15, 15, 31};

    for (int level = 0; level <= 9; ++level) {
        for (int m = 0; m < 3; ++m) {
            uLong compressed_size = compressBound(data_length) + 24;
            Bytef* compressed_data = new Bytef[compressed_size];
            common_compress(modes[m], level, data, data_length, compressed_data, compressed_size);

            uLong decompressed_size = data_length + 1024;
            Bytef* decompressed_data = new Bytef[decompressed_size];
            common_uncompress(modes[m], compressed_data, compressed_size,
                              decompressed_data, decompressed_size);

            EXPECT_EQ(data_length, decompressed_size);
            EXPECT_EQ(memcmp(data, decompressed_data, data_length), 0);

            delete[] compressed_data;
            delete[] decompressed_data;
        }
    }
    delete[] data;
}

/* ======================== 数据集测试 ======================== */

/*
 * 测试目的: 验证低压缩率数据(随机二进制)的压缩解压
 *          随机数据具有接近最大熵, 压缩效果差甚至膨胀
 * 预期结果: 压缩解压成功; 解压数据与原始一致; 压缩率>90%
 * 测试数据: 64KB随机二进制数据(熵~8 bits/byte)
 * 验证方法: 往返正确性; 压缩率接近1.0
 */
TEST(DataSetTest, LowCompressionRatio_RandomBinary)
{
    const uLong data_length = 64UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_random_data(data, data_length);

    uLong compressed_size = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_size];
    common_compress(15, Z_BEST_COMPRESSION, data, data_length, compressed_data, compressed_size);

    double ratio = (double)compressed_size / (double)data_length;
    EXPECT_GT(ratio, 0.9);

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
 * 测试目的: 验证中压缩率数据(英文文本)的压缩解压
 *          自然语言文本通常压缩到原始大小的30-50%
 * 预期结果: 压缩解压成功; 压缩率在10%-70%范围内
 * 测试数据: 128KB英文文本(重复段落)
 * 验证方法: 往返正确性; 压缩率在合理范围
 */
TEST(DataSetTest, MediumCompressionRatio_EnglishText)
{
    const uLong data_length = 128UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_data_with_ratio(data, data_length, 0.4);

    uLong compressed_size = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_size];
    common_compress(15, Z_DEFAULT_COMPRESSION, data, data_length, compressed_data, compressed_size);

    double ratio = (double)compressed_size / (double)data_length;
    EXPECT_LT(ratio, 0.7);
    EXPECT_GT(ratio, 0.1);

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
 * 测试目的: 验证高压缩率数据(全零字节)的压缩解压
 *          全零数据应压缩到极小尺寸
 * 预期结果: 压缩解压成功; 压缩率<1%
 * 测试数据: 1MB全零字节
 * 验证方法: 往返正确性; 压缩尺寸极小
 */
TEST(DataSetTest, HighCompressionRatio_AllZeros)
{
    const uLong data_length = 1024UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_repeated_data(data, data_length, 0x00);

    uLong compressed_size = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_size];
    common_compress(15, Z_BEST_COMPRESSION, data, data_length, compressed_data, compressed_size);

    double ratio = (double)compressed_size / (double)data_length;
    EXPECT_LT(ratio, 0.01);

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
 * 测试目的: 验证高压缩率数据(重复单字节0xAA)的压缩解压
 * 预期结果: 极高压缩率; 正确往返
 * 测试数据: 1MB的0xAA字节
 * 验证方法: 往返正确性; 压缩尺寸极小
 */
TEST(DataSetTest, HighCompressionRatio_RepeatedByte)
{
    const uLong data_length = 1024UL * 1024;
    Bytef* data = new Bytef[data_length];
    generate_repeated_data(data, data_length, 0xAA);

    uLong compressed_size = compressBound(data_length);
    Bytef* compressed_data = new Bytef[compressed_size];
    common_compress(15, Z_BEST_COMPRESSION, data, data_length, compressed_data, compressed_size);

    double ratio = (double)compressed_size / (double)data_length;
    EXPECT_LT(ratio, 0.01);

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
 * 测试目的: 验证混合模式数据(不同字节值的交替游程)的压缩解压
 *          模拟具有变化局部熵的数据
 * 预期结果: 压缩解压成功; 中等压缩率
 * 测试数据: 64KB混合模式数据(变长游程的不同字节值)
 * 验证方法: 往返正确性
 */
TEST(DataSetTest, MixedPatternData)
{
    const uLong data_length = 64UL * 1024;
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
 * 测试目的: 验证包含全部256种字节值的数据的压缩解压
 *          测试对完整字节范围的处理能力
 * 预期结果: 压缩解压成功
 * 测试数据: 4KB数据, 每个位置填入(i%256)覆盖全部字节值
 * 验证方法: 往返正确性
 */
TEST(DataSetTest, AllByteValues)
{
    const uLong data_length = 4UL * 1024;
    Bytef* data = new Bytef[data_length];
    for (uLong i = 0; i < data_length; ++i) {
        data[i] = (Bytef)(i % 256);
    }

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
 * 测试目的: 验证使用标准Calgary/Canterbury语料库文件的压缩解压
 *          这些是压缩社区事实上的标准基准文件
 * 预期结果: 所有测试文件在三种模式下均压缩解压正确
 * 测试数据: compressTestDataset目录下的7个标准语料文件
 * 验证方法: 每个文件在每种模式下的往返正确性
 */
TEST(DataSetTest, StandardCorpusFiles)
{
    const string testfiles[] = {"itemdata", "ooffice", "osdb", "samba", "webster", "xml", "x-ray"};
    int modes[] = {-15, 15, 31};

    for (const auto& fileName : testfiles) {
        Bytef* input = nullptr;
        string fullPath = "../../../scripts/compressTestDataset/" + fileName;
        uLong input_size = read_inputFile(input, fullPath.c_str());
        ASSERT_NE(input_size, (uLong)0);
        ASSERT_NE(input, nullptr);

        for (int m = 0; m < 3; ++m) {
            uLong compressed_size = compressBound(input_size) + 24;
            Bytef* compressed_data = new Bytef[compressed_size];
            common_compress(modes[m], Z_DEFAULT_COMPRESSION, input, input_size,
                            compressed_data, compressed_size);

            uLong decompressed_size = input_size + 1024;
            Bytef* decompressed_data = new Bytef[decompressed_size];
            common_uncompress(modes[m], compressed_data, compressed_size,
                              decompressed_data, decompressed_size);

            EXPECT_EQ(input_size, decompressed_size);
            EXPECT_EQ(memcmp(input, decompressed_data, input_size), 0);

            delete[] compressed_data;
            delete[] decompressed_data;
        }
        delete[] input;
    }
}

/*
 * 测试目的: 验证交替字节模式(0x00/0xFF)数据的压缩解压
 *          此模式测试LZ77匹配算法对特定重复模式的处理
 * 预期结果: 压缩解压成功
 * 测试数据: 32KB交替0x00和0xFF字节
 * 验证方法: 往返正确性
 */
TEST(DataSetTest, AlternatingBytePattern)
{
    const uLong data_length = 32UL * 1024;
    Bytef* data = new Bytef[data_length];
    for (uLong i = 0; i < data_length; ++i) {
        data[i] = (i % 2 == 0) ? 0x00 : 0xFF;
    }

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
