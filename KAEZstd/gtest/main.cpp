#include <gtest/gtest.h>

#include "func_common.h"

extern "C" {
    #include "kaezstd.h"
}

using namespace testing;

// input @oBuff: 待压缩数据
// input @cBuff: 压缩后数据
// input @dBuff: 解压后数据
static void FreeAllBuf(void *oBuff, void *cBuff, void *dBuff)
{
    free(oBuff);
    free(cBuff);
    free(dBuff);
}

TEST(functest_block, size_level_thread)
{
    const int size[] = {1000 /* 1k */, 1000 * 1000};
    const int clevel[] = {-5, -1, 0, 1, 5, 15, 22};
    const int nbThreads[] = {0, 1, 10, 100};

    for (int i = 0; i < sizeof(size) / sizeof(size[0]); ++i) {
        for (int j = 0; j < sizeof(clevel) / sizeof(clevel[0]); ++j) {
            for (int k = 0; k < sizeof(nbThreads) / sizeof(nbThreads[0]); ++k) {
                CompressOut cOut = DoCompress(size[i], clevel[j], nbThreads[k]);
                DecompressOut dOut = Decompress(cOut);
                
                ASSERT_EQ(cOut.oSize, dOut.dSize);
                for (int i = 0; i < cOut.oSize; ++i) {
                    EXPECT_EQ(((uint8_t *)(cOut.oBuff))[i], ((uint8_t *)(dOut.dBuff))[i]);
                }

                FreeAllBuf(cOut.oBuff, cOut.cBuff, dOut.dBuff);
            }
        }
    }
}

TEST(functest_stream, size_level_thread)
{
    const int size[] = {1000 /* 1k */, 1000 * 1000};
    const int clevel[] = {-5, -1, 0, 1, 5, 15, 22};
    const int nbThreads[] = {0, 1, 10, 100};

    for (int i = 0; i < sizeof(size) / sizeof(size[0]); ++i) {
        for (int j = 0; j < sizeof(clevel) / sizeof(clevel[0]); ++j) {
            for (int k = 0; k < sizeof(nbThreads) / sizeof(nbThreads[0]); ++k) {
                CompressOut cOut = DoCompressStream2(size[i], clevel[j], nbThreads[k]);
                DecompressOut dOut = DecompressStream(cOut);
                
                ASSERT_EQ(cOut.oSize, dOut.dSize);
                for (int i = 0; i < cOut.oSize; ++i) {
                    EXPECT_EQ(((uint8_t *)(cOut.oBuff))[i], ((uint8_t *)(dOut.dBuff))[i]);
                }

                FreeAllBuf(cOut.oBuff, cOut.cBuff, dOut.dBuff);
            }
        }
    }
}

TEST(functest_version, kaezstd_version)
{
    KAEZstdVersion ver;
    int ret = kaezstd_get_version(&ver);
    EXPECT_EQ(ret, 0);
    EXPECT_STREQ(ver.productName, "Kunpeng Boostkit");
    EXPECT_STREQ(ver.productVersion, "23.0.RC2");
    EXPECT_STREQ(ver.componentName, "KAEZstd");
    EXPECT_STREQ(ver.componentVersion, "2.0.0");
}

// 主函数
int main(int argc, char **argv)
{
    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}