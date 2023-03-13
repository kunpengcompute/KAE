#include <gtest/gtest.h>
using namespace testing;

// 主函数
int main(int argc, char **argv)
{
    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}