#include <stdio.h>

// Declare test functions
void test_async_frame_with_perferences_0();
void test_async_frame_with_perferences_1();
void test_async_frame_with_perferences_2();
void test_async_frame_with_perferences_3();
void test_async_frame_with_perferences_4();

typedef struct {
    const char *test_name;
    void (*test_func)(void);
} test_case_t;

test_case_t test_cases[] = {
    {"异步frame压缩 基本没有参数测试", test_async_frame_with_perferences_0},
    {"异步frame压缩带 contentChecksum 测试", test_async_frame_with_perferences_1},
    {"异步frame压缩带 blockChecksum 测试", test_async_frame_with_perferences_2},
    {"异步frame压缩带 contentSize 测试", test_async_frame_with_perferences_3},
    {"异步frame压缩带 blockChecksum 和 contentChecksum 和 contentSize 测试", test_async_frame_with_perferences_4},
};

#define NUM_TESTS (sizeof(test_cases) / sizeof(test_case_t))

int scene_tests_run()
{
    for (int i = 0; i < NUM_TESTS; i++) {
        printf("Running: %s\n", test_cases[i].test_name);
        test_cases[i].test_func();
    }
    return 0;
}