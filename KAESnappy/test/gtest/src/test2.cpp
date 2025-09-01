
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
    #include "kaelz4.h"
    #include <lz4.h>
    #include <lz4frame.h>
    #include "kaelz4_ctx.h"
    #include "kaelz4_comp.h"
    #include "kaelz4_log.h"
    extern void kaelz4_ctx_clear(void);
}

extern __thread struct kaelz4_async_ctrl g_async_ctrl;

TEST(kaelz4_ctx_clear_Test, is_test_g_async_ctrl_all_clean)
{
    int ret = 0;
    kaelz4_ctx_t *kzctx = (kaelz4_ctx_t *)malloc(sizeof(kaelz4_ctx_t));
    g_async_ctrl.kz_ctx[0] = kzctx;
    kaelz4_init_ctx(g_async_ctrl.kz_ctx[0]);
    for (int i = 0; i < 2; i++) {
        if (g_async_ctrl.kz_ctx[i] != NULL) {
            ret++;
        }
    }
    ASSERT_EQ(ret, 1);

    kaelz4_ctx_clear();

    ret = 0;
    for (int i = 0; i < 2; i++) {
        if (g_async_ctrl.kz_ctx[i] != NULL) {
            ret++;
        }
    }
    ASSERT_EQ(ret, 0);
}
