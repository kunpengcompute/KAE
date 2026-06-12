
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
    #include <lz4_accelerater.h>
    #include "kaelz4_ctx.h"
    #include "kaelz4_comp.h"
    #include "kaelz4_log.h"
    extern void kaelz4_ctx_clear(struct kaelz4_async_ctrl *ctrl);
}

extern __thread struct kaelz4_async_ctrl g_async_ctrl;

TEST(kaelz4_ctx_clear_Test, empty_ctrl_is_safe)
{
    memset(&g_async_ctrl, 0, sizeof(g_async_ctrl));
    g_async_ctrl.ctx_num = 2;

    kaelz4_ctx_clear(&g_async_ctrl);

    for (int i = 0; i < 2; i++) {
        ASSERT_EQ(g_async_ctrl.kz_ctx[i], nullptr);
    }
}
