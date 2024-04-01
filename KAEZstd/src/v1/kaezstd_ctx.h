/*****************************************************************************
 * @file kaezstd_ctx.h
 *
 * This file provides kaezip ctx control and driver compress funtion;
 *
 *****************************************************************************/

#ifndef KAEZIP_CTX_H
#define KAEZIP_CTX_H
#include <sys/time.h>
#include "wd_queue_memory.h"
#include "uadk/v1/wd_comp.h"

enum kaezip_comp_status {
    KAEZIP_COMP_INIT = 0,
    KAEZIP_COMP_DOING,
    KAEZIP_COMP_CRC_UNCHECK,
    KAEZIP_COMP_END_BUT_DATAREMAIN,
    KAEZIP_COMP_END,
    KAEZIP_COMP_VERIFY_ERR,
};

enum kaezip_decomp_status {
    KAEZIP_DECOMP_INIT = 0,
    KAEZIP_DECOMP_DOING,
    KAEZIP_DECOMP_END_BUT_DATAREMAIN,
    KAEZIP_DECOMP_END,
    KAEZIP_DECOMP_VERIFY_ERR,
};

struct wcrypto_end_block {
    char             buffer[32];
    unsigned int     data_len;
    unsigned int     remain;
    unsigned int     b_set;
};

struct kaezip_ctx {
    void            *in;
    unsigned int    in_len;
    void            *out;
    unsigned int     avail_out;
    unsigned int     consumed;
    unsigned int     produced;
    unsigned int     remain;        //data produced by warpdrive but haven't been take away for not enough avail out buf

    int              flush;         // WCRYPTO_SYNC_FLUSH / WCRYPTO_FINISH
    int              comp_alg_type; // WCRYPTO_LZ77_ZSTD
    int              comp_type;     // WCRYPTO_DEFLATE / WCRYPTO_INFLATE
    unsigned int     do_comp_len;   // a compress proccess cost len
    int              status;        // enum kaezip_comp_status

    struct wcrypto_end_block        end_block;
    KAE_QUEUE_DATA_NODE_S*          q_node;
    struct wcrypto_comp_ctx_setup   setup;
    struct wcrypto_comp_op_data     op_data;
    struct wcrypto_lz77_zstd_format zstd_data;
    void*                           wd_ctx;
};
typedef struct kaezip_ctx   kaezip_ctx_t;

kaezip_ctx_t* kaezip_get_ctx(int alg_comp_type, int comp_optype);
void          kaezip_put_ctx(kaezip_ctx_t* kz_ctx);
void          kaezip_init_ctx(kaezip_ctx_t* kz_ctx);
void          kaezip_free_ctx(void* kz_ctx);

void          kaezip_set_input_data(kaezip_ctx_t *kz_ctx);
void          kaezip_get_output_data(kaezip_ctx_t *kz_ctx);

int           kaezip_get_remain_data(kaezip_ctx_t *kz_ctx);
int           kaezip_driver_do_comp(kaezip_ctx_t *kaezip_ctx);

#endif

