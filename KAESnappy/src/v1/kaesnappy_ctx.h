/*****************************************************************************
 * @file kaesnappy_ctx.h
 *
 * This file provides kaezip ctx control and driver compress funtion;
 *
 *****************************************************************************/

#ifndef KAESNAPPY_CTX_H
#define KAESNAPPY_CTX_H
#include <sys/time.h>
#include "wd_queue_memory.h"
#include "uadk/v1/wd_comp.h"

enum kaesnappy_comp_status {
    KAEZIP_COMP_INIT = 0,
    KAEZIP_COMP_DOING,
    KAEZIP_COMP_CRC_UNCHECK,
    KAEZIP_COMP_END_BUT_DATAREMAIN,
    KAEZIP_COMP_END,
    KAEZIP_COMP_VERIFY_ERR,
};

enum kaesnappy_decomp_status {
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

struct kaesnappy_ctx {
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
    int              status;        // enum kaesnappy_comp_status

    struct wcrypto_end_block        end_block;
    KAE_QUEUE_DATA_NODE_S*          q_node;
    struct wcrypto_comp_ctx_setup   setup;
    struct wcrypto_comp_op_data     op_data;
    struct wcrypto_lz77_zstd_format snappy_data;
    void*                           wd_ctx;
    void (*callback)(int status, void *param);
    void* param;
};
typedef struct kaesnappy_ctx   kaesnappy_ctx_t;

kaesnappy_ctx_t* kaesnappy_get_ctx(int alg_comp_type, int comp_optype);
void          kaesnappy_put_ctx(kaesnappy_ctx_t* kz_ctx);
void          kaesnappy_init_ctx(kaesnappy_ctx_t* kz_ctx);
void          kaesnappy_free_ctx(kaesnappy_ctx_t* kz_ctx);

void          kaesnappy_set_input_data(kaesnappy_ctx_t *kz_ctx);
void          kaesnappy_get_output_data(kaesnappy_ctx_t *kz_ctx);

int           kaesnappy_get_remain_data(kaesnappy_ctx_t *kz_ctx);
int           kaesnappy_driver_do_comp(kaesnappy_ctx_t *kaesnappy_ctx);
void          kaesnappy_free_all_qps(void);

#endif

