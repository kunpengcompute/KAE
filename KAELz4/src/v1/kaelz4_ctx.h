/*****************************************************************************
 * @file kaelz4_ctx.h
 *
 * This file provides kaezip ctx control and driver compress funtion;
 *
 *****************************************************************************/

#ifndef KAELZ4_CTX_H
#define KAELZ4_CTX_H
#include <sys/time.h>
#include "wd_queue_memory.h"
#include "uadk/v1/wd_comp.h"

#define MAX_KAE_CTX_DEPTH 64
#define REQ_BUFFER_MAX 60   // uadk支持最大的sgl buf数量

enum kaelz4_comp_status {
    KAEZIP_COMP_INIT = 0,
    KAEZIP_COMP_DOING,
    KAEZIP_COMP_CRC_UNCHECK,
    KAEZIP_COMP_END_BUT_DATAREMAIN,
    KAEZIP_COMP_END,
    KAEZIP_COMP_VERIFY_ERR,
};

enum kaelz4_decomp_status {
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

struct kaelz4_ctx {
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
    int              status;        // enum kaelz4_comp_status
    unsigned int     index;

    struct wcrypto_end_block        end_block;
    KAE_QUEUE_DATA_NODE_S           *q_node;
    struct wcrypto_comp_ctx_setup   *setup;
    struct wcrypto_comp_op_data     op_data;
    struct wcrypto_lz77_zstd_format lz4_data;
    void*                           wd_ctx;
    struct wcrypto_zstd_out         output;
    wd_map                          usr_map;
    unsigned char                   src_sgl_buf[32 + (32 * (REQ_BUFFER_MAX + 1))];   // 32: sizeof(struct wd_sgl) + sizeof(struct wd_sge) * 60 + 1 * sizeof(struct wd_sge) for hisi_sge
    unsigned char                   dst_sgl_buf[32 + (32 * (REQ_BUFFER_MAX + 1))];   // 32: sizeof(struct wd_sgl) + sizeof(struct wd_sge) * 60 + 1 * sizeof(struct wd_sge) for hisi_sge
    void                            *src_sgl;
    void                            *dst_sgl_usr;
    void                            *dst_sgl_kernel;
    void (*callback)(int status, void *param);
    void* param;
};

struct kaelz4_instance {
    KAE_QUEUE_DATA_NODE_S *q_node;
    void *wd_ctx;
    struct kaelz4_ctx *kz_ctx[MAX_KAE_CTX_DEPTH];
    struct wcrypto_comp_ctx_setup setup;
    unsigned int total_num;
    unsigned int cur_idx;
    unsigned int free_num;
};

typedef struct kaelz4_ctx   kaelz4_ctx_t;

kaelz4_ctx_t* kaelz4_get_ctx(int alg_comp_type, int comp_optype, int is_sgl);
void          kaelz4_put_ctx(kaelz4_ctx_t* kz_ctx);
void          kaelz4_init_ctx(kaelz4_ctx_t* kz_ctx);
void          kaelz4_free_ctx(kaelz4_ctx_t* kz_ctx);

void          kaelz4_set_input_data(kaelz4_ctx_t *kz_ctx);
void          kaelz4_get_output_data(kaelz4_ctx_t *kz_ctx);

int           kaelz4_get_remain_data(kaelz4_ctx_t *kz_ctx);
int           kaelz4_driver_do_comp(kaelz4_ctx_t *kaelz4_ctx);
void          kaelz4_free_all_qps(void);

#endif

