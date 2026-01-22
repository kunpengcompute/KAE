/*
 * Copyright (C) 2019. Huawei Technologies Co., Ltd. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the zlib License.
 * You may obtain a copy of the License at
 *
 *     https://www.zlib.net/zlib_license.html
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * zlib License for more details.
 */

/*****************************************************************************
 * @file kaezip.h
 *
 * This file provides the interface for zlib;
 *
 *****************************************************************************/

#ifndef KAEZIP_H
#define KAEZIP_H
#include <stdint.h>
#include <stddef.h>
#include "zlib.h"
#include "kaezip_dev.h"

#define Z_CALL_SOFT 10

#define VERSION_STRUCT_MAXLEN 100
typedef struct {
    char productName[VERSION_STRUCT_MAXLEN];
    char productVersion[VERSION_STRUCT_MAXLEN];
    char componentName[VERSION_STRUCT_MAXLEN];
    char componentVersion[VERSION_STRUCT_MAXLEN];
} KAEZlibVersion;

#define KAE_ZLIB_SUCC 0
#define KAE_ZLIB_INVAL_PARA 1
#define KAE_ZLIB_INIT_FAIL 2
#define KAE_ZLIB_COMP_FAIL 3
#define KAE_ZLIB_RELEASE_FAIL 4
#define KAE_ZLIB_ALLOC_FAIL 5
#define KAE_ZLIB_SET_FAIL 6
#define KAE_ZLIB_HW_TIMEOUT_FAIL 7
#define KAE_ZLIB_DST_BUF_OVERFLOW 8
#define KAE_ZLIB_TASK_QUEUE_FULL 9

struct kaezip_result {
    int status;
    unsigned int rsvd;
    void *user_data;
    size_t src_size;
    size_t dst_len;
    uint32_t *ibuf_crc;
    uint32_t *obuf_crc;
};

struct kaezip_buffer {
    size_t buf_len;
    void *data;
};

struct kaezip_buffer_list {
    unsigned int buf_num;
    unsigned int rsvd;
    struct kaezip_buffer *buf;
    void *usr_data;
};

typedef void (*kaezip_async_callback)(struct kaezip_result *result);
typedef void *(*iova_map_fn)(void *usr, void *vaddr, size_t sz);
extern int kaezlib_get_version(KAEZlibVersion* ver);

extern int kz_get_devices(void);
extern int kz_deflate(z_streamp strm, int flush);
extern int kz_inflate(z_streamp strm, int flush);
extern int kz_inflateEnd(z_streamp strm);
extern int kz_deflateInit2_(z_streamp strm, int level, int metho, int windowBit, int memLevel, int strategy,
                       const char *version, int stream_size);
extern int kz_inflateInit2_(z_streamp strm, int windowBits, const char *version, int stream_size);
extern int kz_deflateEnd(z_streamp strm);
extern int kz_inflateReset(z_streamp strm);
extern int kz_deflateReset(z_streamp strm);
extern int kz_getAutoInflateAlgType(z_streamp strm);
extern int kz_do_inflateInit(z_streamp strm, int alg_comp_type);

extern int lz_deflate(z_streamp strm, int flush);
extern int lz_deflateEnd(z_streamp strm);
extern int lz_deflateInit2_(z_streamp strm, int level, int metho, int windowBit, int memLevel, int strategy,
                      const char *version, int stream_size);
extern int lz_deflateReset(z_streamp strm);

extern int lz_inflate(z_streamp strm, int flush);
extern int lz_inflateEnd(z_streamp strm);
extern int lz_inflateInit2_(z_streamp strm, int windowBits, const char *version, int stream_size);
extern int lz_inflateReset(z_streamp strm);

extern int getInflateStateWrap(z_streamp strm);
extern unsigned long getInflateKaezipCtx(z_streamp strm);
extern void setInflateKaezipCtx(z_streamp strm, unsigned long kaezip_ctx);
extern unsigned long getDeflateKaezipCtx(z_streamp strm);
extern void setDeflateKaezipCtx(z_streamp strm, unsigned long kaezip_ctx);
/**
 * @brief: block compress async api
 * @param: sess : session
 * @param: src [IN] : input data, up to 255 SGES, each physically contiguous and ≤8 MB in size.
 * @param: dst [OUT] : output data, up to 255 SGES, each physically contiguous and ≤8 MB in size.
 * @param: callback [IN] : async callback function,it can not be NULL, must be typedef void (*kaezip_async_callback)(struct kaezip_result *result).
 * @param: result [IN OUT] : async callback  result,it can not be NULL. must be pointer of struct kaezip_result.
 * @return: 0 success, other fail
 */
int KAEZIP_compress_async_in_session(void *sess, const struct kaezip_buffer_list *src, struct kaezip_buffer_list *dst,
                                     kaezip_async_callback callback, struct kaezip_result *result);
/**
 * @brief: Polling hardware result in session.
 * @param: sess : session.
 * @param: budget : process packet num per call.
 */
 void KAEZIP_async_polling_in_session(void *sess, int budget);

/**
 * @brief: Initialize Task Queues and Threads on the KAE Side.
 * @param: usr_map : function to translate src/dst buf's VA to PA/IOVA.
 * @param: config : pointer to device configuration structure used to select KAE device.
 * @return: session, NULL if fail.
 */
void *KAEZIP_create_async_compress_session(iova_map_fn usr_map, const device_config_t *config);

/**
 * @brief: Destroy session and hardware ctx.
 * @param: sess : session.
 */
void KAEZIP_destroy_async_compress_session(void *sess);

/**
 * @brief: Initialize Task Queues and Threads on the KAE Side for decompress.
 * @param: usr_map : function to translate src/dst buf's VA to PA/IOVA.
 * @param: config : pointer to device configuration structure used to select KAE device.
 * @return: session, NULL if fail.
 */
void *KAEZIP_create_async_decompress_session(iova_map_fn usr_map, const device_config_t *config);

/**
 * @brief: Destroy decompress session and hardware ctx.
 * @param: sess : session.
 */
void KAEZIP_destroy_async_decompress_session(void *sess);

/**
 * @brief: block decompress async api
 * @param: sess : session.
 * @param: src [IN] : input data, up to 255 SGES, each physically contiguous and ≤8 MB in size.
 * @param: dst [OUT] : output data, up to 255 SGES, each physically contiguous and ≤8 MB in size.
 * @param: callback [IN] : async callback function,it can not be NULL, must be typedef void (*kaezip_async_callback)(struct kaezip_result *result).
 * @param: result [IN OUT] : async callback  result,it can not be NULL. must be pointer of struct kaezip_result.
 * @return: 0 success, other fail.
 */
int KAEZIP_decompress_async_in_session(void *sess, const struct kaezip_buffer_list *src, struct kaezip_buffer_list *dst,
                                       kaezip_async_callback callback, struct kaezip_result *result);
/**
 * @brief: reset session and hardware ctx, all compress tasks will be canceled.
 * @param: sess : session.
 */
void KAEZIP_reset_session(void *sess);

/**
 * @brief: Initialize Task Queues and Threads on the KAE Side with zlib format.
 * @param: usr_map : function to translate src/dst buf's VA to PA/IOVA.
 * @param: config : pointer to device configuration structure used to select KAE device.
 * @param: level : an integer from 0 to 9 or -1 controlling the level of compression.
 * @param: windowBits : an integer from 8 to 15 to control the size of sliding window.
 * @return: session, NULL if fail.
 */
void *KAEZIP_create_async_compress_session_zlib(iova_map_fn usr_map, const device_config_t *config, int level, int windowBits);
      
/**
 * @brief: Initialize Task Queues and Threads on the KAE Side for decompress with zlib format.
 * @param: usr_map : function to translate src/dst buf's VA to PA/IOVA.
 * @param: config : pointer to device configuration structure used to select KAE device.
 * @return: session, NULL if fail.
 */
void *KAEZIP_create_async_decompress_session_zlib(iova_map_fn usr_map, const device_config_t *config);

/**
 * @brief: retrieve the list of available ZIP accelerator devices.
 * @param: num [out] : pointer to store the number of devices.
 * @return: pointer to an array of device descriptors.
 */
const struct zip_dev *KAEZIP_get_devices(unsigned int *num);
#endif
