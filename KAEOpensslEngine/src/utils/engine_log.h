/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description: This file provides the interface for log module
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KAE_ACC_ENGINE_LOG_H
#define KAE_ACC_ENGINE_LOG_H
#include <sys/file.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>


#define LOG_LEVEL_CONFIG KAE_NONE
#define KAE_DEBUG_FILE_PATH  "/var/log/kae.log"
#define KAE_DEBUG_FILE_PATH_OLD "/var/log/kae.log.old"
#define KAE_LOG_MAX_SIZE 209715200

enum KAE_LOG_LEVEL {
	KAE_NONE = 0,
	KAE_ERROR,
	KAE_WARNING,
	KAE_INFO,
	KAE_DEBUG,
};

void ENGINE_LOG_LIMIT(int level, int times, int limit, const char *fmt, ...);


#define US_WARN(fmt, args...)		ENGINE_LOG_LIMIT(KAE_WARNING, 3, 1, fmt, ##args)
#define US_ERR(fmt, args...)		ENGINE_LOG_LIMIT(KAE_ERROR, 3, 1, fmt, ##args)
#define US_INFO(fmt, args...)		ENGINE_LOG_LIMIT(KAE_INFO, 3, 1, fmt, ##args)
#define US_DEBUG(fmt, args...)		ENGINE_LOG_LIMIT(KAE_DEBUG, 3, 1, fmt, ##args)
#define US_WARN_LIMIT(fmt, args...)	ENGINE_LOG_LIMIT(KAE_WARNING, 3, 1, fmt, ##args)
#define US_ERR_LIMIT(fmt, args...)	ENGINE_LOG_LIMIT(KAE_ERROR, 3, 1, fmt, ##args)
#define US_INFO_LIMIT(fmt, args...)	ENGINE_LOG_LIMIT(KAE_INFO, 3, 1, fmt, ##args)
#define US_DEBUG_LIMIT(fmt, args...)	ENGINE_LOG_LIMIT(KAE_DEBUG, 3, 1, fmt, ##args)

void kae_debug_init_log(void);
void kae_debug_close_log(void);
void kae_save_log(FILE *src);

/*
 * desc: print data for debug
 * @param name the name of buf
 * @param buf  the buf msg when input
 * @param len bd len
 */
void dump_data(const char *name, unsigned char *buf, unsigned int len);

/*
 * desc: print bd for debug
 * @param bd  the buf msg when input
 * @param len bd len
 */
void dump_bd(unsigned int *bd, unsigned int len);

#endif
