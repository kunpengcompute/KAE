/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the wd queue management module
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

#include "wd_alg_queue.h"
#include "engine_log.h"

struct wd_queue* wd_new_queue(int algtype)
{
    struct wd_queue* queue = (struct wd_queue *)kae_malloc(sizeof(struct wd_queue));
    if (queue == NULL) {
        US_ERR("malloc failed");
        return NULL;
    }

    kae_memset(queue, 0, sizeof(struct wd_queue));

    switch (algtype) {
        case WCRYPTO_RSA:
            queue->capa.alg = "rsa";
            break;        
        case WCRYPTO_DH:
            queue->capa.alg = "dh";
            break;
        case WCRYPTO_CIPHER:
            queue->capa.alg = "cipher";
            break;
        case WCRYPTO_DIGEST:
            queue->capa.alg = "digest";
            break;
        case WCRYPTO_COMP:
        case WCRYPTO_EC:
        case WCRYPTO_RNG:
        default:
            US_WARN("not support algtype:%d", algtype);
            kae_free(queue);
            queue = NULL;
            return NULL;
    }
    
    int ret = wd_request_queue(queue);
    if (ret) {
        US_ERR("request wd queue fail!errno:%d", ret);
        kae_free(queue);
        queue = NULL;
        return NULL;
    }

    return queue;
}

void wd_free_queue(struct wd_queue* queue)
{
    if (queue != NULL) {
        wd_release_queue(queue);
        kae_free(queue);
        queue = NULL;
    }
}

