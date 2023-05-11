/*
 * Copyright 2020-2022 Huawei Technologies Co.,Ltd. All rights reserved.
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
 *
 */
#include "v2/utils/uadk_utils.h"

#if defined(__AARCH64_CMODEL_SMALL__) && __AARCH64_CMODEL_SMALL__

#define  UADK_MEM_IMPROVE_THRESHOLD 1024

static void *memcpy_large(void *dstpp, const void *srcpp, size_t len)
{
	__asm__ __volatile__(
			"add x4, %[src], %[count]\n\t"
			"add x5, %[res], %[count]\n\t"
			"ldr q0, [%[src]]\n\t"
			"str q0, [%[res]]\n\t"
			"sub %[count], %[count], 80\n\t"
			"and x14, %[src], 15\n\t"
			"bic %[src], %[src], 15\n\t"
			"sub x3, %[res], x14\n\t"
			"add %[count], %[count], x14\n\t"

			"1:\n\t"
			"ldp q0, q1, [%[src], 16]\n\t"
			"stp q0, q1, [x3, 16]\n\t"
			"ldp q0, q1, [%[src], 48]\n\t"
			"stp q0, q1, [x3, 48]\n\t"
			"add %[src], %[src], 64\n\t"
			"add x3, x3, 64\n\t"
			"subs %[count], %[count], 64\n\t"
			"b.hi 1b\n\t"

			"ldp q0, q1, [x4, -64]\n\t"
			"stp q0, q1, [x5, -64]\n\t"
			"ldp q0, q1, [x4, -32]\n\t"
			"stp q0, q1, [x5, -32]\n\t"

			: [res] "+r"(dstpp)
			: [src] "r"(srcpp), [count] "r"(len)
			  : "x3", "x4", "x5", "x14", "q0", "q1"
				  );

	return dstpp;
}

void *uadk_memcpy(void *dstpp, const void *srcpp, size_t len)
{
	if (len >= UADK_MEM_IMPROVE_THRESHOLD)
		return memcpy_large(dstpp, srcpp, len);
	else
		return memcpy(dstpp, srcpp, len);
}

#else

void *uadk_memcpy(void *dstpp, const void *srcpp, size_t len)
{
	return memcpy(dstpp, srcpp, len);
}

#endif
