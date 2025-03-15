/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 *
 * Description:  This file provides common function for DH.
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

#ifndef HPRE_DH_UTILS_H
#define HPRE_DH_UTILS_H

#define HPRE_DH_SUCCESS 1
#define HPRE_DH_FAIL 0

#define CHECK_AND_GOTO(cond, goto_tag, log)	\
	do {					\
		if (cond) {			\
			US_WARN(log);		\
			goto goto_tag;		\
		}				\
	} while (0)

#endif
