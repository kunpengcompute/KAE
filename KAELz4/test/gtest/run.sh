#!/bin/bash
# Copyright (c) 2026 Huawei Technologies Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

export LD_LIBRARY_PATH=/usr/local/kaelz4/lib/:/usr/local/kaezstd/lib/:/usr/local/kaezip/lib/:${LD_LIBRARY_PATH:-}
export KAE_LZ4_WINTYPE=8
export KAE_LZ4_COMP_TYPE=8

sh "${SCRIPT_DIR}/build.sh"

exec "${SCRIPT_DIR}/kaelz4test" "$@"
