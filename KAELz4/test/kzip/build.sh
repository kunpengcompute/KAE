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

export LD_LIBRARY_PATH=/usr/local/kaelz4/lib:/usr/local/kaezstd/lib:/usr/local/kaezip/lib:$LD_LIBRARY_PATH
export C_INCLUDE_PATH=/usr/local/kaelz4/include:$C_INCLUDE_PATH

# echo "测试kaezip 和 kaelz4，请使用 sh build.sh kaelz4, 默认kaelz4"
# echo "测试kaezip 和 kaezstd，请使用 sh build.sh kaezstd"
# echo "测试qat，请使用 sh build.sh qat"

TestEnv=$1
TestEnv=${TestEnv:=kaelz4}
echo "build kzip for $TestEnv..."
case "$TestEnv" in
    kaelz4)
    gcc -g -o kzip main.c delayRecord.c datagen.c alg/manage.c alg/*/*.c scene_test_functions/*c -lz -lnuma -lrt -L/usr/local/kaelz4/lib -llz4 -DBUILD_ENV=$TestEnv -DBUILD_ENV_KAELZ4=1 -O3 -fstack-protector-all -Wall -Werror
    ;;
    *)
    ;;
esac

echo "build kzip done"
