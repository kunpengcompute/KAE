# scripts
- 此目录下为编译、构建、测试需要的patch文件等，不涉及开源组件。

KAE 发布版本统一保存在根目录 `VERSION`（`主版本.次版本.修订版本`）。升级时只修改
这个文件，直接重新构建即可。4 个 KAE 压缩库的文件名、OpenSSL/BoringSSL 引擎的
libtool 版本和 RPM/DEB 使用的 KAE 版本均从 `VERSION` 派生。4 个压缩库的
`*_get_version()` 将该 KAE 发布版本同时填入 `productVersion` 和 `componentVersion`。
上游适配补丁中的 KAE 链接名占位符也会在组件构建脚本应用补丁时展开。
版本变化会触发增量重编译或重新链接，不需要手动清理或编辑各子库。
BoostKit 套件自身的发行版本独立维护。UADK、内核驱动及第三方上游库也各自维护版本。
历史发布记录按原发布版本保留。

RPM 使用 `bash build.sh rpmpack`：两个 spec 文件是模板，入口按 `VERSION` 渲染后在
`kae_build/rpmpack/run.XXXXXX/` 内构建二进制包及源码包，二进制包同时复制到 `kae_build/`。
构建只写入暂存目录，不安装或卸载构建机已有组件。

Ubuntu ARM64 / OpenSSL 3.0 出包使用 `bash build.sh debpack`，打包文件保存在
`scripts/debian/`。入口会在 `kae_output/debpack/` 下的独立源码副本中展开标准
`debian/` 布局；同步到 Ubuntu 仓库时，将打包目录移到该仓库根目录。
产物和构建目录保留在本次 `kae_output/debpack/run.XXXXXX/` 中，不受 RPM 构建清理
`kae_build/` 的影响，不再需要时可手动删除。Ubuntu 仓库已有
根目录 `debian/` 时，入口直接调用标准构建，产物输出到源码目录上一层。
同步时只维护一份打包配置，保留 Ubuntu 仓库已有的 Debian 修订号和发行版修改。
`debpack` 会在调用 `dpkg-buildpackage` 前同步 KAE 上游版本；版本变化时新增 changelog
条目，保留原有历史。直接使用 `dpkg-buildpackage` 前，先执行
`python3 debian/prepare-version.py`。
设置相对路径 `KERNEL_DIR` 时，以调用命令时的工作目录为基准；路径不存在或不可访问时，
入口会在准备构建目录前报错，并提示检查路径及匹配的内核头文件。
