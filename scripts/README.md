# scripts
- 此目录下为编译、构建、测试需要的patch文件等，不涉及开源组件。

Ubuntu ARM64 / OpenSSL 3.0 出包使用 `bash build.sh debpack`，打包文件保存在
`scripts/debian/`。入口会在 `kae_output/debpack/` 下的独立源码副本中展开标准
`debian/` 布局；同步到 Ubuntu 仓库时，将打包目录移到该仓库根目录。
产物和构建目录保留在本次 `kae_output/debpack/run.XXXXXX/` 中，不受 RPM 构建清理
`kae_build/` 的影响，不再需要时可手动删除。Ubuntu 仓库已有
根目录 `debian/` 时，入口直接调用标准构建，产物输出到源码目录上一层。
同步时只维护一份打包配置，合并 Ubuntu 仓库已有的 changelog、版本号和发行版修改。
设置相对路径 `KERNEL_DIR` 时，以调用命令时的工作目录为基准；路径不存在或不可访问时，
入口会在准备构建目录前报错，并提示检查路径及匹配的内核头文件。
