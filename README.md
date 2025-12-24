# 项目介绍

鲲鹏加速引擎（KAE）是基于鲲鹏处理器提供的硬件加速解决方案，包含了 KAE 加解密和 KAE 解压缩两个模块，分别用于加速 SSL/TLS 应用和数据压缩，可以显著降低处理器消耗，提高处理器效率。此外，加速引擎对应用层屏蔽了其内部实现细节，用户通过 OpenSSL、zlib标准接口即可以实现快速迁移现有业务。

# 版本说明

鲲鹏加速引擎（KAE）是一款基于鲲鹏 920 处理器研发的加速器。由于不同内核版本的差异，KAE 存在两套代码用于支持不同的内核代码，分别是 KAE1.0 和 KAE2.0 两套代码分支。其中，KAE1.0 适用于 4.19 内核；而 KAE2.0 适用于 5.X 内核（其中TOS适配了5.4内核版本）。

**表 1**  KAE支持版本

<table><thead align="left"><tr id="row1282443814467"><th class="cellrowborder" valign="top" width="25%" id="mcps1.2.5.1.1"><p id="p1682563815463"><a name="p1682563815463"></a><a name="p1682563815463"></a>内核版本<sup id="sup714911196507"><a name="sup714911196507"></a><a name="sup714911196507"></a>[1]</sup></p>
</th>
<th class="cellrowborder" valign="top" width="25%" id="mcps1.2.5.1.2"><p id="p19825438174616"><a name="p19825438174616"></a><a name="p19825438174616"></a>设备形态</p>
</th>
<th class="cellrowborder" valign="top" width="25%" id="mcps1.2.5.1.3"><p id="p38259381468"><a name="p38259381468"></a><a name="p38259381468"></a>KAE 1.0</p>
</th>
<th class="cellrowborder" valign="top" width="25%" id="mcps1.2.5.1.4"><p id="p188251738134612"><a name="p188251738134612"></a><a name="p188251738134612"></a>KAE 2.0</p>
</th>
</tr>
</thead>
<tbody><tr id="row182593854618"><td class="cellrowborder" valign="top" width="25%" headers="mcps1.2.5.1.1 "><p id="p108255381469"><a name="p108255381469"></a><a name="p108255381469"></a>4.19</p>
</td>
<td class="cellrowborder" valign="top" width="25%" headers="mcps1.2.5.1.2 "><p id="p158251382464"><a name="p158251382464"></a><a name="p158251382464"></a>920/920X<sup id="sup1855193634913"><a name="sup1855193634913"></a><a name="sup1855193634913"></a>[2]</sup></p>
</td>
<td class="cellrowborder" valign="top" width="25%" headers="mcps1.2.5.1.3 "><p id="p882543811469"><a name="p882543811469"></a><a name="p882543811469"></a>YES</p>
</td>
<td class="cellrowborder" valign="top" width="25%" headers="mcps1.2.5.1.4 "><p id="p98253385469"><a name="p98253385469"></a><a name="p98253385469"></a>NA</p>
</td>
</tr>
<tr id="row11825183811467"><td class="cellrowborder" valign="top" width="25%" headers="mcps1.2.5.1.1 "><p id="p16825123811466"><a name="p16825123811466"></a><a name="p16825123811466"></a>5.4</p>
</td>
<td class="cellrowborder" valign="top" width="25%" headers="mcps1.2.5.1.2 "><p id="p882583814615"><a name="p882583814615"></a><a name="p882583814615"></a>920/920X</p>
</td>
<td class="cellrowborder" valign="top" width="25%" headers="mcps1.2.5.1.3 "><p id="p68251385467"><a name="p68251385467"></a><a name="p68251385467"></a>NA</p>
</td>
<td class="cellrowborder" valign="top" width="25%" headers="mcps1.2.5.1.4 "><p id="p18251238124611"><a name="p18251238124611"></a><a name="p18251238124611"></a>YES</p>
</td>
</tr>
<tr id="row882553812462"><td class="cellrowborder" valign="top" width="25%" headers="mcps1.2.5.1.1 "><p id="p11825238164616"><a name="p11825238164616"></a><a name="p11825238164616"></a>5.10</p>
</td>
<td class="cellrowborder" valign="top" width="25%" headers="mcps1.2.5.1.2 "><p id="p3825113814612"><a name="p3825113814612"></a><a name="p3825113814612"></a>920/920X</p>
</td>
<td class="cellrowborder" valign="top" width="25%" headers="mcps1.2.5.1.3 "><p id="p4825138194612"><a name="p4825138194612"></a><a name="p4825138194612"></a>NA</p>
</td>
<td class="cellrowborder" valign="top" width="25%" headers="mcps1.2.5.1.4 "><p id="p138259386468"><a name="p138259386468"></a><a name="p138259386468"></a>YES</p>
</td>
</tr>
</tbody>
</table>

\[1\]由于不同版本内核接口可能存在差异，不同的操作系统使能KAE需要实际编译内核驱动验证是否匹配，若特定OS内核编译KAE驱动遇到接口报错，则说明驱动不兼容。

\[2\]KAE 1.0代码分支不支持920X机器，需要使用kae1\_for\_920X代码分支

# 环境部署

根据芯片款型及内核版本选择适合的KAE代码进行安装，安装前需要确定环境信息及安装license。




## License安装

安装鲲鹏KAE加速引擎之前需要先安装相应的License，License安装成功之后，操作系统才能识别到加速器设备。

TaiShan K系列服务器硬件KAE加速引擎已默认开启，无需申请License。 920新型号后续更新BIOS可以免license使用，具体BIOS版本待发布再更新

具体License申请使用操作可参考《[华为服务器iBMC许可证 使用指导](https://gitee.com/link?target=https%3A%2F%2Fsupport.huawei.com%2Fenterprise%2Fzh%2Fmanagement-software%2Fibmc-pid-8060757%3Fcategory%3Doperation-maintenance)》。

通过lspci命令进行查看操作系统是否有加速器设备，如下所示。

```
lspci | grep HPRE 
79:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon HPRE Engine (rev 21) 
b9:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon HPRE Engine (rev 21)  

lspci | grep ZIP 
75:00.0 Processing accelerators: Huawei Technologies Co., Ltd. HiSilicon ZIP Engine (rev 21) 
b5:00.0 Processing accelerators: Huawei Technologies Co., Ltd. HiSilicon ZIP Engine (rev 21)  

lspci | grep SEC 
76:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon SEC Engine (rev 21) 
b6:00.0 Network and computing encryption device: Huawei Technologies Co., Ltd. HiSilicon SEC Engine (rev 21)
```

## 软件包获取

基于硬件cpu款型及内核OS情况，选择正确的KAE版本后，再获取软件包，用于后续安装。

**表 1**  软件包获取列表

<table><thead align="left"><tr id="row7334111611818"><th class="cellrowborder" valign="top" width="33.33333333333333%" id="mcps1.2.4.1.1"><p id="p033413161985"><a name="p033413161985"></a><a name="p033413161985"></a>KAE版本</p>
</th>
<th class="cellrowborder" valign="top" width="33.33333333333333%" id="mcps1.2.4.1.2"><p id="p133349161082"><a name="p133349161082"></a><a name="p133349161082"></a>软件包类型</p>
</th>
<th class="cellrowborder" valign="top" width="33.33333333333333%" id="mcps1.2.4.1.3"><p id="p20334131614814"><a name="p20334131614814"></a><a name="p20334131614814"></a>获取方式</p>
</th>
</tr>
</thead>
<tbody><tr id="row143345165812"><td class="cellrowborder" rowspan="2" valign="top" width="33.33333333333333%" headers="mcps1.2.4.1.1 "><p id="p3334191611813"><a name="p3334191611813"></a><a name="p3334191611813"></a><span>KAE2.0（v2.x.x）</span></p>
<p id="p16334116587"><a name="p16334116587"></a><a name="p16334116587"></a></p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.2.4.1.2 "><p id="p1133414164815"><a name="p1133414164815"></a><a name="p1133414164815"></a><span>源码包</span></p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.2.4.1.3 "><p id="p13334151618810"><a name="p13334151618810"></a><a name="p13334151618810"></a><a href="https://gitee.com/kunpengcompute/KAE/tree/kae2/" target="_blank" rel="noopener noreferrer">获取链接</a></p>
</td>
</tr>
<tr id="row1133417161088"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p13334151619817"><a name="p13334151619817"></a><a name="p13334151619817"></a><span>RPM包</span></p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p1633491615811"><a name="p1633491615811"></a><a name="p1633491615811"></a><a href="https://gitee.com/kunpengcompute/KAE/releases" target="_blank" rel="noopener noreferrer">获取链接</a></p>
</td>
</tr>
<tr id="row1433412160813"><td class="cellrowborder" rowspan="3" valign="top" width="33.33333333333333%" headers="mcps1.2.4.1.1 "><p id="p143341516685"><a name="p143341516685"></a><a name="p143341516685"></a><span>KAE1.0（v1.x.x）</span></p>
<p id="p93341216985"><a name="p93341216985"></a><a name="p93341216985"></a></p>
<p id="p633419164818"><a name="p633419164818"></a><a name="p633419164818"></a></p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.2.4.1.2 "><p id="p14334916382"><a name="p14334916382"></a><a name="p14334916382"></a><span>源码包</span></p>
</td>
<td class="cellrowborder" valign="top" width="33.33333333333333%" headers="mcps1.2.4.1.3 "><p id="p6334131614815"><a name="p6334131614815"></a><a name="p6334131614815"></a><a href="https://gitee.com/kunpengcompute/KAE/tree/kae1/" target="_blank" rel="noopener noreferrer">获取链接</a></p>
</td>
</tr>
<tr id="row333415161582"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p183341816786"><a name="p183341816786"></a><a name="p183341816786"></a><span>RPM包</span></p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p1233415161084"><a name="p1233415161084"></a><a name="p1233415161084"></a><a href="https://gitee.com/kunpengcompute/KAE/releases" target="_blank" rel="noopener noreferrer">获取链接</a></p>
</td>
</tr>
<tr id="row1733414165811"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p133414163814"><a name="p133414163814"></a><a name="p133414163814"></a><span>DEB包</span></p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p6334216883"><a name="p6334216883"></a><a name="p6334216883"></a><a href="https://gitee.com/kunpengcompute/KAE/releases" target="_blank" rel="noopener noreferrer">获取链接</a></p>
</td>
</tr>
<tr id="row1433420163811"><td class="cellrowborder" colspan="3" valign="top" headers="mcps1.2.4.1.1 mcps1.2.4.1.2 mcps1.2.4.1.3 "><p id="p92251542142220"><a name="p92251542142220"></a><a name="p92251542142220"></a><span>注：历史版本软件包请通过</span><a href="https://gitee.com/kunpengcompute/KAE/releases" target="_blank" rel="noopener noreferrer">Release</a><span>获取。软件包名称使用OS命名，请根据实际使用的OS选择合适的软件包。例如：kae-1.3.12-1.centos7.6.aarch64.rar为KAE1.0适配CentOS 7.6的RPM安装包。</span></p>
</td>
</tr>
</tbody>
</table>

## KAE 2.0安装

KAE提供源码安装和RPM包安装两种方式，安装指南详见[《鲲鹏加速引擎用户指南》](https://www.hikunpeng.com/document/detail/zh/kunpengaccel/kae/usermanual/kunpengaccel_06_0007.html)。

# 快速上手

## 查看KAEOpensslEngine加速引擎是否生效

以验证RSA性能为例，验证步骤请参见[测试同步RSA性能](https://www.hikunpeng.com/document/detail/zh/kunpengaccel/kae/usermanual/kunpengaccel_06_0019.html#ZH-CN_TOPIC_0000002327524289__section54081455216)，通过RSA性能命令可以看到指定KAE引擎之后，RSA的性能得到明显提升。

除上述方法，在执行RSA性能命令过程中，可以在新的终端上同时查看hisi\_hpre设备的硬件队列资源情况如下，相同地，SM3/SM4算法可以查看hisi\_sec2的硬件队列消耗情况。

```
cat /sys/class/uacce/hisi_hpre-*/available_instances
```

您也可以通过以下命令每0.1秒刷新一次，实时查看hisi\_hpre的硬件队列消耗情况。

```
watch -n 0.1 cat /sys/class/uacce/hisi_hpre-*/available_instances
```

查看zlib加速压缩库是否安装成功

```
ll /usr/local/kaezip/lib/
```

回显信息如下，表示安装成功

```
lrwxrwxrwx. 1 root root     40 Aug 29 10:20 libkaezip.so -> /usr/local/kaezip/lib/libkaezip.so.2.0.0
lrwxrwxrwx. 1 root root     40 Aug 29 10:20 libkaezip.so.0 -> /usr/local/kaezip/lib/libkaezip.so.2.0.0
-rwxr-xr-x. 1 root root 148096 Aug 29 10:20 libkaezip.so.2.0.0
-rw-r--r--. 1 root root 145674 Aug 29 10:20 libz.alrwxrwxrwx. 1 root root     14 Aug 29 10:20 libz.so -> libz.so.1.2.11
lrwxrwxrwx. 1 root root     14 Aug 29 10:20 libz.so.1 -> libz.so.1.2.11
-rwxr-xr-x. 1 root root 144784 Aug 29 10:20 libz.so.1.2.11
drwxr-xr-x. 2 root root   4096 Aug 29 10:20 pkgconfig
```

## 查看KAEZlib库加速引擎是否生效

过ldd命令查看KAEZlib加速库是否链接到libwd库。

```
ldd /usr/local/kaezip/lib/libz.so.1.2.11
```

如果有如下返回信息，说明KAEZlib加速库安装成功。

```
linux-vdso.so.1 (0x0000ffff89774000)        
libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffff896b5000)
libkaezip.so => /usr/local/kaezip/lib/libkaezip.so (0x0000ffffa60df000)
libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffff89684000)        
libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffff894d5000)        
/lib/ld-linux-aarch64.so.1 (0x0000ffff89737000)        
libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffff894b0000)
```

## 查看KAEZstd库加速引擎是否生效

过ldd命令查看KAEZstd加速库是否链接到libwd库。

```
ldd /usr/local/kaezstd/lib/libkaezstd.so
```

如果有如下返回信息，说明KAEZstd加速库安装成功。

```
linux-vdso.so.1 (0x0000ffff89774000)        
libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffff896b5000)        
libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffff89684000)        
libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffff894d5000)        
/lib/ld-linux-aarch64.so.1 (0x0000ffff89737000)        
libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffff894b0000)
```

## 查看KAELz4库加速引擎是否生效

过ldd命令查看KAELz4加速库是否链接到libwd库。

```
ldd /usr/local/kaezstd/lib/libkaelz4.so
```

如果有如下返回信息，说明KAEZstd加速库安装成功。

```
linux-vdso.so.1 (0x0000ffff89774000)        
libwd.so.2 => /usr/local/lib/libwd.so.2 (0x0000ffff896b5000)        
libwd_comp.so.2 => /usr/local/lib/libwd_comp.so.2 (0x0000ffff89684000)        
libc.so.6 => /usr/lib64/libc.so.6 (0x0000ffff894d5000)        
/lib/ld-linux-aarch64.so.1 (0x0000ffff89737000)        
libnuma.so.1 => /usr/lib64/libnuma.so.1 (0x0000ffff894b0000)
```

# 贡献指南

如果使用过程中有任何问题，或者需要反馈特性需求和bug报告，可以提交issues联系我们，具体贡献方法可参考[这里](https://gitcode.com/boostkit/community/blob/master/docs/contributor/contributing.md)。

# 免责声明

此代码仓计划参与OpenSSL/Tongsuo/BoringSSL/Lz4/Zlib/Gzip/Zstd软件开源，仅作OpenSSL/Tongsuo/BoringSSL/Lz4/Zlib/Gzip/Zstd功能扩展或性能提升，编码风格遵照原生开源软件，继承原生开源软件安全设计，不破坏原生开源软件设计及编码风格和方式，软件的任何漏洞与安全问题，均由相应的上游社区根据其漏洞和安全响应机制解决。请密切关注上游社区发布的通知和版本更新。鲲鹏计算社区对软件的漏洞及安全问题不承担任何责

# 常见问题

## 驱动加载失败问题

* 内核版本和内核开发包版本不一致导致内核安装失败。（包括小版本号）
  
  > uname -r 查看内核版本 rpm -qa | grep kernel-devel 查看内核开发包版本
  
  解决办法：安装和内核版本一致的开发包
* 缺少license导致加载失败
  
  > lspci | grep HPRE lspci | grep SEC lspci | grep ZIP
  
  解决办法：920申请license安装；920新型号更新免license版本BIOS
  
## 驱动修改instance数量
  
  驱动instance数量默认安装是每个加速器设备256个instance。
  
  > cat /sys/class/uacce/hisi_*/available_instances 显示的数量为256（每个加速器）
  
  每个加速器最大的instance数量为1024，修改方式如下（选择1种合适的方式即可）：
  
  1、可以在驱动目录对应的Makefile文件将pf_q_num=256修改为pf_q_num=1024之后，卸载驱动重新编译安装。
  
  2、或者直接执行：
  ```modprobe -r hisi_zip
  modprobe -r hisi_hpre
  modprobe -r hisi_sec2
  modprobe -r hisi_qm
  modprobe -r uacce
  ```

  先卸载驱动 之后再执行：
  ```modprobe uacce 
  modprobe hisi_qm
  modprobe hisi_sec2 uacce_mode=2 pf_q_num=1024
  modprobe hisi_hpre uacce_mode=2 pf_q_num=1024
  modprobe hisi_zip uacce_mode=2 pf_q_num=1024
  ```

  按新的队列数量加载驱动。（uacce_mode=2是nosva模式，一般场景不涉及）
  
  > 注意，若容器场景，每个设备虚拟出的VF，也是和PF共享1024个instance，也就是PF+VF的instance最大为1024