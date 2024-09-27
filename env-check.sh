#!/bin/sh

kaeversion=-1 # 初始化kae推荐安装的版本

successecho () {
 echo -e "\033[32m[检查通过] $1 \033[0m"
}

warnecho () {
 echo -e "\033[33m [检查提醒] $1 \033[0m"
}
errorecho () {
  echo -e "\033[31m [检查失败] $1 \033[0m"
}
inputecho () {
  echo -e "\033[43;37m $1 \033[0m"
}

# 检查证书安装
checkLicense () {
  echo "check0、检查License证书====>"

  # 查看是否存在高性能RSA加速引擎 HPRE
  hpre=$(lspci | grep HPRE)

  if [[ $hpre ]]; then
    successecho "HPRE引擎检查通过"
  else
    warnecho "没有高性能RSA加速引擎 HPRE !!!!!!!， 确认命令：lspci | grep HPRE"
  fi

  # 查看是否存在RAID DIF运算加速引擎 RDE
  rde=$(lspci | grep RDE)
  if [[ $rde ]]; then
    successecho "RDE引擎检查通过"
  else
    warnecho "没有RAID DIF运算加速引擎 RDE !!!!!!!，确认命令：lspci | grep RDE"
  fi
  
  # 查看是否存在安全加速引擎 SEC
  sec=$(lspci | grep SEC)
  if [[ $sec ]]; then
    successecho "SEC引擎检查通过"
  else
    warnecho "没有加速引擎SEC !!!!!!!， 确认命令：lspci | grep SEC"
  fi

  # 查看是否存在加解密引擎 ZIP
  zip=$(lspci | grep ZIP)
  if [[ $zip ]]; then
    successecho "ZIP引擎检查通过"
  else
    warnecho "没有加速引擎ZIP !!!!!!!， 确认命令：lspci | grep ZIP"
  fi

}

# 检查操作系统版本号。以确认需要安装的KAE版本是1还是2
checkOS () {
    echo "check1、检查操作系统====>"

    osinfo=$(uname -a)
    if [[ $osinfo == *4.19* ]]; then
      echo "当前内核版本：4.19内核（应该使用 KAE1.0）"
      kaeversion=1
    elif [[ $osinfo == *5.10* ]]; then
      echo "当前内核版本：5.10内核（应该使用 KAE2.0）"
      kaeversion=2
    else 
      echo "当前内核版本：其他内核"
    fi

    # KAE2.0中，操作系统小版本也有影响。
    if [[ $osinfo == *oe2203.aarch64* ]]; then
      errorecho "当前内核版本比较老，不支持KAE诶，建议使用LTS-SP2及以上版本操作系统"
    elif [[ $osinfo == *oe2203sp1.aarch64* ]]; then
      warnecho "当前内核版本比较老，仅支持kae2.0.0，不能安装最新版本的KAE。建议使用LTS-SP2及以上版本操作系统"
    else 
      echo ""
    fi

    osname=`cat /etc/os-release | grep PRETTY_NAME`
    echo "当前操作系统名字: ${osname}"
    if [[ $osname == *22.03* ]]; then
      successecho "应该安装使用KAE2.0"
      kaeversion=2
    elif [[ $osname == *20.03* ]]; then
      successecho "应该安装使用KAE1.0"
      kaeversion=1
    else
      warnecho "需要手动判断安装哪个版本"
    fi

    # 检查本机安装的 kernel-devel 版本是否与当前机器的 内核版本保持一致
    kernelDevel=$(rpm -qa kernel-devel)
    unamer=$(uname -r)
    if [[ -z "$kernelDevel" ]] ; then
      errorecho "未安装kernel-devel !!需要安装与内核同版本的kernel-devel:  yum list kernel-devel 查看版本；yum install kernel-devel 安装"
    else
      echo "已安装kernel-devel: ${kernelDevel}。本机内核版本：${unamer}"
    fi

    isFlictKernelAndUname=$(rpm -qa kernel-devel | grep `uname -r`)
    if [[ -z "$isFlictKernelAndUname" ]] ; then
      errorecho "kernel-devel 与 linux 内核版本不一致！需重新安装kernel-devel。"
      warnecho "kernel-devel版本：${kernelDevel}"
      warnecho "linux 内核版本：${unamer}"
      warnecho "【安装指南】yum list kernel-devel 命令查看可安装版本；yum install kernel-devel 安装"
    else
      successecho "kernel-devel 已成功安装"
    fi

    # yum install numactl 。
    # 查看numa的硬件绑定信息：numactl --hardware
    # 问题案例：源码编译依赖 numa.h 头文件。安装uadk 报错：fatal error: numa.h: No such file or directory
    # 问题原因：缺少依赖包
    # 解决办法：需要 yum install numactl-devel
    numactlDevel=$(rpm -qa numactl-devel)
    if [[ -z "$numactlDevel" ]] ; then
      errorecho "未安装 numactl-devel, 编译uadk会报错!!需要安装 numactl-devel: yum install numactl-devel"
    fi

    # yum list openssl // 检查当前yum源可安装的openssl版本
    # which openssl // 查找当前机器上已安装的openssl的位置
    # openssl version // 检查openssl的版本号

    # 问题案例：源码编译engine，脚本正常结束，但是引擎未成功安装。
    # 中间日志：
    # checking for openssl/engine.h... no
    # checking for libcrypto... no
    # 问题原因：缺少openssl-devel包
    # 解决办法：使用 yum install openssl-devel 命令安装缺少的包
    opensslDevel=$(rpm -qa openssl-devel)
    if [[ -z "$opensslDevel" ]] ; then
      errorecho "未安装 openssl-devel, 编译 engine 会报错!!需要安装 openssl-devel: yum install openssl-devel"
    fi

    # 一般来说，kae引擎需要依赖这些包：
    # yum install gcc g++ gdb make patch tree autoconf automake libtool numactl numactl-devel kernel-devel openssl-devel
}

# 检查驱动
checkDriver(){
  echo "check2、检查driver驱动====>"
  driverinfo=$(ls -l /sys/class/uacce/)
  if [[ $driverinfo = *hisi_hpre* ]]; then
    successecho "已检测到hisi_hpre引擎文件"
  else 
    errorecho "未检测到hisi_hpre加速引擎文件系统！！！ 加解密可能有问题，检查 ls -l /sys/class/uacce/"
  fi 
  if [[ $driverinfo = *hisi_sec* ]]; then
    successecho "已检测到hisi_sec引擎文件"
  else 
    errorecho "未检测到hisi_sec加速引擎文件系统！！！加解密可能有问题，检查 ls -l /sys/class/uacce/"
  fi 
  if [[ $driverinfo = *hisi_zip* ]]; then
    successecho "已检测到hisi_zip引擎文件"
  else 
    errorecho "未检测到hisi_zip加速引擎文件系统！！！解压缩可能有问题，检查 ls -l /sys/class/uacce/"
  fi 
  # if [[ $driverinfo = *hisi_hpre* ]]; then
  #   echo "已检测到hisi_hpre驱动"
  # else 
  #   errorecho "未检测到hisi_hpre驱动！！！"
  # fi 

  driverUacce=$(lsmod|grep uacce)
  driverUacce2=$(lsmod|grep hisi_qm)

  if [[( $driverUacce = *hisi_qm* ) && ( $driverUacce = *hisi_sec2*) && ( $driverUacce = *hisi_hpre*) && ( $driverUacce = *hisi_zip*) ]];  then
    successecho "内核uacce模块加载成功 lsmod|grep uacce"
  elif [[( $driverUacce2 = *hisi_sec2*) && ( $driverUacce2 = *hisi_hpre*) && ( $driverUacce2 = *hisi_zip*)]]; then
    successecho "内核uacce模块加载成功 lsmod|grep hisi_qm"
  else
    warnecho "内核uacce模块可能存在卸载情况！！ 查看命令 lsmod | grep uacce "
    warnecho "内核手动卸载模块命令(以hisi_sec2为例)：rmmod hisi_sec2  ；加载模块命令：modprobe hisi_sec2 。如果手动执行后仍然不成功，尝试重启设备后安装内核驱动"
  fi
}
checkUadk(){
  echo "check3、检查uadk驱动====>"
  uadkinfo=$(ls -l /usr/local/lib/libwd*)
  if [[ ($uadkinfo = *libwd_comp.la*) && ($uadkinfo = *libwd_comp.so*) && ($uadkinfo = *libwd_crypto.la*) && ($uadkinfo = *libwd_crypto.so*) && ($uadkinfo = *libwd.la*) && ($uadkinfo = *libwd.so*)]]; then
    successecho "已安装uadk驱动. v2"
  elif [[ ($uadkinfo = *libwd.a*) &&  ($uadkinfo = *libwd.la*) && ($uadkinfo = *libwd.so*)]]; then
    successecho "已安装uadk驱动. v1"
  else 
    errorecho "未检测到驱动安装！！！ 检查命令：ls -l /usr/local/lib/libwd*"
  fi 
}
checkEngine(){
  echo "check4、检查openssl engine====>"

  opensslversion=$(openssl version)
  echo "检查openssl version: ${opensslversion}"

  engine=$(ls -l /usr/local/lib/engines-1.1)
  if [[ ($engine = *kae.la*) && ($engine = *kae.so*) && ($engine = *kae.a*)]]; then
    successecho "已默认安装openssl 的 kae 2.0 engine "
  elif [[ ($engine = *kae.so*) && ($engine = *libkae.so*)]]; then
    successecho "已默认安装openssl 的 kae 1.0 engine "
  else 
    errorecho "未检测到默认openssl引擎安装！！！确认引擎命令：ls -l /usr/local/lib/engines-1.1  ;安装引擎命令 sh build.sh engine"
  fi
}

# 直接进行openssl命令
testOpenSSL() {

  echo "openssl 的引擎设置路径："$OPENSSL_ENGINES
  if [[ -z "$OPENSSL_ENGINES" ]] ;then
    warnecho "openssl 的引擎路径未设置。设置命令： export OPENSSL_ENGINES=/usr/local/lib/engines-1.1"
  fi

  echo "openssl 的配置文件路径："$OPENSSL_CONF
  if [[ -z "$OPENSSL_CONF" ]] ;then
    echo "测试nginx需要配置 OPENSSL_CONF 变量"
  fi

  echo "KAE1.0需要设置一个环境变量，使得kae能够通过它找到openssl的动态库和wrapDrive的动态库。export LD_LIBRARY_PATH=/usr/local/lib"

}

main() {
  echo "KAE 环境检查开始"

  checkLicense
  checkOS

  checkDriver
  checkUadk
  checkEngine

  testOpenSSL

  if [[ $kaeversion == -1 ]]; then
    warnecho "无法自动确定应该安装KAE1.0还是2.0，请输入想要安装的版本：(可选：1 2)"
    read inputKaeVersion
    kaeversion=$inputKaeVersion
  fi

  echo "基本检查完毕========================>"
}

main


howToAddQueue () {
  echo "以加解密hpre模块为例：从默认256个队列增加到1024个队列"
  echo "[步骤1] modprobe -r hisi_hpre #1、卸载 内核中的hisi_hpre模块"
  echo "[步骤2] lsmod | grep uacce #2、检查是否卸载成功，成功的话应该没有hisi_hpre了"
  echo "[步骤3] vi /etc/modprobe.d/hisi_hpre.conf #3、调整内部pf_q_num的值为1024，例如最终内容：options hisi_hpre uacce_mode=2 pf_q_num=1024"
  echo "[步骤4] modprobe hisi_hpre uacce_mode=2 pf_q_num=1024 #4、以新配置重新加载 hisi_hpre 模块"
  echo "[步骤5] lsmod | grep uacce #5、检查是否加载成功，成功的话应该有hisi_hpre了"
  echo "[步骤6] watch -d cat /sys/class/uacce/hisi_hpre-*/available_instances #6、开始监控hpre模块的队列消耗情况"
  # KAE1.0的话
  echo "[步骤6] watch -d cat /sys/class/uacce/hisi_hpre-*/attrs/available_instances #6、开始监控hpre模块的队列消耗情况(1.0版本)"
  echo "[步骤7] 测试nginx的web服务如果有奇奇怪怪的错误，尝试卸载内核中的hisi_sec2模块： modprobe -r hisi_sec2"
}

howToOpenLogSec() {
  echo "开启加解密日志步骤:（开启日志会影响性能，建议仅调试时开启）"
  echo "1、设置日志配置环境变量 export KAE_CONF_ENV=/var/log/"
  warnecho "请拷贝export命令手动执行"
  echo "2、在第一步设置的路径下创建配置文件kae.cnf  并写入日志级别"
  touch /var/log/kae.cnf
  echo "[LogSection]" > /var/log/kae.cnf
  echo "debug_level=debug" >> /var/log/kae.cnf
  echo "已自动开启错误级别的日志，如需调整，需自行修改/var/log/kae.cnf文件中的debug_level字段，可选：none/error/info/warning/debug"

  echo "请在本窗口重新启动使用KAE的软件，然后另外开窗口查看日志，查看日志命令：tail -f -n 300 /var/log/kae.log"
}
howToOpenLogZip() {
  echo "开启解压缩日志步骤:（开启日志会影响性能，建议仅调试时开启）"
  echo "1、设置日志配置环境变量 export KAEZIP_CONF_ENV=/var/log/"
  warnecho "请拷贝export命令手动执行"
  echo "2、在第一步设置的路径下创建配置文件kaezip.cnf  并写入日志级别"
  touch /var/log/kaezip.cnf
  echo "[LogSection]" > /var/log/kaezip.cnf
  echo "debug_level=debug" >> /var/log/kaezip.cnf
  echo "已自动开启错误级别的日志，如需调整，需自行修改/var/log/kaezip.cnf文件中的debug_level字段，可选：none/error/info/warning/debug"

  echo "请在本窗口重新启动使用KAE的软件，然后另外开窗口查看日志，查看日志命令：tail -f -n 300 /var/log/kaezip.log"
}
howToCheckIfInstallSucceed() {
  echo "请查看上面的环境检查信息，是否有红色错误输出"
}
howToIfHardwareInUse(){
  echo "一般认为，程序运行时，加速硬件设备队列有消耗即为成功使能了硬件"
  if [[ $kaeversion == 1 ]]; then
    echo "监控命令为：watch -d cat /sys/class/uacce/hisi_*/attr/available_instances"
  else
    echo "监控命令为：watch -d cat /sys/class/uacce/hisi_*/available_instances"
  fi
  echo "hisi_sec2 模块处理 cipher对称加密 digest摘要  aead  算法功能"
  echo "hisi_hpre 模块处理 rsa非对称加密 dh密钥交换 算法功能"
  echo "hisi_zip 模块处理 解压缩 zlib gzip 算法功能"
}



warnecho "好的，您需要安装KAE $kaeversion.0，请输入遇到的问题编号："
echo "问题1： KAE安装过程报错"
echo "问题2： KAE安装后测试openssl speed发现KAE未生效"
echo "问题3： 开启KAE加解密日志，清空并监控打印"
echo "问题4： 开启KAE解压缩日志，清空并监控打印"
echo "问题5： 我需要自动检查确认一下KAE是否安装成功？"
echo "问题6： 如何确认程序运行的时候，真的使用到硬算加速了？"
echo "问题7： 如何加大硬算资源队列？"
read questionNum

case $questionNum in
 1) echo "请检查报错信息"
 ;;
 2) testOpenSSL
 ;;
 3) howToOpenLogSec
 ;;
 4) howToOpenLogZip
 ;;
 5) howToCheckIfInstallSucceed
 ;;
 6) howToIfHardwareInUse
 ;;
 7) howToAddQueue
 ;;
 *) echo "暂时还未支持该内容。。。"
 ;;
esac
