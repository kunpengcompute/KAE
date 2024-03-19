Name:          kae
Summary:       Huawei Kunpeng Accelerator Engine Zip
Version:       2.0.2
Release:       1
License:       GPL-2.0
Source:        %{name}-%{version}.tar.gz
ExclusiveOS:   linux
BuildRoot:     %{_tmppath}/%{name}-%{version}-root
Conflicts:     %{name} < %{version}-%{release}
Provides:      %{name} = %{version}-%{release}
BuildRequires: gcc, make, kernel-devel, libtool, numactl-devel, openssl-devel, chrpath
ExclusiveArch: aarch64
Autoreq: no
Autoprov: no

%define kernel_version %(rpm -q kernel-devel | sed 's/kernel-devel-//')
%define kae_build_path  %{_builddir}/%{name}-%{version}/kae_build
%define kae_path  %{_builddir}/%{name}-%{version}/
%define kae_driver_path  %{_builddir}/%{name}-%{version}/KAEKernelDriver
%define kae_uadk_path  %{_builddir}/%{name}-%{version}/uadk
%define zlib_version 1.2.11
%define zstd_version 1.5.2

%description
This package contains the Huawei Hisilicon Zip and Openssl Accelerator Engine.


%prep
%global debug_package %{nil}
%setup -c -n %{name}-%{version}
implementer=$(cat /proc/cpuinfo | grep "CPU implementer" | awk 'NR==1{printf $4}')
part=$(cat /proc/cpuinfo | grep "CPU part" | awk 'NR==1{printf $4}')
if [ "${implementer}-${part}" != "0x48-0xd01" ] && [ "${implementer}-${part}" != "0x48-0xd02" ]; then
    echo "Only installed on kunpeng CPUs"
fi

%build
sh build.sh rpm


%install
implementer=$(cat /proc/cpuinfo | grep "CPU implementer" | awk 'NR==1{printf $4}')
part=$(cat /proc/cpuinfo | grep "CPU part" | awk 'NR==1{printf $4}')
#driver
    mkdir -p ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
    mkdir -p ${RPM_BUILD_ROOT}/etc/modprobe.d
    install -b -m755 %{kae_path}/kae_build/driver/*.ko                ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
    install -b -m755 %{kae_path}/kae_build/driver/*.conf              ${RPM_BUILD_ROOT}/etc/modprobe.d/

#uadk
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/lib
    chrpath -d %{kae_path}/kae_build/uadk/lib/*
    cp -rf %{kae_path}/kae_build/uadk/lib/*               ${RPM_BUILD_ROOT}/usr/local/lib
    mkdir -p ${RPM_BUILD_ROOT}/usr/include/uadk
    mkdir -p ${RPM_BUILD_ROOT}/usr/include/uadk/drv
    install -b -m755 %{kae_path}/kae_build/uadk/include/*.h                        ${RPM_BUILD_ROOT}/usr/include/uadk
    install -b -m755 %{kae_path}/kae_build/uadk/include/drv/*.h                    ${RPM_BUILD_ROOT}/usr/include/uadk/drv


#engine
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/lib/engines-1.1
    chrpath -d %{kae_path}/kae_build/KAEOpensslEngine/lib/*
    cp -rf %{kae_path}/kae_build/KAEOpensslEngine/lib/*    ${RPM_BUILD_ROOT}/usr/local/lib/engines-1.1/

#zlib
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezip/lib
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezip/include
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezip/lib/pkgconfig
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezip/share/man/man3
    cp -rf %{kae_path}/kae_build/KAEZlib/kaezip/lib/*                           ${RPM_BUILD_ROOT}/usr/local/kaezip/lib
    cp -rf %{kae_path}/kae_build/KAEZlib/kaezip/include/*                       ${RPM_BUILD_ROOT}/usr/local/kaezip/include
    cp -rf %{kae_path}/kae_build/KAEZlib/kaezip/share/*                         ${RPM_BUILD_ROOT}/usr/local/kaezip/share  

    #zstd只在SVA支持
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezstd/lib
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezstd/bin
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezstd/include
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezstd/lib/pkgconfig
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezstd/share/man/man3
    cp -rf %{kae_path}/kae_build/KAEZstd/kaezstd/lib/*                             ${RPM_BUILD_ROOT}/usr/local/kaezstd/lib
    cp -rf %{kae_path}/kae_build/KAEZstd/kaezstd/bin/*                             ${RPM_BUILD_ROOT}/usr/local/kaezstd/bin
    cp -rf %{kae_path}/kae_build/KAEZstd/kaezstd/include/*                         ${RPM_BUILD_ROOT}/usr/local/kaezstd/include
    cp -rf %{kae_path}/kae_build/KAEZstd/kaezstd/share/*                           ${RPM_BUILD_ROOT}/usr/local/kaezstd/share 

%clean
rm -rf ${RPM_BUILD_ROOT}

%package driver
Summary: KAE Driver Package
Autoreq: no
Autoprov: no

%description driver
This package kae_driver library.

%files driver
%defattr(644,root,root)
/lib/modules/%{kernel_version}/extra/*.ko
%config(noreplace) /etc/modprobe.d/*.conf

%defattr(755,root,root)
/usr/local/lib/libwd.*
/usr/local/lib/libwd_comp.*  
/usr/local/lib/libwd_crypto.*
/usr/local/lib/libhisi_hpre.*
/usr/local/lib/libhisi_sec.* 
/usr/local/lib/libhisi_zip.* 

%defattr(644,root,root)
/usr/include/uadk/*.h
/usr/include/uadk/drv/*.h


%pre driver
echo "Preprocessing before installing the driver"
modprobe -r hisi_zip > /dev/null 2>&1 || true
modprobe -r hisi_hpre > /dev/null 2>&1 || true
modprobe -r hisi_sec2 > /dev/null 2>&1 || true
modprobe -r hisi_qm > /dev/null 2>&1 || true
modprobe -r uacce > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libwd.*   > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libwd_comp.*   > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libwd_crypto.*   > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libhisi_hpre.*   > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libhisi_sec.*   > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libhisi_zip.*   > /dev/null 2>&1 || true


echo "checking installed modules"
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    echo "uacce modules start to install"
fi

echo "checking installed modules"
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    echo "hisi_sec2 modules start to install"
fi

echo "checking installed modules"
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    echo "hisi_hpre modules start to install"
fi

echo "checking installed modules"
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    echo "hisi_zip modules start to install"
fi

%post driver
echo "installing driver..."
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    implementer=$(cat /proc/cpuinfo | grep "CPU implementer" | awk 'NR==1{printf $4}')
    part=$(cat /proc/cpuinfo | grep "CPU part" | awk 'NR==1{printf $4}')
    depmod -a
    modprobe uacce
    modprobe hisi_qm
    modprobe hisi_sec2 uacce_mode=2 pf_q_num=256
    modprobe hisi_hpre uacce_mode=2 pf_q_num=256
    modprobe hisi_zip  uacce_mode=2 pf_q_num=256
    echo "options hisi_sec2 uacce_mode=2 pf_q_num=256" > /etc/modprobe.d/hisi_sec2.conf
    echo "options hisi_hpre uacce_mode=2 pf_q_num=256" > /etc/modprobe.d/hisi_hpre.conf
    echo "options hisi_zip  uacce_mode=2 pf_q_num=256" > /etc/modprobe.d/hisi_zip.conf
fi
/sbin/ldconfig

if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    if [ -e /sbin/weak-modules ]; then
        echo "/lib/modules/%{kernel_version}/extra/uacce.ko" | /sbin/weak-modules --add-module --no-initramfs
        echo "/lib/modules/%{kernel_version}/extra/hisi_qm.ko" | /sbin/weak-modules --add-module --no-initramfs
    fi
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "uacce modules installed"

if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    if [ -e /sbin/weak-modules ]; then
        echo "/lib/modules/%{kernel_version}/extra/hisi_sec2.ko" | /sbin/weak-modules --add-module --no-initramfs
    fi
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "hisi_sec2 modules installed"

if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    if [ -e /sbin/weak-modules ]; then
        echo "/lib/modules/%{kernel_version}/extra/hisi_hpre.ko" | /sbin/weak-modules --add-module --no-initramfs
    fi
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "hisi_hpre modules installed"

if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    if [ -e /sbin/weak-modules ]; then
        echo "/lib/modules/%{kernel_version}/extra/hisi_zip.ko" | /sbin/weak-modules --add-module --no-initramfs
    fi
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "hisi_zip modules installed"

%preun driver
modprobe -r hisi_zip > /dev/null 2>&1 || true
modprobe -r hisi_hpre > /dev/null 2>&1 || true
modprobe -r hisi_sec2 > /dev/null 2>&1 || true
modprobe -r hisi_qm > /dev/null 2>&1 || true
modprobe -r uacce > /dev/null 2>&1 || true

if [ -e /sbin/weak-modules ]; then
    echo "/lib/modules/%{kernel_version}/extra/uacce.ko" | /sbin/weak-modules --remove-module --no-initramfs
    echo "/lib/modules/%{kernel_version}/extra/hisi_qm.ko" | /sbin/weak-modules --remove-module --no-initramfs
fi
/sbin/depmod -a > /dev/null 2>&1 || true
if [ "$1" = "0" ] ; then  #0: uninstall
    echo "uacce modules uninstalling"
fi

if [ -e /sbin/weak-modules ]; then
    echo "/lib/modules/%{kernel_version}/extra/hisi_sec2.ko" | /sbin/weak-modules --remove-module --no-initramfs
fi
if [ "$1" = "0" ] ; then  #0: uninstall
    echo "hisi_sec2 modules uninstalling"
fi

if [ -e /sbin/weak-modules ]; then
    echo "/lib/modules/%{kernel_version}/extra/hisi_hpre.ko" | /sbin/weak-modules --remove-module --no-initramfs
fi
if [ "$1" = "0" ] ; then  #0: uninstall
    echo "hisi_hpre modules uninstalling"
fi

if [ -e /sbin/weak-modules ]; then
    echo "/lib/modules/%{kernel_version}/extra/hisi_zip.ko" | /sbin/weak-modules --remove-module --no-initramfs
fi
if [ "$1" = "0" ] ; then  #0: uninstall
    echo "hisi_zip modules uninstalling"
fi

%postun driver
/sbin/ldconfig
rm -rf /usr/local/lib/libwd.*   > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libwd_comp.*   > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libwd_crypto.*   > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libhisi_hpre.*   > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libhisi_sec.*   > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libhisi_zip.*   > /dev/null 2>&1 || true

rm -rf /lib/modules/%{kernel_version}/extra/uacce.ko > /dev/null 2>&1 || true
rm -rf /lib/modules/%{kernel_version}/extra/hisi_qm.ko > /dev/null 2>&1 || true
rm -rf /lib/modules/%{kernel_version}/extra/hisi_sec2.ko > /dev/null 2>&1 || true
rm -rf /lib/modules/%{kernel_version}/extra/hisi_hpre.ko > /dev/null 2>&1 || true
rm -rf /lib/modules/%{kernel_version}/extra/hisi_zip.ko > /dev/null 2>&1 || true
rm -rf /etc/modprobe.d/hisi_sec2.conf > /dev/null 2>&1 || true
rm -rf /etc/modprobe.d/hisi_hpre.conf > /dev/null 2>&1 || true
rm -rf /etc/modprobe.d/hisi_zip.conf > /dev/null 2>&1 || true


if [ "$1" = "0" ] ; then  #0: uninstall
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "uacce modules uninstalled"

if [ "$1" = "0" ] ; then  #0: uninstall
    if [ -e /sbin/weak-modules ]; then
        echo "/lib/modules/%{kernel_version}/extra/hisi_sec2.ko" | /sbin/weak-modules --remove-module --no-initramfs
    fi
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "hisi_sec2 modules uninstalled"

if [ "$1" = "0" ] ; then  #0: uninstall
    if [ -e /sbin/weak-modules ]; then
        echo "/lib/modules/%{kernel_version}/extra/hisi_hpre.ko" | /sbin/weak-modules --remove-module --no-initramfs
    fi
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "hisi_hpre modules uninstalled"

if [ "$1" = "0" ]; then  #0: uninstall
    if [ -e /sbin/weak-modules ]; then
        echo "/lib/modules/%{kernel_version}/extra/hisi_zip.ko" | /sbin/weak-modules --remove-module --no-initramfs
    fi
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "hisi_zip modules uninstalled"


%package zip
Summary: KAE Zip Package
Requires:kae-driver
Autoreq: no
Autoprov: no

%description zip
This package kaezip library.

%files zip
%defattr(755,root,root)
/usr/local/kaezip/lib/*
%defattr(644,root,root)
/usr/local/kaezip/share/man/man3/zlib.3
/usr/local/kaezip/include/*.h

%defattr(755,root,root)
%config(missingok) /usr/local/kaezstd/lib/*
%config(missingok) /usr/local/kaezstd/bin/*
%defattr(644,root,root)
%config(missingok) /usr/local/kaezstd/include/*.h
%config(missingok) /usr/local/kaezstd/share/man/man1/*

%pre zip
echo "installing pre zip..."
if [ "$1" = "2" ] ; then  #2: update
    rm -rf /usr/local/kaezip     > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezstd    > /dev/null 2>&1 || true
fi

%post zip
echo "installing post zip..."
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    implementer=$(cat /proc/cpuinfo | grep "CPU implementer" | awk 'NR==1{printf $4}')
    part=$(cat /proc/cpuinfo | grep "CPU part" | awk 'NR==1{printf $4}')
    if [ "${implementer}-${part}" == "0x48-0xd01" ]; then
        rm -rf /usr/local/kaezstd    > /dev/null 2>&1 || true
    fi
fi
/sbin/ldconfig

%preun zip
echo "uninstalling zip-rpm"


%postun zip
rm -rf /usr/local/kaezip                > /dev/null 2>&1 || true
rm -rf /usr/local/kaezstd               > /dev/null 2>&1 || true
rm -f /var/log/kaezip.log*              > /dev/null 2>&1 || true
rm -f /var/log/kaezstd.log*             > /dev/null 2>&1 || true
echo "zip-rpm uninstalled"
/sbin/ldconfig


%package openssl
Summary: KAE Openssl Package
Requires:kae-driver, openssl-devel
Autoreq: no
Autoprov: no

%description openssl
This package kae_openssl library.

%files openssl
%defattr(755,root,root)
/usr/local/lib/engines-1.1/*

%pre openssl
if  [ "$RPM_INSTALL_PREFIX" == "" ]; then
    RPM_INSTALL_PREFIX=/usr/local/lib/engines-1.1
fi
if [ "$1" = "2" ] ; then  #2: update
    rm -rf $RPM_INSTALL_PREFIX      > /dev/null 2>&1 || true
fi

%post openssl
echo "installing openssl engine..."
if  [ "$RPM_INSTALL_PREFIX" == "" ]; then
    RPM_INSTALL_PREFIX=/usr/local/lib/engines-1.1
fi
/sbin/ldconfig

%preun openssl
echo "uninstalling openssl engine..."
if  [ "$RPM_INSTALL_PREFIX" == "" ]; then
    RPM_INSTALL_PREFIX=/usr/local/lib/engines-1.1
fi

%postun openssl
if  [ "$RPM_INSTALL_PREFIX" == "" ]; then
    RPM_INSTALL_PREFIX=/usr/local/lib/engines-1.1
fi
rm -rf $RPM_INSTALL_PREFIX   > /dev/null 2>&1 || true
rm -f /var/log/kae.log*      > /dev/null 2>&1 || true
echo "openssl engine uninstalled"
/sbin/ldconfig

%changelog
* Tue Mar 19 2024 liuyang <liuyang645@huawei.com> 2.0.2-1
- Update Spec Version Include kunpeng accelerator engine Code

* Tue Jan 2 2024 liuyang <liuyang645@huawei.com> 2.0.1-1
- Update Spec Version Include kunpeng accelerator engine Code

* Wed Jun 14 2023 liuyang <liuyang645@huawei.com> 2.0.0-2
- Second Spec Version Include kunpeng accelerator engine Code

* Tue Jan 07 2020 jinbinhua <jinbinhua@huawei.com> 1.2.7-1
- First Spec Version Include kunpeng accelerator engine Code
