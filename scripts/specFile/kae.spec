Name:          kae
Summary:       Huawei Kunpeng Accelerator Engine
Version:       2.1.0
Release:       2
License:       GPL-2.0
Source:        %{name}-%{version}.tar.gz
ExclusiveOS:   linux
BuildRoot:     %{_tmppath}/%{name}-%{version}-root
Conflicts:     %{name} < %{version}-%{release}
Provides:      %{name} = %{version}-%{release}
BuildRequires: gcc, make, kernel-devel, libtool, numactl-devel, openssl-devel, chrpath, lz4-devel
ExclusiveArch: aarch64
Autoreq: no
Autoprov: no

%define kernel_version   %(rpm -q kernel-devel | sed 's/kernel-devel-//')
%define kae_build_path   %{_builddir}/%{name}-%{version}/kae_build
%define kae_path         %{_builddir}/%{name}-%{version}/
%define kae_driver_path  %{_builddir}/%{name}-%{version}/KAEKernelDriver
%define kae_uadk_path    %{_builddir}/%{name}-%{version}/uadk
%define zlib_version     1.2.11
%define zstd_version     1.5.2
%{!?kae_allow_non_kunpeng:%global kae_allow_non_kunpeng 0}

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
KAE_ALLOW_NON_KUNPENG_BUILD=%{kae_allow_non_kunpeng} sh build.sh rpm


%install
implementer=$(cat /proc/cpuinfo | grep "CPU implementer" | awk 'NR==1{printf $4}')
part=$(cat /proc/cpuinfo | grep "CPU part" | awk 'NR==1{printf $4}')
#driver
    mkdir -p ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
    mkdir -p ${RPM_BUILD_ROOT}/etc/modprobe.d
    install -b -m755 %{kae_path}/kae_build/driver/*.ko             ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
    install -b -m755 %{kae_path}/kae_build/driver/*.conf           ${RPM_BUILD_ROOT}/etc/modprobe.d/

#uadk
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/lib
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/lib/uadk
    chrpath -d %{kae_path}/kae_build/uadk/lib/*
    cp -rf %{kae_path}/kae_build/uadk/lib/libwd.*                   ${RPM_BUILD_ROOT}/usr/local/lib
    cp -rf %{kae_path}/kae_build/uadk/lib/libwd_comp.*              ${RPM_BUILD_ROOT}/usr/local/lib
    cp -rf %{kae_path}/kae_build/uadk/lib/libwd_crypto.*            ${RPM_BUILD_ROOT}/usr/local/lib
    cp -rf %{kae_path}/kae_build/uadk/lib/libwd_udma.*              ${RPM_BUILD_ROOT}/usr/local/lib
    cp -rf %{kae_path}/kae_build/uadk/lib/libwd_dae.*               ${RPM_BUILD_ROOT}/usr/local/lib
    cp -rf %{kae_path}/kae_build/uadk/lib/libhisi_hpre.*            ${RPM_BUILD_ROOT}/usr/local/lib/uadk
    cp -rf %{kae_path}/kae_build/uadk/lib/libhisi_sec.*             ${RPM_BUILD_ROOT}/usr/local/lib/uadk
    cp -rf %{kae_path}/kae_build/uadk/lib/libhisi_zip.*             ${RPM_BUILD_ROOT}/usr/local/lib/uadk
    cp -rf %{kae_path}/kae_build/uadk/lib/libhisi_dae.*             ${RPM_BUILD_ROOT}/usr/local/lib/uadk
    cp -rf %{kae_path}/kae_build/uadk/lib/libhisi_udma.*            ${RPM_BUILD_ROOT}/usr/local/lib/uadk
    cp -rf %{kae_path}/kae_build/uadk/lib/libisa_ce.*               ${RPM_BUILD_ROOT}/usr/local/lib/uadk
    cp -rf %{kae_path}/kae_build/uadk/lib/libisa_sve.*              ${RPM_BUILD_ROOT}/usr/local/lib/uadk
    mkdir -p ${RPM_BUILD_ROOT}/usr/include/uadk
    mkdir -p ${RPM_BUILD_ROOT}/usr/include/uadk/drv
    install -b -m755 %{kae_path}/kae_build/uadk/include/*.h        ${RPM_BUILD_ROOT}/usr/include/uadk
    install -b -m755 %{kae_path}/kae_build/uadk/include/drv/*.h    ${RPM_BUILD_ROOT}/usr/include/uadk/drv


#engine
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/lib/engines-1.1
    for file in %{kae_path}/kae_build/KAEOpensslEngine/lib/*.so*;do
        [-f "$file" ] $$ chrpath -d "$file" 2>/dev/null || true
    done
    cp -rf %{kae_path}/kae_build/KAEOpensslEngine/lib/*    ${RPM_BUILD_ROOT}/usr/local/lib/engines-1.1/

#zlib
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezip/lib
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezip/include
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezip/lib/pkgconfig
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezip/share/man/man3
    cp -rf %{kae_path}/kae_build/kaezip/lib/*                           ${RPM_BUILD_ROOT}/usr/local/kaezip/lib
    cp -rf %{kae_path}/kae_build/kaezip/include/*                       ${RPM_BUILD_ROOT}/usr/local/kaezip/include
    cp -rf %{kae_path}/kae_build/kaezip/share/*                         ${RPM_BUILD_ROOT}/usr/local/kaezip/share  

#gzip
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaegzip
    cp %{kae_path}/kae_build/kaegzip/*                                  ${RPM_BUILD_ROOT}/usr/local/kaegzip

#zstd
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezstd/lib
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezstd/bin
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezstd/include
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezstd/lib/pkgconfig
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezstd/share/man/man1
    cp -rf %{kae_path}/kae_build/kaezstd/lib/*                          ${RPM_BUILD_ROOT}/usr/local/kaezstd/lib
    cp -rf %{kae_path}/kae_build/kaezstd/bin/*                          ${RPM_BUILD_ROOT}/usr/local/kaezstd/bin
    cp -rf %{kae_path}/kae_build/kaezstd/include/*                      ${RPM_BUILD_ROOT}/usr/local/kaezstd/include
    cp -rf %{kae_path}/kae_build/kaezstd/share/*                        ${RPM_BUILD_ROOT}/usr/local/kaezstd/share 

#lz4
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaelz4/lib
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaelz4/bin
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaelz4/include
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaelz4/share/man/man1
    cp -rf %{kae_path}/kae_build/kaelz4/lib/*                           ${RPM_BUILD_ROOT}/usr/local/kaelz4/lib
    cp -rf %{kae_path}/kae_build/kaelz4/bin/*                           ${RPM_BUILD_ROOT}/usr/local/kaelz4/bin
    cp -rf %{kae_path}/kae_build/kaelz4/include/*                       ${RPM_BUILD_ROOT}/usr/local/kaelz4/include
    cp -rf %{kae_path}/kae_build/kaelz4/share/*                         ${RPM_BUILD_ROOT}/usr/local/kaelz4/share 

#snappy
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaesnappy/lib
    mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaesnappy/include
    cp -rf %{kae_path}/kae_build/kaesnappy/lib/*                        ${RPM_BUILD_ROOT}/usr/local/kaesnappy/lib
    cp -rf %{kae_path}/kae_build/kaesnappy/include/*                    ${RPM_BUILD_ROOT}/usr/local/kaesnappy/include

%clean
rm -rf ${RPM_BUILD_ROOT}

%package driver
Summary: KAE Driver Package
Autoreq: no
Autoprov: no
Conflicts: libwd

%description driver
This package kae_driver library.

%files driver
%defattr(644,root,root)
/lib/modules/%{kernel_version}/extra/*.ko
/etc/modprobe.d/*.conf

%defattr(755,root,root)
/usr/local/lib/libwd.*
/usr/local/lib/libwd_comp.*  
/usr/local/lib/libwd_crypto.*
/usr/local/lib/libwd_udma.*
/usr/local/lib/libwd_dae.*
%dir /usr/local/lib/uadk
/usr/local/lib/uadk/libhisi_hpre.*
/usr/local/lib/uadk/libhisi_sec.*
/usr/local/lib/uadk/libhisi_zip.*
/usr/local/lib/uadk/libhisi_dae.*
/usr/local/lib/uadk/libhisi_udma.*
/usr/local/lib/uadk/libisa_ce.*
/usr/local/lib/uadk/libisa_sve.*

%defattr(644,root,root)
/usr/include/uadk/*.h
/usr/include/uadk/drv/*.h


%pre driver
echo "Preprocessing before installing the driver"
modprobe -r hisi_zip  > /dev/null 2>&1 || true
modprobe -r hisi_hpre > /dev/null 2>&1 || true
modprobe -r hisi_sec2 > /dev/null 2>&1 || true
modprobe -r hisi_qm   > /dev/null 2>&1 || true
modprobe -r uacce     > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libwd.*              > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libwd_comp.*         > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libwd_crypto.*       > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libwd_udma.*         > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libwd_dae.*          > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libhisi_hpre.*       > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libhisi_sec.*        > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libhisi_zip.*        > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libhisi_dae.*        > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libhisi_udma.*       > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libisa_ce.*          > /dev/null 2>&1 || true
rm -rf /usr/local/lib/libisa_sve.*         > /dev/null 2>&1 || true
rm -rf /usr/local/lib/uadk/libhisi_hpre.*  > /dev/null 2>&1 || true
rm -rf /usr/local/lib/uadk/libhisi_sec.*   > /dev/null 2>&1 || true
rm -rf /usr/local/lib/uadk/libhisi_zip.*   > /dev/null 2>&1 || true
rm -rf /usr/local/lib/uadk/libhisi_dae.*   > /dev/null 2>&1 || true
rm -rf /usr/local/lib/uadk/libhisi_udma.*  > /dev/null 2>&1 || true
rm -rf /usr/local/lib/uadk/libisa_ce.*     > /dev/null 2>&1 || true
rm -rf /usr/local/lib/uadk/libisa_sve.*    > /dev/null 2>&1 || true
rmdir /usr/local/lib/uadk                  > /dev/null 2>&1 || true

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
    running_kver=$(uname -r)
    build_kver=%{kernel_version}
    if [ "${KAE_USE_RUNNING_KERNEL}" = "1" ] && [ "${running_kver}" != "${build_kver}" ]; then
        mkdir -p "/lib/modules/${running_kver}/extra"
        ln -snf "/lib/modules/${build_kver}/extra/uacce.ko"     "/lib/modules/${running_kver}/extra/uacce.ko"
        ln -snf "/lib/modules/${build_kver}/extra/hisi_qm.ko"   "/lib/modules/${running_kver}/extra/hisi_qm.ko"
        ln -snf "/lib/modules/${build_kver}/extra/hisi_sec2.ko" "/lib/modules/${running_kver}/extra/hisi_sec2.ko"
        ln -snf "/lib/modules/${build_kver}/extra/hisi_hpre.ko" "/lib/modules/${running_kver}/extra/hisi_hpre.ko"
        ln -snf "/lib/modules/${build_kver}/extra/hisi_zip.ko"  "/lib/modules/${running_kver}/extra/hisi_zip.ko"
    fi
    if [ -e /sbin/weak-modules ]; then
        {
            echo "/lib/modules/%{kernel_version}/extra/uacce.ko"
            echo "/lib/modules/%{kernel_version}/extra/hisi_qm.ko"
            echo "/lib/modules/%{kernel_version}/extra/hisi_sec2.ko"
            echo "/lib/modules/%{kernel_version}/extra/hisi_hpre.ko"
            echo "/lib/modules/%{kernel_version}/extra/hisi_zip.ko"
        } | /sbin/weak-modules --add-module --no-initramfs
    fi
    /sbin/depmod -a > /dev/null 2>&1 || true
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

echo "uacce modules installed"
echo "hisi_sec2 modules installed"
echo "hisi_hpre modules installed"
echo "hisi_zip modules installed"

%preun driver
modprobe -r hisi_zip  > /dev/null 2>&1 || true
modprobe -r hisi_hpre > /dev/null 2>&1 || true
modprobe -r hisi_sec2 > /dev/null 2>&1 || true
modprobe -r hisi_qm   > /dev/null 2>&1 || true
modprobe -r uacce     > /dev/null 2>&1 || true

if [ -e /sbin/weak-modules ]; then
    {
        echo "/lib/modules/%{kernel_version}/extra/uacce.ko"
        echo "/lib/modules/%{kernel_version}/extra/hisi_qm.ko"
        echo "/lib/modules/%{kernel_version}/extra/hisi_sec2.ko"
        echo "/lib/modules/%{kernel_version}/extra/hisi_hpre.ko"
        echo "/lib/modules/%{kernel_version}/extra/hisi_zip.ko"
    } | /sbin/weak-modules --remove-module --no-initramfs
fi
if [ "$1" = "0" ] ; then  #0: uninstall
    echo "uacce modules uninstalling"
fi

if [ "$1" = "0" ] ; then  #0: uninstall
    echo "hisi_sec2 modules uninstalling"
fi

if [ "$1" = "0" ] ; then  #0: uninstall
    echo "hisi_hpre modules uninstalling"
fi

if [ "$1" = "0" ] ; then  #0: uninstall
    echo "hisi_zip modules uninstalling"
fi

%postun driver
/sbin/ldconfig
if [ "$1" = "0" ] ; then  #0: uninstall
    build_kver=%{kernel_version}
    changed_kvers="${build_kver}"

    for link in $(find /lib/modules -path '*/extra/*.ko' -type l 2>/dev/null); do
        target=$(readlink "$link")
        case "$target" in
            "/lib/modules/${build_kver}/extra/"*)
                rm -f "$link" > /dev/null 2>&1 || true
                kver=$(echo "$link" | sed -n 's#^/lib/modules/\([^/]*\)/extra/.*#\1#p')
                case " ${changed_kvers} " in
                    *" ${kver} "*) ;;
                    *) changed_kvers="${changed_kvers} ${kver}" ;;
                esac
                ;;
        esac
    done

fi

if [ "$1" = "0" ] ; then  #0: uninstall
    rm -rf /usr/local/lib/libwd.*              > /dev/null 2>&1 || true
    rm -rf /usr/local/lib/libwd_comp.*         > /dev/null 2>&1 || true
    rm -rf /usr/local/lib/libwd_crypto.*       > /dev/null 2>&1 || true
    rm -rf /usr/local/lib/libwd_udma.*         > /dev/null 2>&1 || true
    rm -rf /usr/local/lib/libwd_dae.*          > /dev/null 2>&1 || true
    rm -rf /usr/local/lib/libhisi_hpre.*       > /dev/null 2>&1 || true
    rm -rf /usr/local/lib/libhisi_sec.*        > /dev/null 2>&1 || true
    rm -rf /usr/local/lib/libhisi_zip.*        > /dev/null 2>&1 || true
    rm -rf /usr/local/lib/libhisi_dae.*        > /dev/null 2>&1 || true
    rm -rf /usr/local/lib/libhisi_udma.*       > /dev/null 2>&1 || true
    rm -rf /usr/local/lib/libisa_ce.*          > /dev/null 2>&1 || true
    rm -rf /usr/local/lib/libisa_sve.*         > /dev/null 2>&1 || true
    rm -rf /usr/local/lib/uadk/libhisi_hpre.*  > /dev/null 2>&1 || true
    rm -rf /usr/local/lib/uadk/libhisi_sec.*   > /dev/null 2>&1 || true
    rm -rf /usr/local/lib/uadk/libhisi_zip.*   > /dev/null 2>&1 || true
    rm -rf /usr/local/lib/uadk/libhisi_dae.*   > /dev/null 2>&1 || true
    rm -rf /usr/local/lib/uadk/libhisi_udma.*  > /dev/null 2>&1 || true
    rm -rf /usr/local/lib/uadk/libisa_ce.*     > /dev/null 2>&1 || true
    rm -rf /usr/local/lib/uadk/libisa_sve.*    > /dev/null 2>&1 || true
    rmdir /usr/local/lib/uadk                  > /dev/null 2>&1 || true
fi

if [ "$1" = "0" ] ; then  #0: uninstall
    rm -rf /lib/modules/%{kernel_version}/extra/uacce.ko     > /dev/null 2>&1 || true
    rm -rf /lib/modules/%{kernel_version}/extra/hisi_qm.ko   > /dev/null 2>&1 || true
    rm -rf /lib/modules/%{kernel_version}/extra/hisi_sec2.ko > /dev/null 2>&1 || true
    rm -rf /lib/modules/%{kernel_version}/extra/hisi_hpre.ko > /dev/null 2>&1 || true
    rm -rf /lib/modules/%{kernel_version}/extra/hisi_zip.ko  > /dev/null 2>&1 || true
    rm -rf /etc/modprobe.d/hisi_sec2.conf                    > /dev/null 2>&1 || true
    rm -rf /etc/modprobe.d/hisi_hpre.conf                    > /dev/null 2>&1 || true
    rm -rf /etc/modprobe.d/hisi_zip.conf                     > /dev/null 2>&1 || true
    for kver in ${changed_kvers}; do
        /sbin/depmod -a "${kver}" > /dev/null 2>&1 || true
    done
fi
echo "uacce modules uninstalled"
echo "hisi_sec2 modules uninstalled"
echo "hisi_hpre modules uninstalled"
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
/usr/local/kaegzip/*
/usr/local/kaezstd/lib/*
/usr/local/kaezstd/bin/*
/usr/local/kaelz4/lib/*
/usr/local/kaelz4/bin/*
/usr/local/kaesnappy/lib/*

%defattr(644,root,root)
/usr/local/kaezip/share/man/man3/zlib.3
/usr/local/kaezip/include/*.h
/usr/local/kaezstd/include/*.h
/usr/local/kaezstd/share/man/man1/*
/usr/local/kaelz4/include/*.h
/usr/local/kaelz4/share/man/man1/*
/usr/local/kaesnappy/include/*.h

%pre zip
echo "installing pre zip..."
if [ "$1" = "2" ] ; then  #2: update
    rm -rf /usr/local/kaezip    > /dev/null 2>&1 || true
    rm -rf /usr/local/kaegzip   > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezstd   > /dev/null 2>&1 || true
    rm -rf /usr/local/kaelz4    > /dev/null 2>&1 || true
    rm -rf /usr/local/kaesnappy > /dev/null 2>&1 || true
fi

%post zip
echo "installing post zip..."
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    implementer=$(cat /proc/cpuinfo | grep "CPU implementer" | awk 'NR==1{printf $4}')
    part=$(cat /proc/cpuinfo | grep "CPU part" | awk 'NR==1{printf $4}')
    if [ "${implementer}-${part}" == "0x48-0xd01" ]; then
        rm -rf /usr/local/kaezstd   > /dev/null 2>&1 || true
        rm -rf /usr/local/kaelz4    > /dev/null 2>&1 || true
        rm -rf /usr/local/kaesnappy > /dev/null 2>&1 || true
    fi
fi
/sbin/ldconfig

%preun zip
echo "uninstalling zip-rpm"

%postun zip
if [ "$1" = "0" ] ; then  #0: uninstall
    rm -rf /usr/local/kaezip                > /dev/null 2>&1 || true
    rm -f  /var/log/kaezip.log*             > /dev/null 2>&1 || true
    rm -rf /usr/local/kaegzip               > /dev/null 2>&1 || true

    implementer=$(cat /proc/cpuinfo | grep "CPU implementer" | awk 'NR==1{printf $4}')
    part=$(cat /proc/cpuinfo | grep "CPU part" | awk 'NR==1{printf $4}')
    if [ "${implementer}-${part}" != "0x48-0xd01" ]; then
        rm -rf /usr/local/kaezstd          > /dev/null 2>&1 || true
        rm -rf /usr/local/kaelz4           > /dev/null 2>&1 || true
        rm -rf /usr/local/kaesnappy        > /dev/null 2>&1 || true

        rm -f /var/log/kaezstd.log*        > /dev/null 2>&1 || true
        rm -f /var/log/kaelz4.log*         > /dev/null 2>&1 || true
        rm -f /var/log/kaesnappy.log*      > /dev/null 2>&1 || true
    fi
fi
echo "zip-rpm uninstalled"
/sbin/ldconfig


%package openssl
Summary: KAE Openssl Package
Requires:kae-driver
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
* Tue Apr 14 2026 yuzhihuan <yuzhihuan@huawei.com> 2.1.0-2
- Update RPM spec to support optional running-kernel ko symlinks

* Wed Mar 25 2026 yuzhihuan <yuzhihuan@huawei.com> 2.1.0-1
- Update KAE algorithm library versions from 2.0.4 to 2.1.0

* Mon Feb 9 2026 yuzhihuan <yuzhihuan@huawei.com> 2.0.4-2
- Add RPM build support for kaesnappy and kaegzip module

* Mon Jan 20 2025 nieweiqiang <nieweiqiang@huawei.com> 2.0.4-1
- Update Spec Version Include kunpeng accelerator engine Code

* Mon Nov 4 2024 liuyang <liuyang645@huawei.com> 2.0.3-1
- Update Spec Version Include kunpeng accelerator engine Code

* Tue Mar 19 2024 liuyang <liuyang645@huawei.com> 2.0.2-1
- Update Spec Version Include kunpeng accelerator engine Code

* Tue Jan 2 2024 liuyang <liuyang645@huawei.com> 2.0.1-1
- Update Spec Version Include kunpeng accelerator engine Code

* Wed Jun 14 2023 liuyang <liuyang645@huawei.com> 2.0.0-2
- Second Spec Version Include kunpeng accelerator engine Code

* Tue Jan 07 2020 jinbinhua <jinbinhua@huawei.com> 1.2.7-1
- First Spec Version Include kunpeng accelerator engine Code
