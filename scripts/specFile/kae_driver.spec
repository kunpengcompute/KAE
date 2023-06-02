Name:          kae_driver
Summary:       Kunpeng Accelerator Engine Kernel Driver
Version:       2.0.0
Release:       1%dist
License:       GPL-2.0
Source:        KAE-%{version}.tar.gz
ExclusiveOS:   linux
BuildRoot:     %{_tmppath}/%{name}-%{version}-root
Conflicts:     %{name} < %{version}-%{release}
Provides:      %{name} = %{version}-%{release}
BuildRequires: gcc, make

%define kernel_version %(uname -r)
%define kae_driver_path  %{_builddir}/%{name}-%{version}/KAEKernelDriver
%define kae_uadk_path  %{_builddir}/%{name}-%{version}/uadk

%description
This package contains the Kunpeng Accelerator Engine Driver

%prep
%global debug_package %{nil}
%setup -c -n %{name}-%{version}

%build
cd KAEKernelDriver
make -j

cd ..
cd uadk
sh autogen.sh
sh conf.sh
make -j

%install
mkdir -p ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
mkdir -p ${RPM_BUILD_ROOT}/etc/modprobe.d
install -b -m -644 %{kae_driver_path}/uacce/uacce.ko              ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
install -b -m -644 %{kae_driver_path}/hisilicon/hisi_qm.ko        ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
install -b -m -644 %{kae_driver_path}/hisilicon/sec2/hisi_sec2.ko ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
#install -b -m -644 %{kae_driver_path}/conf/hisi_sec2.conf         ${RPM_BUILD_ROOT}/etc/modprobe.d/hisi_sec2.conf
install -b -m -644 %{kae_driver_path}/hisilicon/hpre/hisi_hpre.ko ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
#install -b -m -644 %{kae_driver_path}/conf/hisi_hpre.conf         ${RPM_BUILD_ROOT}/etc/modprobe.d/hisi_hpre.conf
install -b -m -644 %{kae_driver_path}/hisilicon/zip/hisi_zip.ko   ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
#install -b -m -644 %{kae_driver_path}/conf/hisi_zip.conf          ${RPM_BUILD_ROOT}/etc/modprobe.d/hisi_zip.conf
#install -b -m -644 %{kae_driver_path}/hisilicon/rde/hisi_rde.ko   ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
#install -b -m -644 %{kae_driver_path}/conf/hisi_rde.conf          ${RPM_BUILD_ROOT}/etc/modprobe.d/hisi_rde.conf

mkdir -p ${RPM_BUILD_ROOT}/usr/lib64
install -b -m -755 %{kae_uadk_path}/.libs/libwd_comp.so.2.4.0               ${RPM_BUILD_ROOT}/usr/lib64
install -b -m -755 %{kae_uadk_path}/.libs/libwd_crypto.so.2.4.0             ${RPM_BUILD_ROOT}/usr/lib64
install -b -m -755 %{kae_uadk_path}/.libs/libwd.so.2.4.0                   ${RPM_BUILD_ROOT}/usr/lib64
install -b -m -755 %{kae_uadk_path}/.libs/libhisi_hpre.so.2.4.0             ${RPM_BUILD_ROOT}/usr/lib64
install -b -m -755 %{kae_uadk_path}/.libs/libhisi_sec.so.2.4.0              ${RPM_BUILD_ROOT}/usr/lib64
install -b -m -755 %{kae_uadk_path}/.libs/libhisi_zip.so.2.4.0              ${RPM_BUILD_ROOT}/usr/lib64
mkdir -p ${RPM_BUILD_ROOT}/usr/include/uadk
mkdir -p ${RPM_BUILD_ROOT}/usr/include/uadk/drv
install -b -m -755 %{kae_uadk_path}/include/hisi_qm_udrv.h                       ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m -755 %{kae_uadk_path}/include/wd.h                                 ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m -755 %{kae_uadk_path}/include/wd_aead.h                            ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m -755 %{kae_uadk_path}/include/wd_alg_common.h                      ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m -755 %{kae_uadk_path}/include/wd_cipher.h                          ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m -755 %{kae_uadk_path}/include/wd_comp.h                            ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m -755 %{kae_uadk_path}/include/wd_dh.h                              ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m -755 %{kae_uadk_path}/include/wd_digest.h                          ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m -755 %{kae_uadk_path}/include/wd_ecc.h                             ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m -755 %{kae_uadk_path}/include/wd_ecc_curve.h                       ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m -755 %{kae_uadk_path}/include/wd_rsa.h                             ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m -755 %{kae_uadk_path}/include/wd_sched.h                           ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m -755 %{kae_uadk_path}/include/wd_util.h                            ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m -755 %{kae_uadk_path}/include/uacce.h                              ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m -755 %{kae_uadk_path}/include/drv/wd_aead_drv.h                    ${RPM_BUILD_ROOT}/usr/include/uadk/drv
install -b -m -755 %{kae_uadk_path}/include/drv/wd_cipher_drv.h                  ${RPM_BUILD_ROOT}/usr/include/uadk/drv
install -b -m -755 %{kae_uadk_path}/include/drv/wd_comp_drv.h                    ${RPM_BUILD_ROOT}/usr/include/uadk/drv
install -b -m -755 %{kae_uadk_path}/include/drv/wd_dh_drv.h                      ${RPM_BUILD_ROOT}/usr/include/uadk/drv
install -b -m -755 %{kae_uadk_path}/include/drv/wd_digest_drv.h                  ${RPM_BUILD_ROOT}/usr/include/uadk/drv
install -b -m -755 %{kae_uadk_path}/include/drv/wd_ecc_drv.h                     ${RPM_BUILD_ROOT}/usr/include/uadk/drv
install -b -m -755 %{kae_uadk_path}/include/drv/wd_rsa_drv.h                     ${RPM_BUILD_ROOT}/usr/include/uadk/drv

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(644,root,root)
/lib/modules/%{kernel_version}/extra/uacce.ko
/lib/modules/%{kernel_version}/extra/hisi_qm.ko
/lib/modules/%{kernel_version}/extra/hisi_sec2.ko
/lib/modules/%{kernel_version}/extra/hisi_hpre.ko
/lib/modules/%{kernel_version}/extra/hisi_zip.ko
%defattr(755,root,root)
/usr/lib64/libwd.so.2.4.0
/usr/lib64/libwd_comp.so.2.4.0
/usr/lib64/libwd_crypto.so.2.4.0
/usr/lib64/libhisi_hpre.so.2.4.0
/usr/lib64/libhisi_sec.so.2.4.0
/usr/lib64/libhisi_zip.so.2.4.0
/usr/lib64/libhisi_hpre.so.2
/usr/lib64/libhisi_sec.so.2
/usr/lib64/libhisi_zip.so.2
/usr/lib64/libwd.so.2
/usr/lib64/libwd_comp.so.2
/usr/lib64/libwd_crypto.so.2
%defattr(644,root,root)
/usr/include/uadk/hisi_qm_udrv.h     
/usr/include/uadk/wd.h               
/usr/include/uadk/wd_aead.h          
/usr/include/uadk/wd_alg_common.h    
/usr/include/uadk/wd_cipher.h    
/usr/include/uadk/wd_comp.h          
/usr/include/uadk/wd_dh.h            
/usr/include/uadk/wd_digest.h        
/usr/include/uadk/wd_ecc.h           
/usr/include/uadk/wd_ecc_curve.h     
/usr/include/uadk/wd_rsa.h           
/usr/include/uadk/wd_sched.h         
/usr/include/uadk/wd_util.h          
/usr/include/uadk/uacce.h            
/usr/include/uadk/drv/wd_aead_drv.h  
/usr/include/uadk/drv/wd_cipher_drv.h
/usr/include/uadk/drv/wd_comp_drv.h  
/usr/include/uadk/drv/wd_dh_drv.h    
/usr/include/uadk/drv/wd_digest_drv.h
/usr/include/uadk/drv/wd_ecc_drv.h   
/usr/include/uadk/drv/wd_rsa_drv.h   

%pre
if [ "$1" = "2" ] ; then  #2: update
    rm -rf /usr/lib64/libwd.so   > /dev/null 2>&1 || true
    rm -rf /usr/lib64/libwd.so.1   > /dev/null 2>&1 || true

    rm -rf /usr/lib64/libwd_comp.so   > /dev/null 2>&1 || true
    rm -rf /usr/lib64/libwd_comp.so.1   > /dev/null 2>&1 || true

    rm -rf /usr/lib64/libwd_crypto.so   > /dev/null 2>&1 || true
    rm -rf /usr/lib64/libwd_crypto.so.1   > /dev/null 2>&1 || true

    rm -rf /usr/lib64/libhisi_hpre.so   > /dev/null 2>&1 || true
    rm -rf /usr/lib64/libhisi_hpre.so.1   > /dev/null 2>&1 || true

    rm -rf /usr/lib64/libhisi_sec.so   > /dev/null 2>&1 || true
    rm -rf /usr/lib64/libhisi_sec.so.1   > /dev/null 2>&1 || true

    rm -rf /usr/lib64/libhisi_zip.so   > /dev/null 2>&1 || true
    rm -rf /usr/lib64/libhisi_zip.so.1   > /dev/null 2>&1 || true
fi

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

%post
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    cd /usr/lib64
    ln -sf libwd.so.2.4.0 libwd.so
    ln -sf libwd.so.2.4.0 libwd.so.1

    ln -sf libwd_comp.so.2.4.0 libwd_comp.so
    ln -sf libwd_comp.so.2.4.0 libwd_comp.so.1

    ln -sf libwd_crypto.so.2.4.0 libwd_crypto.so
    ln -sf libwd_crypto.so.2.4.0 libwd_crypto.so.1

    ln -sf libhisi_hpre.so.2.4.0 libhisi_hpre.so
    ln -sf libhisi_hpre.so.2.4.0 libhisi_hpre.so.1

    ln -sf libhisi_sec.so.2.4.0 libhisi_sec.so
    ln -sf libhisi_sec.so.2.4.0 libhisi_sec.so.1

    ln -sf libhisi_zip.so.2.4.0 libhisi_zip.so
    ln -sf libhisi_zip.so.2.4.0 libhisi_zip.so.1
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

%preun
if [ "$1" = "0" ] ; then  #0: uninstall
    rm -rf /usr/lib64/libwd.so    > /dev/null 2>&1 || true
    rm -rf /usr/lib64/libwd.so.1    > /dev/null 2>&1 || true

    rm -rf /usr/lib64/libwd_comp.so    > /dev/null 2>&1 || true
    rm -rf /usr/lib64/libwd_comp.so.1    > /dev/null 2>&1 || true

    rm -rf /usr/lib64/libwd_crypto.so    > /dev/null 2>&1 || true
    rm -rf /usr/lib64/libwd_crypto.so.1    > /dev/null 2>&1 || true

    rm -rf /usr/lib64/libhisi_hpre.so    > /dev/null 2>&1 || true
    rm -rf /usr/lib64/libhisi_hpre.so.1    > /dev/null 2>&1 || true

    rm -rf /usr/lib64/libhisi_sec.so    > /dev/null 2>&1 || true
    rm -rf /usr/lib64/libhisi_sec.so.1    > /dev/null 2>&1 || true

    rm -rf /usr/lib64/libhisi_zip.so    > /dev/null 2>&1 || true
    rm -rf /usr/lib64/libhisi_zip.so.1    > /dev/null 2>&1 || true
fi

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

%postun
/sbin/ldconfig

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

%changelog
* Tue Jan 07 2020 jinbinhua <jinbinhua@huawei.com> 1.2.7-1
- First Spec Version Include all Kunpeng Accelerator Engine Kernel Driver Code
