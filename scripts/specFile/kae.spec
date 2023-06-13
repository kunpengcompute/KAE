Name:          kae
Summary:       Huawei Kunpeng Accelerator Engine Zip
Version:       2.0.0
Release:       2
License:       GPL-2.0
Source:        %{name}-%{version}.tar.gz
ExclusiveOS:   linux
BuildRoot:     %{_tmppath}/%{name}-%{version}-root
Conflicts:     %{name} < %{version}-%{release}
Provides:      %{name} = %{version}-%{release}
BuildRequires: gcc, make, kernel-devel, libtool, numactl-devel
Autoreq: no
Autoprov: no

%define kernel_version %(rpm -q kernel-devel | sed 's/kernel-devel-//;s/\.[a-zA-Z0-9]*$//')
%define kae_build_path  %{_builddir}/%{name}-%{version}/%{name}-%{version}/kae_build
%define kae_path  %{_builddir}/%{name}-%{version}/%{name}-%{version}
%define kae_driver_path  %{_builddir}/%{name}-%{version}/%{name}-%{version}/KAEKernelDriver
%define kae_uadk_path  %{_builddir}/%{name}-%{version}/%{name}-%{version}/uadk
%define zlib_version 1.2.11
%define zstd_version 1.5.2

%description
This package contains the Huawei Hisilicon Zip Accelerator Engine.

%prep
%global debug_package %{nil}
%setup -c -n %{name}-%{version}

%build
cd %{name}-%{version}
sh build.sh buildallv2


%install
#zlib & zstd
mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezip/lib
mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezip/include
mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezip/lib/pkgconfig
mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezip/share/man/man3
install -b -m755 %{name}-%{version}/KAEZlib/libkaezip.so.1.3.11                                     ${RPM_BUILD_ROOT}/usr/local/kaezip/lib
install -b -m755 %{name}-%{version}/KAEZlib/include/kaezip.h                                         ${RPM_BUILD_ROOT}/usr/local/kaezip/include
install -b -m755 %{name}-%{version}/KAEZlib/open_source/zlib-%{zlib_version}/libz.so.%{zlib_version} ${RPM_BUILD_ROOT}/usr/local/kaezip/lib
install -b -m644 %{name}-%{version}/KAEZlib/open_source/zlib-%{zlib_version}/libz.a                  ${RPM_BUILD_ROOT}/usr/local/kaezip/lib
install -b -m644 %{name}-%{version}/KAEZlib/open_source/zlib-%{zlib_version}/zlib.pc                 ${RPM_BUILD_ROOT}/usr/local/kaezip/lib/pkgconfig
install -b -m644 %{name}-%{version}/KAEZlib/open_source/zlib-%{zlib_version}/zlib.3                  ${RPM_BUILD_ROOT}/usr/local/kaezip/share/man/man3
install -b -m644 %{name}-%{version}/KAEZlib/open_source/zlib-%{zlib_version}/zlib.h                  ${RPM_BUILD_ROOT}/usr/local/kaezip/include
install -b -m644 %{name}-%{version}/KAEZlib/open_source/zlib-%{zlib_version}/zconf.h                 ${RPM_BUILD_ROOT}/usr/local/kaezip/include

mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezstd/lib
mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezstd/bin
mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezstd/include
mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezstd/lib/pkgconfig
mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezstd/share/man/man3
install -b -m755 %{name}-%{version}/KAEZstd/libkaezstd.so.0.0.1                                      ${RPM_BUILD_ROOT}/usr/local/kaezstd/lib
install -b -m755 %{name}-%{version}/KAEZstd/include/kaezstd.h                                        ${RPM_BUILD_ROOT}/usr/local/kaezstd/include
install -b -m755 %{name}-%{version}/KAEZstd/open_source/zstd/lib/libzstd.so.%{zstd_version}          ${RPM_BUILD_ROOT}/usr/local/kaezstd/lib
install -b -m644 %{name}-%{version}/KAEZstd/open_source/zstd/lib/libzstd.a                           ${RPM_BUILD_ROOT}/usr/local/kaezstd/lib
install -b -m644 %{name}-%{version}/KAEZstd/open_source/zstd/lib/libzstd.pc                          ${RPM_BUILD_ROOT}/usr/local/kaezstd/lib/pkgconfig
#install -b -m644 %{name}-%{version}/KAEZstd/open_source/zstd/lib/zlib.3                             ${RPM_BUILD_ROOT}/usr/local/kaezstd/share/man/man3
install -b -m644 %{name}-%{version}/KAEZstd/open_source/zstd/lib/zstd.h                              ${RPM_BUILD_ROOT}/usr/local/kaezstd/include
install -b -m644 %{name}-%{version}/KAEZstd/open_source/zstd/lib/zdict.h                             ${RPM_BUILD_ROOT}/usr/local/kaezstd/include
install -b -m644 %{name}-%{version}/KAEZstd/open_source/zstd/lib/zstd_errors.h                       ${RPM_BUILD_ROOT}/usr/local/kaezstd/include
install -b -m755 %{name}-%{version}/KAEZstd/open_source/zstd/programs/zstdless                       ${RPM_BUILD_ROOT}/usr/local/kaezstd/bin
install -b -m755 %{name}-%{version}/KAEZstd/open_source/zstd/programs/zstdgrep                       ${RPM_BUILD_ROOT}/usr/local/kaezstd/bin
install -b -m755 %{name}-%{version}/KAEZstd/open_source/zstd/programs/zstd                           ${RPM_BUILD_ROOT}/usr/local/kaezstd/bin

#openssl
mkdir -p ${RPM_BUILD_ROOT}/usr/local/lib/engines-1.1
install -b -m755 %{name}-%{version}/KAEOpensslEngine/src/.libs/kae.so.2.0.0 ${RPM_BUILD_ROOT}/usr/local/lib/engines-1.1

# kernel
mkdir -p ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
mkdir -p ${RPM_BUILD_ROOT}/etc/modprobe.d
install -b -m644 %{kae_driver_path}/uacce/uacce.ko              ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
install -b -m644 %{kae_driver_path}/hisilicon/hisi_qm.ko        ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
install -b -m644 %{kae_driver_path}/hisilicon/sec2/hisi_sec2.ko ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
install -b -m644 %{kae_driver_path}/conf/hisi_sec2.conf         ${RPM_BUILD_ROOT}/etc/modprobe.d/
install -b -m644 %{kae_driver_path}/hisilicon/hpre/hisi_hpre.ko ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
install -b -m644 %{kae_driver_path}/conf/hisi_hpre.conf         ${RPM_BUILD_ROOT}/etc/modprobe.d/
install -b -m644 %{kae_driver_path}/hisilicon/zip/hisi_zip.ko   ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
install -b -m644 %{kae_driver_path}/conf/hisi_zip.conf          ${RPM_BUILD_ROOT}/etc/modprobe.d/
#install -b -m644 %{kae_driver_path}/hisilicon/rde/hisi_rde.ko   ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
#install -b -m644 %{kae_driver_path}/conf/hisi_rde.conf          ${RPM_BUILD_ROOT}/etc/modprobe.d/

mkdir -p ${RPM_BUILD_ROOT}/usr/lib64
install -b -m755 %{kae_uadk_path}/.libs/libwd_comp.so.2.4.0               ${RPM_BUILD_ROOT}/usr/lib64
install -b -m755 %{kae_uadk_path}/.libs/libwd_crypto.so.2.4.0             ${RPM_BUILD_ROOT}/usr/lib64
install -b -m755 %{kae_uadk_path}/.libs/libwd.so.2.4.0                   ${RPM_BUILD_ROOT}/usr/lib64
install -b -m755 %{kae_uadk_path}/.libs/libhisi_hpre.so.2.4.0             ${RPM_BUILD_ROOT}/usr/lib64
install -b -m755 %{kae_uadk_path}/.libs/libhisi_sec.so.2.4.0              ${RPM_BUILD_ROOT}/usr/lib64
install -b -m755 %{kae_uadk_path}/.libs/libhisi_zip.so.2.4.0              ${RPM_BUILD_ROOT}/usr/lib64
mkdir -p ${RPM_BUILD_ROOT}/usr/include/uadk
mkdir -p ${RPM_BUILD_ROOT}/usr/include/uadk/drv
install -b -m755 %{kae_uadk_path}/include/hisi_qm_udrv.h                       ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m755 %{kae_uadk_path}/include/wd.h                                 ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m755 %{kae_uadk_path}/include/wd_aead.h                            ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m755 %{kae_uadk_path}/include/wd_alg_common.h                      ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m755 %{kae_uadk_path}/include/wd_cipher.h                          ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m755 %{kae_uadk_path}/include/wd_comp.h                            ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m755 %{kae_uadk_path}/include/wd_dh.h                              ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m755 %{kae_uadk_path}/include/wd_digest.h                          ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m755 %{kae_uadk_path}/include/wd_ecc.h                             ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m755 %{kae_uadk_path}/include/wd_ecc_curve.h                       ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m755 %{kae_uadk_path}/include/wd_rsa.h                             ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m755 %{kae_uadk_path}/include/wd_sched.h                           ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m755 %{kae_uadk_path}/include/wd_util.h                            ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m755 %{kae_uadk_path}/include/uacce.h                              ${RPM_BUILD_ROOT}/usr/include/uadk
install -b -m755 %{kae_uadk_path}/include/drv/wd_aead_drv.h                    ${RPM_BUILD_ROOT}/usr/include/uadk/drv
install -b -m755 %{kae_uadk_path}/include/drv/wd_cipher_drv.h                  ${RPM_BUILD_ROOT}/usr/include/uadk/drv
install -b -m755 %{kae_uadk_path}/include/drv/wd_comp_drv.h                    ${RPM_BUILD_ROOT}/usr/include/uadk/drv
install -b -m755 %{kae_uadk_path}/include/drv/wd_dh_drv.h                      ${RPM_BUILD_ROOT}/usr/include/uadk/drv
install -b -m755 %{kae_uadk_path}/include/drv/wd_digest_drv.h                  ${RPM_BUILD_ROOT}/usr/include/uadk/drv
install -b -m755 %{kae_uadk_path}/include/drv/wd_ecc_drv.h                     ${RPM_BUILD_ROOT}/usr/include/uadk/drv
install -b -m755 %{kae_uadk_path}/include/drv/wd_rsa_drv.h                     ${RPM_BUILD_ROOT}/usr/include/uadk/drv


%clean
rm -rf ${RPM_BUILD_ROOT}

%package kaezip
Summary: KAE Zip Package
Requires: uadk

%description kaezip
This package kaezip library.


%files kaezip
%defattr(755,root,root)
/usr/local/kaezip/lib/libkaezip.so.1.3.11
/usr/local/kaezip/include/kaezip.h
/usr/local/kaezip/lib/libz.so.%{zlib_version}
%defattr(644,root,root)
/usr/local/kaezip/lib/libz.a
/usr/local/kaezip/lib/pkgconfig/zlib.pc
/usr/local/kaezip/share/man/man3/zlib.3
/usr/local/kaezip/include/zlib.h
/usr/local/kaezip/include/zconf.h

%defattr(755,root,root)
/usr/local/kaezstd/lib/libkaezstd.so.0.0.1
/usr/local/kaezstd/include/kaezstd.h
/usr/local/kaezstd/lib/libzstd.so.%{zstd_version}
/usr/local/kaezstd/bin/zstdless
/usr/local/kaezstd/bin/zstdgrep
/usr/local/kaezstd/bin/zstd
%defattr(644,root,root)
/usr/local/kaezstd/lib/libzstd.a
/usr/local/kaezstd/lib/pkgconfig/libzstd.pc
#/usr/local/kaezstd/share/man/man3/zlib.3
/usr/local/kaezstd/include/zstd.h
/usr/local/kaezstd/include/zdict.h
/usr/local/kaezstd/include/zstd_errors.h


%package kae_openssl
Summary: KAE Openssl Package
Requires: uadk

%description kae_openssl
This package kae_openssl library.

%files kae_openssl
%defattr(755,root,root)
/usr/local/lib/engines-1.1/kae.so.2.0.0

%package kae_driver
Summary: KAE Driver Package

%description kae_driver
This package kae_driver library.

%files kae_driver
%defattr(644,root,root)
/lib/modules/%{kernel_version}/extra/uacce.ko
/lib/modules/%{kernel_version}/extra/hisi_qm.ko
/lib/modules/%{kernel_version}/extra/hisi_sec2.ko
%config(noreplace) /etc/modprobe.d/hisi_sec2.conf
/lib/modules/%{kernel_version}/extra/hisi_hpre.ko
%config(noreplace) /etc/modprobe.d/hisi_hpre.conf
/lib/modules/%{kernel_version}/extra/hisi_zip.ko
%config(noreplace) /etc/modprobe.d/hisi_zip.conf
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
    #zip&zstp
    rm -rf /usr/local/kaezip/lib/libkaezip.so     > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezip/lib/libkaezip.so.0    > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezip/lib/libz.so     > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezip/lib/libz.so.1     > /dev/null 2>&1 || true

    rm -rf /usr/local/kaezstd/lib/libkaezstd.so     > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezstd/lib/libkaezstd.so.0    > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezstd/lib/libzstd.so     > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezstd/lib/libzstd.so.1     > /dev/null 2>&1 || true

    rm -rf /usr/local/kaezstd/bin/unzstd > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezstd/bin/zstdcat > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezstd/bin/zstdmt > /dev/null 2>&1 || true

    #openssl
    rm -rf $RPM_INSTALL_PREFIX/kae.so      > /dev/null 2>&1 || true
    rm -rf $RPM_INSTALL_PREFIX/kae.so.0    > /dev/null 2>&1 || true

    #kernel&uadk
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

#kernel
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
    #zip&zstp
    ln -sf /usr/local/kaezip/lib/libkaezip.so.1.3.11    /usr/local/kaezip/lib/libkaezip.so
    ln -sf /usr/local/kaezip/lib/libkaezip.so.1.3.11    /usr/local/kaezip/lib/libkaezip.so.0
    ln -sf /usr/local/kaezip/lib/libz.so.%{zlib_version}    /usr/local/kaezip/lib/libz.so
    ln -sf /usr/local/kaezip/lib/libz.so.%{zlib_version}    /usr/local/kaezip/lib/libz.so.1

    ln -sf /usr/local/kaezstd/lib/libkaezstd.so.0.0.1      /usr/local/kaezstd/lib/libkaezstd.so
    ln -sf /usr/local/kaezstd/lib/libkaezstd.so.0.0.1      /usr/local/kaezstd/lib/libkaezstd.so.0
    ln -sf /usr/local/kaezstd/lib/libzstd.so.%{zstd_version}    /usr/local/kaezstd/lib/libzstd.so
    ln -sf /usr/local/kaezstd/lib/libzstd.so.%{zstd_version}    /usr/local/kaezstd/lib/libzstd.so.1

    ln -sf /usr/local/kaezstd/bin/zstd    /usr/local/kaezstd/bin/unzstd
    ln -sf /usr/local/kaezstd/bin/zstd    /usr/local/kaezstd/bin/zstdcat
    ln -sf /usr/local/kaezstd/bin/zstd    /usr/local/kaezstd/bin/zstdmt

    #openssl
    ln -sf $RPM_INSTALL_PREFIX/kae.so.%{version}    $RPM_INSTALL_PREFIX/kae.so
    ln -sf $RPM_INSTALL_PREFIX/kae.so.%{version}    $RPM_INSTALL_PREFIX/kae.so.0

    
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

%preun
#zlib&zstd
if [ "$1" = "0" ] ; then  #0: uninstall
    rm -rf /usr/local/kaezip/lib/libz.so   > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezip/lib/libz.so.1   > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezip/lib/libkaezip.so   > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezip/lib/libkaezip.so.0 > /dev/null 2>&1 || true

    rm -rf /usr/local/kaezstd/lib/libzstd.so   > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezstd/lib/libzstd.so.1   > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezstd/lib/libkaezstd.so   > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezstd/lib/libkaezstd.so.0 > /dev/null 2>&1 || true

    rm -rf /usr/local/kaezstd/bin/unzstd > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezstd/bin/zstdcat > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezstd/bin/zstdmt > /dev/null 2>&1 || true

    rm -f /var/log/kaezip.log              > /dev/null 2>&1 || true
    rm -f /var/log/kaezip.log.old          > /dev/null 2>&1 || true

fi

# openssl
if [ "$1" = "0" ] ; then  #0: uninstall
    rm -rf $RPM_INSTALL_PREFIX/kae.so   > /dev/null 2>&1 || true
    rm -rf $RPM_INSTALL_PREFIX/kae.so.0 > /dev/null 2>&1 || true
    rm -f /var/log/kae.log              > /dev/null 2>&1 || true
    rm -f /var/log/kae.log.old          > /dev/null 2>&1 || true
fi

#kernel & uadk
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
* Tue Jun 03 2022 jinbinhua <liuyang645@huawei.com> 2.0.0-2
- Second Spec Version Include kunpeng accelerator engine Code

* Tue Jan 07 2020 jinbinhua <jinbinhua@huawei.com> 1.2.7-1
- First Spec Version Include kunpeng accelerator engine Code
