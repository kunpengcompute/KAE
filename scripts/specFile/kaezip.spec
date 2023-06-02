Name:          kae_zip
Summary:       Huawei Kunpeng Accelerator Engine Zip
Version:       2.0.0
Release:       1%dist
License:       Apache-2.0
Source:        KAE-%{version}.tar.gz
ExclusiveOS:   linux
BuildRoot:     %{_tmppath}/%{name}-%{version}-root
Conflicts:     %{name} < %{version}-%{release}
Provides:      %{name} = %{version}-%{release}
Requires:      libwd >= %{version}
Autoreq: no
Autoprov: no

%define zlib_version 1.2.11
%define zstd_version 1.5.2

%description
This package contains the Huawei Hisilicon Zip Accelerator Engine.

%prep
%global debug_package %{nil}
%setup -c -n %{name}-%{version}

%build
cd KAEZstd
sh build.sh install

cd ..
cd KAEZlib
sh setup.sh build

%install
mkdir -p ${RPM_BUILD_ROOT}/usr/local/KAEZlib/lib
mkdir -p ${RPM_BUILD_ROOT}/usr/local/KAEZlib/include
mkdir -p ${RPM_BUILD_ROOT}/usr/local/KAEZlib/lib/pkgconfig
mkdir -p ${RPM_BUILD_ROOT}/usr/local/KAEZlib/share/man/man3
install -b -m -755 KAEZlib/libkaezip.so.1.3.11                                  ${RPM_BUILD_ROOT}/usr/local/KAEZlib/lib
install -b -m -755 KAEZlib/include/kaezip.h                                         ${RPM_BUILD_ROOT}/usr/local/KAEZlib/include
install -b -m -755 KAEZlib/open_source/zlib-%{zlib_version}/libz.so.%{zlib_version} ${RPM_BUILD_ROOT}/usr/local/KAEZlib/lib
install -b -m -644 KAEZlib/open_source/zlib-%{zlib_version}/libz.a                  ${RPM_BUILD_ROOT}/usr/local/KAEZlib/lib
install -b -m -644 KAEZlib/open_source/zlib-%{zlib_version}/zlib.pc                 ${RPM_BUILD_ROOT}/usr/local/KAEZlib/lib/pkgconfig
install -b -m -644 KAEZlib/open_source/zlib-%{zlib_version}/zlib.3                  ${RPM_BUILD_ROOT}/usr/local/KAEZlib/share/man/man3
install -b -m -644 KAEZlib/open_source/zlib-%{zlib_version}/zlib.h                  ${RPM_BUILD_ROOT}/usr/local/KAEZlib/include
install -b -m -644 KAEZlib/open_source/zlib-%{zlib_version}/zconf.h                 ${RPM_BUILD_ROOT}/usr/local/KAEZlib/include

mkdir -p ${RPM_BUILD_ROOT}/usr/local/KAEZstd/lib
mkdir -p ${RPM_BUILD_ROOT}/usr/local/KAEZstd/include
mkdir -p ${RPM_BUILD_ROOT}/usr/local/KAEZstd/lib/pkgconfig
mkdir -p ${RPM_BUILD_ROOT}/usr/local/KAEZstd/share/man/man3
install -b -m -755 KAEZstd/libkaezstd.so.0.0.1                                      ${RPM_BUILD_ROOT}/usr/local/KAEZstd/lib
install -b -m -755 KAEZstd/include/kaezstd.h                                        ${RPM_BUILD_ROOT}/usr/local/KAEZstd/include
install -b -m -755 KAEZstd/open_source/zstd/lib/libzstd.so.%{zstd_version}          ${RPM_BUILD_ROOT}/usr/local/KAEZstd/lib
install -b -m -644 KAEZstd/open_source/zstd/lib/libzstd.a                           ${RPM_BUILD_ROOT}/usr/local/KAEZstd/lib
install -b -m -644 KAEZstd/open_source/zstd/lib/libzstd.pc                          ${RPM_BUILD_ROOT}/usr/local/KAEZstd/lib/pkgconfig
#install -b -m -644 KAEZstd/open_source/zstd/lib/zlib.3                             ${RPM_BUILD_ROOT}/usr/local/KAEZstd/share/man/man3
install -b -m -644 KAEZstd/open_source/zstd/lib/zstd.h                              ${RPM_BUILD_ROOT}/usr/local/KAEZstd/include
install -b -m -644 KAEZstd/open_source/zstd/lib/zdict.h                             ${RPM_BUILD_ROOT}/usr/local/KAEZstd/include
install -b -m -644 KAEZstd/open_source/zstd/lib/zstd_errors.h                       ${RPM_BUILD_ROOT}/usr/local/KAEZstd/include

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(755,root,root)
/usr/local/KAEZlib/lib/libkaezip.so.1.3.11
/usr/local/KAEZlib/include/kaezip.h
/usr/local/KAEZlib/lib/libz.so.%{zlib_version}
%defattr(644,root,root)
/usr/local/KAEZlib/lib/libz.a
/usr/local/KAEZlib/lib/pkgconfig/zlib.pc
/usr/local/KAEZlib/share/man/man3/zlib.3
/usr/local/KAEZlib/include/zlib.h
/usr/local/KAEZlib/include/zconf.h

%defattr(755,root,root)
/usr/local/KAEZstd/lib/libkaezstd.so.0.0.1
/usr/local/KAEZstd/include/kaezstd.h
/usr/local/KAEZstd/lib/libzstd.so.%{zstd_version}
%defattr(644,root,root)
/usr/local/KAEZstd/lib/libzstd.a
/usr/local/KAEZstd/lib/pkgconfig/libzstd.pc
#/usr/local/KAEZstd/share/man/man3/zlib.3
/usr/local/KAEZstd/include/zstd.h
/usr/local/KAEZstd/include/zdict.h
/usr/local/KAEZstd/include/zstd_errors.h

%pre
if [ "$1" = "2" ] ; then  #2: update
    rm -rf /usr/local/KAEZlib/lib/libkaezip.so     > /dev/null 2>&1 || true
    rm -rf /usr/local/KAEZlib/lib/libkaezip.so.0    > /dev/null 2>&1 || true
    rm -rf /usr/local/KAEZlib/lib/libz.so     > /dev/null 2>&1 || true
    rm -rf /usr/local/KAEZlib/lib/libz.so.1     > /dev/null 2>&1 || true

    rm -rf /usr/local/KAEZstd/lib/libkaezstd.so     > /dev/null 2>&1 || true
    rm -rf /usr/local/KAEZstd/lib/libkaezstd.so.0    > /dev/null 2>&1 || true
    rm -rf /usr/local/KAEZstd/lib/libzstd.so     > /dev/null 2>&1 || true
    rm -rf /usr/local/KAEZstd/lib/libzstd.so.1     > /dev/null 2>&1 || true
fi

%post
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    ln -sf /usr/local/KAEZlib/lib/libkaezip.so.1.3.11    /usr/local/KAEZlib/lib/libkaezip.so
    ln -sf /usr/local/KAEZlib/lib/libkaezip.so.1.3.11    /usr/local/KAEZlib/lib/libkaezip.so.0
    ln -sf /usr/local/KAEZlib/lib/libz.so.%{zlib_version}    /usr/local/KAEZlib/lib/libz.so
    ln -sf /usr/local/KAEZlib/lib/libz.so.%{zlib_version}    /usr/local/KAEZlib/lib/libz.so.1

    ln -sf /usr/local/KAEZstd/lib/libkaezstd.so.0.0.1      /usr/local/KAEZstd/lib/libkaezstd.so
    ln -sf /usr/local/KAEZstd/lib/libkaezstd.so.0.0.1      /usr/local/KAEZstd/lib/libkaezstd.so.0
    ln -sf /usr/local/KAEZstd/lib/libzstd.so.%{zstd_version}    /usr/local/KAEZstd/lib/libzstd.so
    ln -sf /usr/local/KAEZstd/lib/libzstd.so.%{zstd_version}    /usr/local/KAEZstd/lib/libzstd.so.1
fi
/sbin/ldconfig

%preun
if [ "$1" = "0" ] ; then  #0: uninstall
    rm -rf /usr/local/KAEZlib/lib/libz.so   > /dev/null 2>&1 || true
    rm -rf /usr/local/KAEZlib/lib/libz.so.1   > /dev/null 2>&1 || true
    rm -rf /usr/local/KAEZlib/lib/libkaezip.so   > /dev/null 2>&1 || true
    rm -rf /usr/local/KAEZlib/lib/libkaezip.so.0 > /dev/null 2>&1 || true
	
    rm -rf /usr/local/KAEZstd/lib/libzstd.so   > /dev/null 2>&1 || true
    rm -rf /usr/local/KAEZstd/lib/libzstd.so.1   > /dev/null 2>&1 || true
    rm -rf /usr/local/KAEZstd/lib/libkaezstd.so   > /dev/null 2>&1 || true
    rm -rf /usr/local/KAEZstd/lib/libkaezstd.so.0 > /dev/null 2>&1 || true
    rm -f /var/log/kaezip.log              > /dev/null 2>&1 || true
    rm -f /var/log/kaezip.log.old          > /dev/null 2>&1 || true
fi

%postun
/sbin/ldconfig

%changelog
* Tue Jan 07 2020 jinbinhua <jinbinhua@huawei.com> 1.2.7-1
- First Spec Version Include kunpeng accelerator engine Code
