Name:          libkaezip
Summary:       Huawei Kunpeng Accelerator Engine Zip
Version:       1.3.13
Release:       1%dist
License:       Apache-2.0
Source:        %{name}-%{version}.tar.gz
ExclusiveOS:   linux
BuildRoot:     %{_tmppath}/%{name}-%{version}-root
Conflicts:     %{name} < %{version}-%{release}
Provides:      %{name} = %{version}-%{release}
Requires:      libwd >= %{version}
Autoreq: no
Autoprov: no

%define zlib_version 1.2.11

%description
This package contains the Huawei Hisilicon Zip Accelerator Engine.

%prep
%global debug_package %{nil}
%setup -c -n %{name}-%{version}

%build
cd KAEzip
sh setup.sh build

%install
mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezip/lib
mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezip/include
mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezip/lib/pkgconfig
mkdir -p ${RPM_BUILD_ROOT}/usr/local/kaezip/share/man/man3
install -b -m -755 KAEzip/libkaezip.so.%{version} ${RPM_BUILD_ROOT}/usr/local/kaezip/lib
install -b -m -755 KAEzip/include/kaezip.h        ${RPM_BUILD_ROOT}/usr/local/kaezip/include
install -b -m -755 KAEzip/open_source/zlib-%{zlib_version}/libz.so.%{zlib_version} ${RPM_BUILD_ROOT}/usr/local/kaezip/lib
install -b -m -644 KAEzip/open_source/zlib-%{zlib_version}/libz.a ${RPM_BUILD_ROOT}/usr/local/kaezip/lib
install -b -m -644 KAEzip/open_source/zlib-%{zlib_version}/zlib.pc ${RPM_BUILD_ROOT}/usr/local/kaezip/lib/pkgconfig
install -b -m -644 KAEzip/open_source/zlib-%{zlib_version}/zlib.3 ${RPM_BUILD_ROOT}/usr/local/kaezip/share/man/man3
install -b -m -644 KAEzip/open_source/zlib-%{zlib_version}/zlib.h ${RPM_BUILD_ROOT}/usr/local/kaezip/include
install -b -m -644 KAEzip/open_source/zlib-%{zlib_version}/zconf.h ${RPM_BUILD_ROOT}/usr/local/kaezip/include

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(755,root,root)
/usr/local/kaezip/lib/libkaezip.so.%{version}
/usr/local/kaezip/include/kaezip.h
/usr/local/kaezip/lib/libz.so.%{zlib_version}
%defattr(644,root,root)
/usr/local/kaezip/lib/libz.a
/usr/local/kaezip/lib/pkgconfig/zlib.pc
/usr/local/kaezip/share/man/man3/zlib.3
/usr/local/kaezip/include/zlib.h
/usr/local/kaezip/include/zconf.h

%pre
if [ "$1" = "2" ] ; then  #2: update
    rm -rf /usr/local/kaezip/lib/libkaezip.so     > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezip/lib/libkaezip.so.0    > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezip/lib/libz.so     > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezip/lib/libz.so.1     > /dev/null 2>&1 || true
fi

%post
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    ln -sf /usr/local/kaezip/lib/libkaezip.so.%{version}    /usr/local/kaezip/lib/libkaezip.so
    ln -sf /usr/local/kaezip/lib/libkaezip.so.%{version}    /usr/local/kaezip/lib/libkaezip.so.0
    ln -sf /usr/local/kaezip/lib/libz.so.%{zlib_version}    /usr/local/kaezip/lib/libz.so
    ln -sf /usr/local/kaezip/lib/libz.so.%{zlib_version}    /usr/local/kaezip/lib/libz.so.1
fi
/sbin/ldconfig

%preun
if [ "$1" = "0" ] ; then  #0: uninstall
    rm -rf /usr/local/kaezip/lib/libz.so   > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezip/lib/libz.so.1   > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezip/lib/libkaezip.so   > /dev/null 2>&1 || true
    rm -rf /usr/local/kaezip/lib/libkaezip.so.0 > /dev/null 2>&1 || true
    rm -f /var/log/kaezip.log              > /dev/null 2>&1 || true
    rm -f /var/log/kaezip.log.old          > /dev/null 2>&1 || true
fi

%postun
/sbin/ldconfig

%changelog
* Tue Mar 19 2024 liuyang <liuyang645@huawei.com> 1.3.13-1
- Update Spec Version Include kunpeng accelerator engine Code

* Tue Jan 2 2024 liuyang <liuyang645@huawei.com> 1.3.12-1
- Update Spec Version Include kunpeng accelerator engine Code

* Tue Jan 07 2020 jinbinhua <jinbinhua@huawei.com> 1.2.7-1
- First Spec Version Include kunpeng accelerator engine Code