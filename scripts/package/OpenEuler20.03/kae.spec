Name:          libkae
Summary:       Huawei Kunpeng Accelerator Engine
Version:       1.3.13
Release:       1%dist
License:       Apache-2.0
Source:        %{name}-%{version}.tar.gz
ExclusiveOS:   linux
BuildRoot:     %{_tmppath}/%{name}-%{version}-root
Prefix: /usr/local/lib/engines-1.1
Conflicts:     %{name} < %{version}-%{release}
Provides:      %{name} = %{version}-%{release}
Requires:      libwd >= %{version}
Autoreq: no
Autoprov: no
Prefix: /usr/local/lib/engines-1.1

%description
This package contains the Huawei Kunpeng Accelerator Engine

%prep
%global debug_package %{nil}
%setup -c -n %{name}-%{version}

%build
cd KAE
chmod +x configure
./configure
make

%install
mkdir -p ${RPM_BUILD_ROOT}/usr/local/lib/engines-1.1
install -b -m -755 KAE/libkae.so.%{version} ${RPM_BUILD_ROOT}/usr/local/lib/engines-1.1

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(755,root,root)
/usr/local/lib/engines-1.1/libkae.so.%{version}

%pre
if [ "$1" = "2" ] ; then  #2: update
    rm -rf $RPM_INSTALL_PREFIX/kae.so      > /dev/null 2>&1 || true
    rm -rf $RPM_INSTALL_PREFIX/kae.so.0    > /dev/null 2>&1 || true
fi

%post
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    ln -sf $RPM_INSTALL_PREFIX/libkae.so.%{version}    $RPM_INSTALL_PREFIX/kae.so
    ln -sf $RPM_INSTALL_PREFIX/libkae.so.%{version}    $RPM_INSTALL_PREFIX/kae.so.0
fi
/sbin/ldconfig

%preun
if [ "$1" = "0" ] ; then  #0: uninstall
    rm -rf $RPM_INSTALL_PREFIX/kae.so   > /dev/null 2>&1 || true
    rm -rf $RPM_INSTALL_PREFIX/kae.so.0 > /dev/null 2>&1 || true
    rm -f /var/log/kae.log              > /dev/null 2>&1 || true
    rm -f /var/log/kae.log.old          > /dev/null 2>&1 || true
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
