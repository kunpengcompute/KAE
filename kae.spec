Name:          libkae
Summary:       Huawei Kunpeng Accelerator Engine
Version:       1.3.10
Release:       1%dist
License:       Apache-2.0
Source:        %{name}-%{version}.tar.gz
Vendor:        Huawei Corporation
ExclusiveOS:   linux
URL:           https://support.huawei.com 
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
* Tue Jan 07 2020 jinbinhua <jinbinhua@huawei.com> 1.2.7-1
- First Spec Version Include kunpeng accelerator engine Code