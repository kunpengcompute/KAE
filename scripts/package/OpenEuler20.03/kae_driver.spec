Name:          kae_driver
Summary:       Kunpeng Accelerator Engine Kernel Driver
Version:       1.3.13
Release:       1%dist
License:       GPL-2.0
Source:        %{name}-%{version}.tar.gz
ExclusiveOS:   linux
BuildRoot:     %{_tmppath}/%{name}-%{version}-root
Conflicts:     %{name} < %{version}-%{release}
Provides:      %{name} = %{version}-%{release}
BuildRequires: gcc, make

%define kernel_version %(uname -r)
%define kae_driver_path  %{_builddir}/%{name}-%{version}/%{name}

%description
This package contains the Kunpeng Accelerator Engine Kernel Driver

%package -n uacce
Summary:   Unified/User-space-access-intended Accelerator Framework
Conflicts: %{name} < %{version}-%{release}
Provides:  %{name} = %{version}-%{release}

%description -n uacce
This package contains the Unified/User-space-access-intended Accelerator Framework.

%package -n hisi_sec2
Summary:   Huawei Hisilicon SEC Accelerator Driver
Requires:  uacce >= %{version}-%{release}
Conflicts: %{name} < %{version}-%{release}
Provides:  %{name} = %{version}-%{release}

%description -n hisi_sec2
This package contains the Huawei Hisilicon SEC Accelerator Driver.

%package -n hisi_hpre
Summary:   Huawei Hisilicon HPRE Accelerator Driver
Requires:  uacce >= %{version}-%{release}
Conflicts: %{name} < %{version}-%{release}
Provides:  %{name} = %{version}-%{release}

%description -n hisi_hpre
This package contains the Huawei Hisilicon HPRE Accelerator Driver.

%package -n hisi_zip
Summary:   Huawei Hisilicon ZIP Accelerator Driver
Requires:  uacce >= %{version}-%{release}
Conflicts: %{name} < %{version}-%{release}
Provides:  %{name} = %{version}-%{release}

%description -n hisi_zip
This package contains the Huawei Hisilicon ZIP Accelerator Driver.

%package -n hisi_rde
Summary:   Huawei Hisilicon RDE Accelerator Driver
Requires:  uacce >= %{version}-%{release}
Conflicts: %{name} < %{version}-%{release}
Provides:  %{name} = %{version}-%{release}

%description -n hisi_rde
This package contains the Huawei Hisilicon RDE Accelerator Driver.


%prep
%global debug_package %{nil}

%setup -c -n %{name}-%{version}

%build
cd kae_driver
make

%install
mkdir -p ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
mkdir -p ${RPM_BUILD_ROOT}/etc/modprobe.d
install -b -m -644 %{kae_driver_path}/uacce/uacce.ko              ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
install -b -m -644 %{kae_driver_path}/hisilicon/hisi_qm.ko        ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
install -b -m -644 %{kae_driver_path}/hisilicon/sec2/hisi_sec2.ko ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
install -b -m -644 %{kae_driver_path}/conf/hisi_sec2.conf         ${RPM_BUILD_ROOT}/etc/modprobe.d/hisi_sec2.conf
install -b -m -644 %{kae_driver_path}/hisilicon/hpre/hisi_hpre.ko ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
install -b -m -644 %{kae_driver_path}/conf/hisi_hpre.conf         ${RPM_BUILD_ROOT}/etc/modprobe.d/hisi_hpre.conf
install -b -m -644 %{kae_driver_path}/hisilicon/zip/hisi_zip.ko   ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
install -b -m -644 %{kae_driver_path}/conf/hisi_zip.conf          ${RPM_BUILD_ROOT}/etc/modprobe.d/hisi_zip.conf
install -b -m -644 %{kae_driver_path}/hisilicon/rde/hisi_rde.ko   ${RPM_BUILD_ROOT}/lib/modules/%{kernel_version}/extra
install -b -m -644 %{kae_driver_path}/conf/hisi_rde.conf          ${RPM_BUILD_ROOT}/etc/modprobe.d/hisi_rde.conf

%clean
rm -rf ${RPM_BUILD_ROOT}

%pre -n uacce
echo "checking installed modules"
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    echo "uacce modules start to install"
fi

%pre -n hisi_sec2
echo "checking installed modules"
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    echo "hisi_sec2 modules start to install"
fi

%pre -n hisi_hpre
echo "checking installed modules"
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    echo "hisi_hpre modules start to install"
fi

%pre -n hisi_zip
echo "checking installed modules"
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    echo "hisi_zip modules start to install"
fi

%pre -n hisi_rde
echo "checking installed modules"
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    echo "hisi_rde modules start to install"
fi

%post -n uacce
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    if [ -e /sbin/weak-modules ]; then
        echo "/lib/modules/%{kernel_version}/extra/uacce.ko" | /sbin/weak-modules --add-module --no-initramfs
        echo "/lib/modules/%{kernel_version}/extra/hisi_qm.ko" | /sbin/weak-modules --add-module --no-initramfs
    fi
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "uacce modules installed"

%post -n hisi_sec2
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    if [ -e /sbin/weak-modules ]; then
        echo "/lib/modules/%{kernel_version}/extra/hisi_sec2.ko" | /sbin/weak-modules --add-module --no-initramfs
    fi
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "hisi_sec2 modules installed"

%post -n hisi_hpre
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    if [ -e /sbin/weak-modules ]; then
        echo "/lib/modules/%{kernel_version}/extra/hisi_hpre.ko" | /sbin/weak-modules --add-module --no-initramfs
    fi
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "hisi_hpre modules installed"

%post -n hisi_zip
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    if [ -e /sbin/weak-modules ]; then
        echo "/lib/modules/%{kernel_version}/extra/hisi_zip.ko" | /sbin/weak-modules --add-module --no-initramfs
    fi
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "hisi_zip modules installed"

%post -n hisi_rde
if [[ "$1" = "1" || "$1" = "2" ]] ; then  #1: install 2: update
    if [ -e /sbin/weak-modules ]; then
        echo "/lib/modules/%{kernel_version}/extra/hisi_rde.ko" | /sbin/weak-modules --add-module --no-initramfs
    fi
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "hisi_rde modules installed"

%preun -n uacce
if [ -e /sbin/weak-modules ]; then
    echo "/lib/modules/%{kernel_version}/extra/uacce.ko" | /sbin/weak-modules --remove-module --no-initramfs
    echo "/lib/modules/%{kernel_version}/extra/hisi_qm.ko" | /sbin/weak-modules --remove-module --no-initramfs
fi
/sbin/depmod -a > /dev/null 2>&1 || true
if [ "$1" = "0" ] ; then  #0: uninstall
    echo "uacce modules uninstalling"
fi

%preun -n hisi_sec2
if [ -e /sbin/weak-modules ]; then
    echo "/lib/modules/%{kernel_version}/extra/hisi_sec2.ko" | /sbin/weak-modules --remove-module --no-initramfs
fi
if [ "$1" = "0" ] ; then  #0: uninstall
    echo "hisi_sec2 modules uninstalling"
fi

%preun -n hisi_hpre
if [ -e /sbin/weak-modules ]; then
    echo "/lib/modules/%{kernel_version}/extra/hisi_hpre.ko" | /sbin/weak-modules --remove-module --no-initramfs
fi
if [ "$1" = "0" ] ; then  #0: uninstall
    echo "hisi_hpre modules uninstalling"
fi

%preun -n hisi_zip
if [ -e /sbin/weak-modules ]; then
    echo "/lib/modules/%{kernel_version}/extra/hisi_zip.ko" | /sbin/weak-modules --remove-module --no-initramfs
fi
if [ "$1" = "0" ] ; then  #0: uninstall
    echo "hisi_zip modules uninstalling"
fi

%preun -n hisi_rde
if [ -e /sbin/weak-modules ]; then
    echo "/lib/modules/%{kernel_version}/extra/hisi_rde.ko" | /sbin/weak-modules --remove-module --no-initramfs
fi
if [ "$1" = "0" ] ; then  #0: uninstall
    echo "hisi_rde modules uninstalling"
fi

%postun -n uacce
if [ "$1" = "0" ] ; then  #0: uninstall
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "uacce modules uninstalled"

%postun -n hisi_sec2
if [ "$1" = "0" ] ; then  #0: uninstall
    if [ -e /sbin/weak-modules ]; then
        echo "/lib/modules/%{kernel_version}/extra/hisi_sec2.ko" | /sbin/weak-modules --remove-module --no-initramfs
    fi
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "hisi_sec2 modules uninstalled"

%postun -n hisi_hpre
if [ "$1" = "0" ] ; then  #0: uninstall
    if [ -e /sbin/weak-modules ]; then
        echo "/lib/modules/%{kernel_version}/extra/hisi_hpre.ko" | /sbin/weak-modules --remove-module --no-initramfs
    fi
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "hisi_hpre modules uninstalled"

%postun -n hisi_zip
if [ "$1" = "0" ]; then  #0: uninstall
    if [ -e /sbin/weak-modules ]; then
        echo "/lib/modules/%{kernel_version}/extra/hisi_zip.ko" | /sbin/weak-modules --remove-module --no-initramfs
    fi
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "hisi_zip modules uninstalled"

%postun -n hisi_rde
if [ "$1" = "0" ] ; then  #0: uninstall
    if [ -e /sbin/weak-modules ]; then
        echo "/lib/modules/%{kernel_version}/extra/hisi_rde.ko" | /sbin/weak-modules --remove-module --no-initramfs
    fi
    /sbin/depmod -a > /dev/null 2>&1 || true
fi
echo "hisi_rde modules uninstalled"

%files -n uacce
%defattr(644,root,root)
/lib/modules/%{kernel_version}/extra/uacce.ko
/lib/modules/%{kernel_version}/extra/hisi_qm.ko


%files -n hisi_sec2
%defattr(644,root,root)
/lib/modules/%{kernel_version}/extra/hisi_sec2.ko
%config(noreplace) /etc/modprobe.d/hisi_sec2.conf

%files -n hisi_hpre
%defattr(644,root,root)
/lib/modules/%{kernel_version}/extra/hisi_hpre.ko
%config(noreplace) /etc/modprobe.d/hisi_hpre.conf

%files -n hisi_zip
%defattr(644,root,root)
/lib/modules/%{kernel_version}/extra/hisi_zip.ko
%config(noreplace) /etc/modprobe.d/hisi_zip.conf

%files -n hisi_rde
%defattr(644,root,root)
/lib/modules/%{kernel_version}/extra/hisi_rde.ko
%config(noreplace) /etc/modprobe.d/hisi_rde.conf

%changelog
* Tue Mar 19 2024 liuyang <liuyang645@huawei.com> 1.3.13-1
- Update Spec Version Include all Kunpeng Accelerator Engine Kernel Driver Code

* Tue Jan 2 2024 liuyang <liuyang645@huawei.com> 1.3.12-1
- Update Spec Version Include all Kunpeng Accelerator Engine Kernel Driver Code

* Tue Jan 07 2020 jinbinhua <jinbinhua@huawei.com> 1.2.7-1
- First Spec Version Include all Kunpeng Accelerator Engine Kernel Driver Code
