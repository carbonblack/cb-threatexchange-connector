%define name python-cb-threatexchange-connector
%define version 1.2
%define unmangled_version 1.2
%define release 1
%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}

Summary: Carbon Black ThreatExchange Connector
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{unmangled_version}.tar.gz
License: MIT
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: Bit9
Url: http://www.bit9.com/

%description
UNKNOWN

%prep
%setup -n %{name}-%{unmangled_version}

%build
pyinstaller cb-threatexchange-connector.spec

%install
python setup.py install_cb --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%pre
if [ -f "/etc/cb/integrations/threatexchange/connector.conf" ]; then
    cp /etc/cb/integrations/threatexchange/connector.conf /tmp/__bridge.conf.backup
fi

%post
if [ -f "/tmp/__bridge.conf.backup" ]; then
    mv /tmp/__bridge.conf.backup /etc/cb/integrations/threatexchange/connector.conf
fi

%posttrans
chkconfig --add cb-threatexchange-connector
chkconfig --level 345 cb-threatexchange-connector on

# not auto-starting because conf needs to be updated
#/etc/init.d/cb-threatexchange-connector start

mkdir -p /usr/share/cb/integrations/threatexchange/db

%preun
/etc/init.d/cb-threatexchange-connector stop

# only delete the chkconfig entry when we uninstall for the last time,
# not on upgrades
if [ "X$1" = "X0" ]
then
    echo "deleting threatexchange chkconfig entry on uninstall"
    chkconfig --del cb-threatexchange-connector
fi


%files -f INSTALLED_FILES
%defattr(-,root,root)

