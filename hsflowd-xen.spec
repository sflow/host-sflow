Summary: host sFlow daemon
Name: hsflowd
Version: 2.0.12
Release: 2
License: http://sflow.net/license.html
Group: Applications/Internet
URL: http://sflow.net
Source0: %{name}-%{version}-%{release}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}
%define debug_package %{nil}

%description
This program implements the host sFlow(R) standard - sending
key performance metrics to an sFlow collector to enable
highly-scalable monitoring of all critical resources in
the network. If Open VSwitch is present, will also control
the Open VSwitch sFlow configuration.

%prep
%setup -n %{name}-%{version}-%{release}

%build
make FEATURES="XEN"

%install
rm -rf %{buildroot}
make INSTROOT=%{buildroot} install

%clean
rm -rf %{buildroot}
make clean

%files
%defattr(-,root,root,-)
/usr/sbin/hsflowd
%config(noreplace) /etc/hsflowd.conf
%config(noreplace) /etc/dbus-1/system.d/net.sflow.hsflowd.conf
/etc/init.d/hsflowd
/lib/systemd/system/hsflowd.service 
%doc README LICENSE INSTALL.Linux
/etc/hsflowd/modules/

%post
# need this logic just for Xenserver package. It preserves config
# across Xenserver upgrades by copying the config to another directory
# so that we get a chance to merge the old and new configs.
if [ -n "$XS_PREVIOUS_INSTALLATION" ]; then
  # upgrade in progress
  if [ -r $XS_PREVIOUS_INSTALLATION/etc/hsflowd.conf ]; then
    mv -f /etc/hsflowd.conf /etc/hsflowd.conf.rpmnew
    cp -fp $XS_PREVIOUS_INSTALLATION/etc/hsflowd.conf /etc
    # TODO: insert ovs {} ?
  fi
fi

%preun
if [ $1 = 0 ]; then
  /sbin/service hsflowd stop > /dev/null 2>&1;
fi

%changelog
* Thu Jan 19 2017 nhm <neil.mckee@inmon.com>
- update for XenServer 7.0 and systemd
* Tue Jul 26 2016 nhm <neil.mckee@inmon.com>
- fork custom spec file for xen
* Wed Jul 20 2016 nhm <neil.mckee@inmon.com>
- add systemd service file
- remove sflowovsd (now an hsflowd module)
- remove automatic scheduling
* Fri Oct 08 2010 nhm <nhm@noodle.sf.inmon.com>
- move install from /usr/local/sbin to /usr/sbin
* Mon Aug 30 2010 nhm <nhm@noodle.sf.inmon.com>
- add sflowovsd
* Thu Jul 22 2010 nhm <nhm@chow.sf.inmon.com>
- use BuildRoot
* Fri Jul 09 2010 nhm <nhm@chow.sf.inmon.com>
- added post and preun,  and require chkconfig
* Thu Feb 11 2010 nhm <nhm@chow.sf.inmon.com> 
- Initial build.

