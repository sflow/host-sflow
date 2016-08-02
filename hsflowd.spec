Summary: host sFlow daemon
Name: hsflowd
Version: 2.0.1
Release: 1
License: http://sflow.net/license.html
Group: Applications/Internet
URL: http://sflow.net
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}
Requires(post): chkconfig

%description
This program implements the host sFlow(R) standard - sending
key performance metrics to an sFlow collector to enable
highly-scalable monitoring of all critical resources in
the network. If Open VSwitch is present, will also control
the Open VSwitch sFlow configuration.

%prep
%setup

%build
make FEATURES=%{_FEATURES}

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
/etc/init.d/hsflowd
/lib/systemd/system/hsflowd.service
%doc README LICENSE INSTALL.Linux
/etc/hsflowd/modules/

%changelog
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

