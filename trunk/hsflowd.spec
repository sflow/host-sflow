Summary: host sFlow daemon
Name: hsflowd
Version: 1.19
Release: 1
License: http://host-sflow.sourceforge.net/license.html
Group: Applications/Internet
URL: http://host-sflow.sourceforge.net
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}
Requires(post): chkconfig

%define OpenVSwitchControl /usr/bin/ovs-vsctl

%description
This program implements the host sFlow(R) standard - sending
key performance metrics to an sFlow collector to enable
highly-scalable monitoring of all critical resources in
the network. If Open VSwitch is present, will also control
the Open VSwitch sFlow configuration.

%prep
%setup

%build
make

%install
rm -rf %{buildroot}
make INSTROOT=%{buildroot} install

%clean
rm -rf %{buildroot}
make clean


%files
%defattr(-,root,root,-)
/usr/sbin/hsflowd
/usr/sbin/sflowovsd
%config /etc/hsflowd.conf
/etc/init.d/hsflowd
/etc/init.d/sflowovsd
%doc README LICENSE INSTALL.Linux

%post
# schedule daemon(s)
/sbin/chkconfig --add hsflowd
if [ -x %{OpenVSwitchControl} ]; then /sbin/chkconfig --add sflowovsd; fi
# need this logic just for Xenserver package. It preserves config
# across Xenserver upgrades by copying the config to another directory
# so that we get a chance to merge the old and new configs.
if [ -n "$XS_PREVIOUS_INSTALLATION" ]; then
  # upgrade in progress
  if [ -r $XS_PREVIOUS_INSTALLATION/etc/hsflowd.conf ]; then
    mv -f /etc/hsflowd.conf /etc/hsflowd.conf.rpmnew
    cp -fp $XS_PREVIOUS_INSTALLATION/etc/hsflowd.conf /etc
  fi
fi
if [ -r /etc/hsflowd.conf -a -r /etc/hsflowd.conf.rpmnew ]; then
  # merge new material from hsflowd.conf.rpmnew with hsflowd.conf
  # which may contain changes.  (Nothing to do at the moment.)
  # And remove the rpmnew file.
  rm -f /etc/hsflowd.conf.rpmnew
fi

%preun
if [ $1 = 0 ]; then
  /sbin/service hsflowd stop > /dev/null 2>&1
  /sbin/service sflowovsd stop > /dev/null 2>&1
  /sbin/chkconfig --del hsflowd
  /sbin/chkconfig --del sflowovsd
fi

%changelog
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

