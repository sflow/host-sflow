Summary: host sFlow daemon
Name: hsflowd
Version: 0.98
Release: 1
License: http://host-sflow.sourceforge.net/license.html
Group: Applications/Internet
URL: http://host-sflow.sourceforge.net
Source0: %{name}-%{version}.tar.gz
Requires(post): chkconfig

%description
This program implements the host-sFlow standard - sending
key performance metrics to an sFlow collector to enable
highly-scalable monitoring of all critical resources in
the network.

%prep
%setup

%build
make

%install
make install

%clean
make clean


%files
%defattr(-,root,root,-)
/usr/local/sbin/hsflowd
/etc/hsflowd.conf
/etc/init.d/hsflowd
%doc README LICENSE INSTALL.Linux

%post
/sbin/chkconfig --add hsflowd

%preun
if [ $1 = 0 ]; then
  /sbin/service hsflowd stop > /dev/null 2>&1
  /sbin/chkconfig --del hsflowd
fi

%changelog
* Fri Jul 09 2010 root <root@chow.sf.inmon.com>
- added post and preun,  and require chkconfig
* Thu Feb 11 2010 root <root@chow.sf.inmon.com> - 
- Initial build.

