Summary: host sFlow daemon
Name: hsflowd
Version: 0.94
Release: 1
License: http://host-sflow.sourceforge.net/license.html
Group: Applications/Internet
URL: http://www.inmon.com
Source0: %{name}-%{version}.tar.gz

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
%doc README LICENSE INSTALL

%changelog
* Thu Feb 11 2010 root <root@chow.sf.inmon.com> - 
- Initial build.

