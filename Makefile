# This software is distributed under the following license:
# http://sflow.net/license.html

# note - shell invocation with `` quotes is portable
# between GNU and BSD make

PROG=hsflowd
MY_RPM_TOP=/tmp/HSFLOWD_RPM_TOP
MY_RPM_BUILDROOT=/tmp/HSFLOWD_RPM_BUILD_ROOT

all: $(PROG)

$(PROG):
	cd src/sflow; $(MAKE)
	cd src/json; $(MAKE)
	PLATFORM=`uname`; \
	MYVER=`./getVersion`; \
	MYREL=`./getRelease`; \
	cd src/$$PLATFORM; $(MAKE) VERSION=$$MYVER RELEASE=$$MYREL

clean:
	cd src/sflow; $(MAKE) clean
	cd src/json; $(MAKE) clean
	PLATFORM=`uname`; \
	MYVER=`./getVersion`; \
	MYREL=`./getRelease`; \
	cd src/$$PLATFORM; $(MAKE) VERSION=$$MYVER RELEASE=$$MYREL clean

install:
	PLATFORM=`uname`; \
	MYVER=`./getVersion`; \
	MYREL=`./getRelease`; \
	cd src/$$PLATFORM; $(MAKE) VERSION=$$MYVER RELEASE=$$MYREL install

schedule:
	PLATFORM=`uname`; \
	MYVER=`./getVersion`; \
	MYREL=`./getRelease`; \
	cd src/$$PLATFORM; $(MAKE) VERSION=$$MYVER RELEASE=$$MYREL schedule

dist: clean
	MYVER=`./getVersion`; \
	MYREL=`./getRelease`; \
	MYTARDIR=$(PROG)-$$MYVER-$$MYREL; \
	MYTARBALL=$$MYTARDIR.tar.gz; \
	MYTMP=.tmpdist; \
	rm -rf $$MYTMP; \
	MYTMPDIR=$$MYTMP/$$MYTARDIR; \
	mkdir -p $$MYTMPDIR; \
	rsync -a --exclude=".*" --exclude="*~" --exclude="*.o" --exclude="*.so" --exclude="*.a" --exclude="$(PROG)[-_][0-9]*" . $$MYTMPDIR; \
	cd $$MYTMP; \
	tar czf ../$$MYTARBALL $$MYTARDIR; \
	cd ..; \
	rm -rf $$MYTMP

rpm: dist
	MYARCH=`uname -m`; \
	MYVER=`./getVersion`; \
	MYREL=`./getRelease`; \
	MYTARBALL=$(PROG)-$$MYVER-$$MYREL.tar.gz; \
	mkdir -p $(MY_RPM_TOP)/BUILD; \
	mkdir -p $(MY_RPM_TOP)/SRPMS; \
	mkdir -p $(MY_RPM_TOP)/RPMS; \
	MYSRCDIR=$(MY_RPM_TOP)/SOURCES; \
	rm -rf $$MYSRCDIR; \
	mkdir -p $$MYSRCDIR; \
	cp $$MYTARBALL $$MYSRCDIR; \
	rpmbuild --define "_topdir $(MY_RPM_TOP)" --define "_FEATURES \"$(FEATURES)\"" --buildroot=$(MY_RPM_BUILDROOT) -ba $(PROG).spec; \
	echo "==============="; \
	MYRPM="$(MY_RPM_TOP)/RPMS/$$MYARCH/$(PROG)-$$MYVER-$$MYREL.$$MYARCH.rpm"; \
	MYSRPM="$(MY_RPM_TOP)/SRPMS/$(PROG)-$$MYVER-$$MYREL.src.rpm"; \
	echo "copying new RPMs $$MYRPM and $$MYSRPM back to current directory"; \
	cp $$MYRPM $$MYSRPM .

xenrpm:
	MYARCH=`uname -m`; \
	MYVER=`./getVersion`; \
	MYREL=`./getRelease`; \
	VDIR=$(PROG)-$$MYVER-$$MYREL; \
	rm -rf /tmp/$$VDIR; \
	mkdir /tmp/$$VDIR && cp -r * /tmp/$$VDIR && mv /tmp/$$VDIR . && tar cvzf $$VDIR.tar.gz $$VDIR; \
	MYSRCDIR=$(MY_RPM_TOP)/SOURCES; \
	rm -rf $$MYSRCDIR; \
	mkdir -p $$MYSRCDIR; \
	cp $$VDIR.tar.gz $$MYSRCDIR; \
	mkdir $(MY_RPM_TOP)/SRPMS; \
	mkdir $(MY_RPM_TOP)/RPMS; \
	mkdir $(MY_RPM_TOP)/RPMS/x86_64; \
	rpmbuild --define "_topdir $(MY_RPM_TOP)" --buildroot=$(MY_RPM_BUILDROOT) -ba $(PROG)-xen.spec; \
	echo "==============="; \
	MYRPM="$(MY_RPM_TOP)/RPMS/$$MYARCH/$(PROG)-$$MYVER-$$MYREL.$$MYARCH.rpm"; \
	MYSRPM="$(MY_RPM_TOP)/SRPMS/$(PROG)-$$MYVER-$$MYREL.src.rpm"; \
	echo "copying new RPMs $$MYRPM and $$MYSRPM back to current directory"; \
	cp $$MYRPM $$MYSRPM .

aixrpm:
	MYVER=`./getVersion`; \
	MYREL=`./getRelease`; \
	SOURCES=/opt/freeware/src/packages/SOURCES; \
	MYSRCDIR=$$SOURCES/$(PROG)-$$MYVER; \
	rm -rf $$MYSRCDIR; \
	cp -r . $$MYSRCDIR; \
	tar cf $$MYSRCDIR.tar -C $$SOURCES $(PROG)-$$MYVER; \
	gzip -f $$MYSRCDIR.tar; \
	rpm -ba $(PROG).spec.aix

pkg:
	PLATFORM=`uname`; \
	MYVER=`./getVersion`; \
	MYREL=`./getRelease`; \
	MYSRCDIR=src/$$PLATFORM/scripts/$(PROG)-$$MYVER; \
	rm -rf $$MYSRCDIR; \
	mkdir -p $$MYSRCDIR; \
	mkdir -p $$MYSRCDIR/etc; cp src/$$PLATFORM/scripts/hsflowd.conf $$MYSRCDIR/etc; \
	mkdir -p $$MYSRCDIR/usr/sbin; cp src/$$PLATFORM/hsflowd $$MYSRCDIR/usr/sbin; \
	mkdir -p $$MYSRCDIR/lib/svc/method; cp src/$$PLATFORM/scripts/svc-hsflowd $$MYSRCDIR/lib/svc/method; \
	mkdir -p $$MYSRCDIR/var/svc/manifest/site; cp src/$$PLATFORM/scripts/hsflowd.xml $$MYSRCDIR/var/svc/manifest/site; \
	pkgmk -o -r $$MYSRCDIR -f src/$$PLATFORM/scripts/Prototype ; \
	pkgtrans /var/spool/pkg /tmp/$(PROG)-$$MYVER-$$MYREL hsflowd; \
	mv /tmp/$(PROG)-$$MYVER-$$MYREL .

deb: $(PROG)
	MYARCH=`uname -m|sed 's/x86_64/amd64/'`; \
	MYVER=`./getVersion`; \
	MYREL=`./getRelease`; \
	PLATFORM=`uname`; \
	mkdir -p debian/DEBIAN; \
	mkdir -p debian/usr/sbin; \
	mkdir -p debian/etc/init.d; \
	mkdir -p debian/etc/hsflowd/modules; \
	mkdir -p debian/lib/systemd/system; \
	mkdir -p debian/etc/dbus-1/system.d; \
	install DEBIAN_build/control debian/DEBIAN; \
	sed -i -e s/_PACKAGE_/$(PROG)/g debian/DEBIAN/control; \
	sed -i -e s/_VERSION_/$${MYVER}-$${MYREL}/g debian/DEBIAN/control; \
	chmod 644 debian/DEBIAN/control; \
	install -m 555 DEBIAN_build/conffiles debian/DEBIAN; \
	install -m 555 DEBIAN_build/preinst debian/DEBIAN; \
	install -m 555 DEBIAN_build/postinst debian/DEBIAN; \
	install -m 555 DEBIAN_build/prerm debian/DEBIAN; \
	cd src/$$PLATFORM; $(MAKE) VERSION=$$MYVER RELEASE=$$MYREL INSTROOT="../../debian" install; cd ../..; \
        pwd; \
	cd debian; \
	find . -type d | xargs chmod 755; \
	md5sum `find usr etc -type f` > DEBIAN/md5sums; \
	cd ..; \
	dpkg-deb --build debian hsflowd_$${MYVER}-$${MYREL}_$$MYARCH.deb

xenserver: xenrpm
	cd xenserver-ddk; $(MAKE) clean; $(MAKE)

.PHONY: $(PROG) clean install schedule rpm xenserver

