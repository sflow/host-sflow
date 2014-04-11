# This software is distributed under the following license:
# http://host-sflow.sourceforge.net/license.html

# note - shell invocation with `` quotes is portable
# between GNU and BSD make

PROG=hsflowd
RPM_SOURCES_DIR=/usr/src/redhat/SOURCES

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

rpm:
	PLATFORM=`uname`; \
	MYVER=`./getVersion`; \
        MYREL=`./getRelease`; \
	MYSRCDIR=$(RPM_SOURCES_DIR)/$(PROG)-$$MYVER; \
	rm -rf $$MYSRCDIR; \
	cp -r . $$MYSRCDIR; \
	tar cz -C $(RPM_SOURCES_DIR) -f $$MYSRCDIR.tar.gz $(PROG)-$$MYVER; \
	rpmbuild -ba $(PROG).spec

aixrpm:
	PLATFORM=`uname`; \
	MYVER=`./getVersion`; \
        MYREL=`./getRelease`; \
	SOURCES=/opt/freeware/src/packages/SOURCES; \
	MYSRCDIR=$$SOURCES/$(PROG)-$$MYVER; \
	rm -rf $$MYSRCDIR; \
	cp -r . $$MYSRCDIR; \
	tar cf $$MYSRCDIR.tar -C $$SOURCES $(PROG)-$$MYVER; \
        gzip -f $$MYSRCDIR.tar; \
	rpm -ba $(PROG)_aix.spec

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
	PLATFORM=`uname`; \
	MYARCH=`uname -m`; \
	MYVER=`./getVersion`; \
        MYREL=`./getRelease`; \
	mkdir -p debian/DEBIAN; \
        mkdir -p debian/usr/sbin; \
	mkdir -p debian/etc/init.d; \
	install DEBIAN_build/control debian/DEBIAN; \
	sed -i -e s/_PACKAGE_/$(PROG)/g debian/DEBIAN/control; \
	sed -i -e s/_VERSION_/$${MYVER}-$${MYREL}/g debian/DEBIAN/control; \
	chmod 644 debian/DEBIAN/control; \
	install -m 555 DEBIAN_build/postinst debian/DEBIAN; \
	install -m 555 DEBIAN_build/prerm debian/DEBIAN; \
	install -m 700 src/Linux/hsflowd src/Linux/sflowovsd debian/usr/sbin; \
	install -m 755 src/Linux/scripts/hsflowd.deb debian/etc/init.d/hsflowd; \
	install -m 755 src/Linux/scripts/sflowovsd.deb debian/etc/init.d/sflowovsd; \
	install -m 644 src/Linux/scripts/hsflowd.conf debian/etc; \
        cd debian; \
	find . -type d | xargs chmod 755; \
        md5sum `find usr etc -type f` > DEBIAN/md5sums; \
        cd ..; \
	dpkg-deb --build debian hsflowd_$${MYVER}-$${MYREL}_$$MYARCH.deb

xenserver: rpm
	cd xenserver-ddk; $(MAKE) clean; $(MAKE)

.PHONY: $(PROG) clean install schedule rpm xenserver

