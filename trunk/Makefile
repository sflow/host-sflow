# This software is distributed under the following license:
# http://host-sflow.sourceforge.net/license.html

# note - shell invocation with `` quotes is portable
# between GNU and BSD make

PROG=hsflowd
RPM_SOURCES_DIR=/usr/src/redhat/SOURCES

all: $(PROG) 

$(PROG):
	cd src/sflow; $(MAKE)
	PLATFORM=`uname`; \
	MYVER=`./getVersion`; \
        MYREL=`./getRelease`; \
        cd src/$$PLATFORM; $(MAKE) VERSION=$$MYVER RELEASE=$$MYREL

clean:
	cd src/sflow; $(MAKE) clean
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
	install -m 700 src/Linux/scripts/hsflowd src/Linux/scripts/sflowovsd debian/etc/init.d; \
	install -m 644 src/Linux/scripts/hsflowd.conf debian/etc; \
        pushd debian; \
	find . -type d | xargs chmod 755; \
        md5sum `find usr etc -type f` > DEBIAN/md5sums; \
        popd; \
	dpkg-deb --build debian hsflowd_$${MYVER}-$${MYREL}_$$MYARCH.deb

xenserver: rpm
	cd xenserver-ddk; $(MAKE) clean; $(MAKE)

.PHONY: $(PROG) clean install schedule rpm xenserver

