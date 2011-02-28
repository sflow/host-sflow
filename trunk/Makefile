# This software is distributed under the following license:
# http://host-sflow.sourceforge.net/license.html

# note - shell invocation with `` quotes is portable
# between GNU and BSD make

PROG=hsflowd
RPM_SOURCES_DIR=/usr/src/redhat/SOURCES
MY_SOURCES_DIR=$(RPM_SOURCES_DIR)/$(PROG)-$(VERSION)

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
	VERSION=`./getVersion`
	rm -rf $(MY_SOURCES_DIR)
	cp -r . $(MY_SOURCES_DIR)
	PLATFORM=`uname`; \
	MYVER=`./getVersion`; \
        MYREL=`./getRelease`; \
	tar cz -C $(RPM_SOURCES_DIR) -f $(MY_SOURCES_DIR).tar.gz $(PROG)-$$VERSION
	rpmbuild -ba $(PROG).spec

xenserver: rpm
	cd xenserver-ddk; $(MAKE)

