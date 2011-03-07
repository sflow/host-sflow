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

xenserver: rpm
	cd xenserver-ddk; $(MAKE) clean; $(MAKE)
