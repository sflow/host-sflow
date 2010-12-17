# This software is distributed under the following license:
# http://host-sflow.sourceforge.net/license.html

PROG=hsflowd
VERSION=1.10
RPM_SOURCES_DIR=/usr/src/redhat/SOURCES
MY_SOURCES_DIR=$(RPM_SOURCES_DIR)/$(PROG)-$(VERSION)

PLATFORM=$(shell uname)

all: $(PROG)

hsflowd:
	cd src/sflow; $(MAKE)
	cd src/$(PLATFORM); $(MAKE)

clean:
	cd src/sflow; $(MAKE) clean
	cd src/$(PLATFORM); $(MAKE) clean

install:
	cd src/$(PLATFORM); $(MAKE) install

schedule:
	cd src/$(PLATFORM); $(MAKE) schedule

rpm:
	rm -rf $(MY_SOURCES_DIR)
	cp -r . $(MY_SOURCES_DIR)
	tar cz -C $(RPM_SOURCES_DIR) -f $(MY_SOURCES_DIR).tar.gz $(PROG)-$(VERSION)
	rpmbuild -ba $(PROG).spec
