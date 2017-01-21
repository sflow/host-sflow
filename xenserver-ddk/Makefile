# the following values must be changed
SPEC := ../hsflowd-xen.spec 
VENDOR_CODE := hostsflow
VENDOR_NAME := Host sFlow
LABEL = hsflowd-xenserver
TEXT := Host sFlow agent

# versioning of pack
PACK_VERSION = $(XENSERVER_VERSION)
PACK_BUILD = $(XENSERVER_BUILD)

# versioning of RPM
RPM_VERSION := $(shell sed -ne 's/^Version: *//p' $(SPEC))
RPM_RELEASE := $(shell sed -ne 's/^Release: *//p' $(SPEC)) 

# no changes below here
RPMDIR := $(shell rpm --eval %{_rpmdir})
RPMSOURCES := $(shell rpm --eval %{_sourcedir})
ARCH := $(shell uname -p)
XENSERVER_VERSION := $(shell set -- `tr '-' ' ' </etc/redhat-release` && echo $$3)
XENSERVER_BUILD := $(shell set -- `tr '-' ' ' </etc/redhat-release` && echo $$4)
PACKAGE_NAME := $(shell sed -ne 's/^Name: *//p' $(SPEC))
ISO := $(PACKAGE_NAME).iso
ISO_MD5 := $(ISO).md5
TAR := $(PACKAGE_NAME).tar.gz
METADATA_MD5 := $(PACKAGE_NAME).metadata.md5

RPMS := $(PACKAGE_NAME)-$(RPM_VERSION)-$(RPM_RELEASE)
RPM_FILES := $(patsubst %, $(RPMDIR)/$(ARCH)/%.$(ARCH).rpm, $(RPMS))


build-iso: build-rpms
	python setup.py "--output=$(dir $(ISO))" --iso "--vendor-code=$(VENDOR_CODE)" "--vendor-name=$(VENDOR_NAME)" "--label=$(LABEL)" "--text=$(TEXT)" "--version=$(PACK_VERSION)" "--build=$(PACK_BUILD)" $(RPM_FILES)

build-tarball: build-rpms
	python setup.py "--output=$(dir $(ISO))" --tar "--vendor-code=$(VENDOR_CODE)" "--vendor-name=$(VENDOR_NAME)" "--label=$(LABEL)" "--text=$(TEXT)" "--version=$(PACK_VERSION)" "--build=$(PACK_BUILD)" $(RPM_FILES)

build-rpms:
	rpmbuild -bb --define "version $(RPM_VERSION)" --define "release $(RPM_RELEASE)" $(SPEC)

build-srctarballs:
	mkdir -p $(RPMSOURCES)
	tar zcvf $(RPMSOURCES)/$(PACKAGE_NAME)-$(RPM_VERSION).tar.gz $(PACKAGE_NAME)-$(RPM_VERSION)

clean:
	rm -f $(ISO) $(ISO_MD5) $(TAR) $(METADATA_MD5)
