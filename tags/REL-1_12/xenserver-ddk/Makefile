# the following values must be changed
SPEC := ../hsflowd.spec
VENDOR_CODE := hostsflow
VENDOR_NAME := Host sFlow
LABEL = xenserver-hsflowd
TEXT := Host sFlow agent

# versioning of pack
PACK_VERSION = $(XENSERVER_VERSION)
PACK_BUILD = $(XENSERVER_BUILD)

# versioning of RPM
RPM_VERSION := $(shell sed -ne 's/^Version: *//p' $(SPEC))
RPM_RELEASE := $(shell sed -ne 's/^Release: *//p' $(SPEC))

# no changes below here
RPMROOT := /usr/src/redhat
ARCH := i386
XENSERVER_VERSION := $(shell set -- `tr '-' ' ' </etc/redhat-release` && echo $$4)
XENSERVER_BUILD := $(shell set -- `tr '-' ' ' </etc/redhat-release` && echo $$5)
PACKAGE_NAME := $(shell sed -ne 's/^Name: *//p' $(SPEC))
PACKAGE := package
ISO := $(shell pwd)/$(PACKAGE_NAME).iso
METADATA_MD5 := $(DRIVER_NAME).metadata.md5

RPMS := $(PACKAGE_NAME)-$(RPM_VERSION)-$(RPM_RELEASE)
RPM_FILES := $(patsubst %, $(RPMROOT)/RPMS/$(ARCH)/%.$(ARCH).rpm, $(RPMS))


build-iso: build-rpms
	mkdir -p $(PACKAGE)
	cp -fp $(RPM_FILES) $(PACKAGE)
	cd $(PACKAGE) && /usr/local/bin/build-supplemental-pack.sh --output=$(dir $(ISO)) --vendor-code=$(VENDOR_CODE) "--vendor-name=$(VENDOR_NAME)" --label=$(LABEL) "--text=$(TEXT)" --version=$(PACK_VERSION) --build=$(PACK_BUILD) $(patsubst %, %.$(ARCH).rpm, $(RPMS))

build-tarball: build-rpms
	mkdir -p $(PACKAGE)
	cp -fp $(RPM_FILES) $(PACKAGE)
	cd $(PACKAGE) && /usr/local/bin/build-supplemental-pack.sh --output=$(dir $(ISO)) --vendor-code=$(VENDOR_CODE) "--vendor-name=$(VENDOR_NAME)" --label=$(LABEL) "--text=$(TEXT)" --version=$(PACK_VERSION) --build=$(PACK_BUILD) --no-iso --tarball $(patsubst %, %.$(ARCH).rpm, $(RPMS))

build-rpms:
	rpmbuild -bb --define "version $(RPM_VERSION)" --define "release $(RPM_RELEASE)" $(SPEC)

build-srctarballs:
	tar zcvf $(RPMROOT)/SOURCES/$(PACKAGE_NAME)-$(RPM_VERSION).tar.gz $(PACKAGE_NAME)-$(RPM_VERSION)

clean:
	rm -rf $(PACKAGE)

distclean: clean
	rm -f $(ISO) $(ISO).md5 $(METADATA_MD5)
