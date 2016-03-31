# This software is distributed under the following license:
# http://host-sflow.sourceforge.net/license.html

HEADERS= hsflowd.h hsflowtokens.h hsflow_ethtool.h sflowovsd.h cpu_utils.h Makefile

# compiler
#CC= g++
CC= gcc -std=gnu99

# optimization
OPT_FULL = -O3 -DNDEBUG
OPT_DEBUG = -g -ggdb
ifeq ($(OPT),)
	OPT=$(OPT_FULL)
endif

# base CFLAGS and LIBS
SFLOWDIR=../sflow
CFLAGS += -I. -I$(SFLOWDIR) $(OPT) -Wall -Wstrict-prototypes -Wunused-value -D_GNU_SOURCE -DHSP_VERSION=$(VERSION) -DUTHEAP
LIBS += $(SFLOWDIR)/libsflow.a -lresolv -lpthread

# if ULOG is not set, assume it should be "yes" if the include file is present
# (So you can use "make ULOG=no" to compile without this feature)
ifeq ($(ULOG),)
	ULOG=$(shell if test -r /usr/include/linux/netfilter_ipv4/ipt_ULOG.h; then echo "yes"; else echo "no"; fi)
endif
ifeq ($(ULOG),yes)
	CFLAGS += -DHSF_ULOG
endif

# if NFLOG is not set, assume it should be "yes" if the include file is present
# (So you can use "make NFLOG=no" to compile without this feature)
ifeq ($(NFLOG),)
	NFLOG=$(shell if test -r /usr/include/libnfnetlink/libnfnetlink.h; then echo "yes"; else echo "no"; fi)
endif
ifeq ($(NFLOG),yes)
#	CFLAGS += -I/usr/include/libnl3 -DHSF_NFLOG
#	LIBS += -lnl-3 -lnl-nf-3
	CFLAGS += -I/usr/include/libnfnetlink -DHSF_NFLOG
	LIBS += -lnfnetlink
endif

# make the inclusion of sflowovsd options
WITH_SFLOWOVSD=yes

# Cumulus Linux
ifeq ($(CUMULUS),)
	CUMULUS=$(shell if test -r /etc/os-release && grep -c 'Cumulus Linux' /etc/os-release >/dev/null 2>&1; then echo "yes"; else echo "no"; fi)
endif
# This turns on the use of ethtool for interface stats,
# identifies switch ports for individual counter-export
# and enables ULOG packet-sampling.
ifeq ($(CUMULUS),yes)
	CFLAGS += -DHSF_CUMULUS
	WITH_SFLOWOVSD=no
endif

# if JSON is not set, assume it should be "yes".
# (So you can use "make JSON=no" to compile without this feature)
ifeq ($(JSON),)
	JSON=yes
endif
ifeq ($(JSON),yes)
	JSONDIR=../json
	CFLAGS += -DHSF_JSON -I$(JSONDIR)
	LIBS += $(JSONDIR)/libjson.a -lm
endif

# if RTMETRIC is not set, assume it should be "yes".
# (So you can use "make RTMETRIC=no" to compile without this feature)
ifeq ($(RTMETRIC),)
	RTMETRIC=yes
endif
ifeq ($(RTMETRIC),yes)
	CFLAGS += -DHSF_RTMETRIC
endif

# if PCAP is not set, assume it should be "yes" if the include file is present
# (So you can use "make PCAP=no" to compile without this feature)
ifeq ($(PCAP),)
	PCAP=$(shell if test -r /usr/include/pcap.h; then echo "yes"; else echo "no"; fi)
endif
ifeq ($(PCAP),yes)
	CFLAGS += -DHSF_PCAP
	LIBS += -lpcap
endif

# Docker containers
# if DOCKER is not set, assume it should be "yes" if "docker ps" runs OK
# (So you can use "make DOCKER=no" to compile without this feature)
ifeq ($(DOCKER),)
	DOCKER=$(shell if docker ps >/dev/null 2>&1; then echo "yes"; else echo "no"; fi)
endif
ifeq ($(DOCKER),yes)
	CFLAGS += -DHSF_DOCKER -I$(JSONDIR)
	LIBS += $(JSONDIR)/libjson.a -lm -lcap
endif

# Check to see if container counters are under /sys/fs/cgroup/cpuacct/system.slice/ (Fedora)
# or /sys/fs/cgroup/cpuacct/docker/ (Ubuntu). The docker directory on Ubuntu only
# appears when the first container starts, so test for system.slice here.  This
# difference stems originally from the fact that Ubuntu systemd does not use slices.
ifeq ($(SYSTEM_SLICE),)
	SYSTEM_SLICE=$(shell if test -r /sys/fs/cgroup/cpuacct/system.slice; then echo "yes"; else echo "no"; fi)
endif
ifeq ($(SYSTEM_SLICE),yes)
	CFLAGS += -DHSF_SYSTEM_SLICE
endif

# if LIBVIRT is not set, then assume it should be "yes" if we find the library.
# Could test for the include file too,  but somtimes it is there even if the
# library is not.  Testing for libvirt-dev[el] might be better.
ifeq ($(LIBVIRT),)
	LIBVIRT=$(shell if ls /usr/lib/libvirt.* >/dev/null 2>&1; then echo "yes"; else echo "no"; fi)
endif

# if XEN_DDK is not set, then assume it should be "yes" if we are on a Xenserver DDK (or equivalent) system.
# Just test if the xenstore and xenctrl libs are present, and require the xenctrl.h include as well.
ifeq ($(XEN_DDK),)
	XEN_DDK=$(shell if ls /usr/lib*/libxenctrl.* >/dev/null 2>&1 && ls /usr/lib*/libxenstore.* >/dev/null 2>&1 && ls /usr/include/xenctrl.h >/dev/null 2>&1; then echo "yes"; else echo "no"; fi)
endif
# to compile with xen-sources instead, specify XEN_ROOT.  e.g. XEN_ROOT=/root/xen-3.2.0

# The options LIBVIRT=yes, XEN_DDK=yes and XEN_ROOT=<path> should be mutually exclusive.
# Enforce that here, so that XEN_ROOT takes priority, then XEN_DDK, then LIBVIRT.  It might
# work better to just have a TARGET=<xen|xensource|kvm|linux> options and insist that it be
# set to something before we proceed (like haproxy)
ifeq ($(LIBVIRT),yes)
	XEN_DDK=no
	XEN_ROOT=
endif
ifeq ($(XEN_DDK),yes)
	LIBVIRT=no
	XEN_ROOT=
endif
ifeq ($(XEN_ROOT),)
else
	LIBVIRT=no
	XEN_DDK=no
endif

# translate the selection into compile flags
ifeq ($(LIBVIRT),yes)
	CFLAGS += -DHSF_VRT -I/usr/include/libvirt -I/usr/include/libxml2
	LIBS += -lvirt -lxml2
endif

ifeq ($(XEN_ROOT),)
else
	include $(XEN_ROOT)/tools/Rules.mk
	CFLAGS += -DHSF_XEN -I$(XEN_XENSTORE) -I$(XEN_LIBXC)
	CFLAGS += -Wno-declaration-after-statement # turn off "mixed declarations and code" warning
	LIBS += -L$(XEN_XENSTORE) -L$(XEN_LIBXC) -lxenstore -lxenctrl
endif

ifeq ($(XEN_DDK),yes)
	CFLAGS += -DHSF_XEN
	LIBS += -lxenstore -lxenctrl
endif


# allow HSF_XEN_VBD_PATH to be overridden here.  For example: make HSF_XEN_VBD_PATH=/sys/devices
ifeq ($(HSF_XEN_VBD_PATH),)
else
	CFLAGS += -DHSF_XEN_VBD_PATH=$(HSF_XEN_VBD_PATH)
endif

# xs.h became xenstore.h by 6.5. Detect that and set a flag.  Could drive this by reading
# /etc/redhat-release to get the version number as in xenserver-ddk/Makefile,  but then it
# might not work properly for a XenSource build.  Seems safer to just check for the file:
ifeq ($(XENSTORE_H),)
	XENSTORE_H=$(shell if ls /usr/include/xenstore.h 2>&1 >/dev/null; then echo "yes"; else echo "no"; fi)
endif
ifeq ($(XENSTORE_H),yes)
	CFLAGS += -DHSF_XENSTORE_H
endif

# control how to read disk info from libvirt
ifeq ($(VRTDSKPATH),yes)
	CFLAGS += -DHSP_VRT_USE_DISKPATH
endif

# if NVML is not set, then assume it should be "yes" if the Nvidia library is present
ifeq ($(NVML),)
	NVML=$(shell if ls /usr/lib*/libnvidia-ml.so >/dev/null 2>&1; then echo "yes"; else echo "no"; fi)
endif

ifeq ($(NVML),yes)
        # we also need the NVML headers, assume /usr/include/nvml
	ifeq ($(NVML_HEADER_DIR),)
		NVML_HEADER_DIR=/usr/include/nvml
	endif
	CFLAGS += -DHSF_NVML -I$(NVML_HEADER_DIR)
	LIBS += -lnvidia-ml
endif

# set ETHTOOL_STATS=yes to enable the use of ethtool for discerning interface counter details
ifeq ($(ETHTOOL_STATS),yes)
	CFLAGS += -DHSP_ETHTOOL_STATS
endif

# set OPTICAL=yes to enable the use of ethtool for adding SFP/QSFP stats.  This extension
# is experimental for now,  so it is off by default.
ifeq ($(OPTICAL_STATS),yes)
	CFLAGS += -DHSP_ETHTOOL_STATS -DHSP_OPTICAL_STATS
endif

# detect Debian systems
ifeq ($(DEBIAN),)
	DEBIAN=$(shell if [ -r /etc/debian_version ]; then echo "yes"; else echo "no"; fi)
endif

# detect Red Hat systems
ifeq ($(REDHAT),)
	REDHAT=$(shell if [ -r /etc/redhat-release ]; then echo "yes"; else echo "no"; fi)
endif

HSFLOWD_INITSCRIPT=scripts/hsflowd
SFLOWOVSD_INITSCRIPT=scripts/sflowovsd
ifeq ($(DEBIAN),yes)
	HSFLOWD_INITSCRIPT=scripts/hsflowd.deb
	SFLOWOVSD_INITSCRIPT=scripts/sflowovsd.deb
endif
ifeq ($(REDHAT),yes)
	HSFLOWD_INITSCRIPT=scripts/hsflowd.redhat
	SFLOWOVSD_INITSCRIPT=scripts/sflowovsd.redhat
endif

ifeq ($(BINDIR),)
	BINDIR=/usr/sbin
endif
ifeq ($(INITDIR),)
	INITDIR=/etc/init.d
endif
ifeq ($(CONFDIR),)
	CONFDIR=/etc
endif

INSTALL=install

# INSTROOT may be passed in, e.g. RPM_BUILD_ROOT
ifeq ($(INSTROOT),)
	BIN_D=$(BINDIR)
	INIT_D=$(INITDIR)
	CONF_D=$(CONFDIR)
else
	BIN_D=$(INSTROOT)/$(BINDIR)
	INIT_D=$(INSTROOT)/$(INITDIR)
	CONF_D=$(INSTROOT)/$(CONFDIR)
endif

READ_OBJS=readInterfaces.o \
          readCpuCounters.o \
          readNvmlCounters.o \
          readMemoryCounters.o \
          readDiskCounters.o \
          readHidCounters.o \
          readNioCounters.o \
	  readPackets.o \
	  readJSON.o \
	  readContainerCounters.o \
	  readBroadcomCounters.o \
	  readTcpipCounters.o

HSFLOW_OBJS= hsflowconfig.o \
             dnsSD.o \
             hsflowd.o \
             hsflowd_xen.o \
             hsflowd_vrt.o \
             hsflowd_docker.o \
             util.o

SFLOWOVS_OBJS=sflowovsd.o util.o

#### BUILD ####

BUILDTGTS=hsflowd
ifeq ($(WITH_SFLOWOVSD),yes)
	BUILDTGTS += sflowovsd
endif

all: $(BUILDTGTS)

hsflowd: $(HSFLOW_OBJS) $(READ_OBJS)
	$(CC) $(CFLAGS) -o $@ $(HSFLOW_OBJS) $(READ_OBJS) $(LIBS)

sflowovsd: $(SFLOWOVS_OBJS)
	$(CC) $(CFLAGS) -o $@ $(SFLOWOVS_OBJS) $(LIBS)

test_netns: test_netns.o util.o
	$(CC) $(CFLAGS) -o $@ test_netns.o util.o $(LIBS)

#### INSTALL ####

INSTALLTGTS=install-hsflowd
ifeq ($(WITH_SFLOWOVSD),yes)
	INSTALLTGTS += install-sflowovsd
endif

install: $(INSTALLTGTS)

install-hsflowd: hsflowd
	$(INSTALL) -d $(BIN_D)
	$(INSTALL) -m 700 hsflowd $(BIN_D)
	if [ ! -e $(INIT_D)/hsflowd ]; then $(INSTALL) -d $(INIT_D); $(INSTALL) -m 755 $(HSFLOWD_INITSCRIPT) $(INIT_D)/hsflowd; fi
	if [ ! -e $(CONF_D)/hsflowd.conf ]; then $(INSTALL) -d $(CONF_D); $(INSTALL) -m 644 scripts/hsflowd.conf $(CONF_D); fi

install-sflowovsd: sflowovsd
	$(INSTALL) -d $(BIN_D)
	$(INSTALL) -m 700 sflowovsd $(BIN_D)
	if [ ! -e $(INIT_D)/sflowovsd ]; then $(INSTALL) -d $(INIT_D); $(INSTALL) -m 755 $(SFLOWOVSD_INITSCRIPT) $(INIT_D)/sflowovsd; fi

#### SCHEDULE ####

# the chkconfig command may not be available in your VM, but all it does it to put the
# necessary links into the /etc/init.d/rc*.d directories to start and stop the daemon
# at the required runlevels.

SCHEDULETGTS=schedule-hsflowd	
ifeq ($(WITH_SFLOWOVSD),yes)	
	SCHEDULETGTS += schedule-sflowovsd
endif

schedule: $(SCHEDULETGTS)

schedule-hsflowd:
ifeq ($(DEBIAN),yes)
	update-rc.d hsflowd defaults
else
	/sbin/chkconfig --add hsflowd
	/sbin/chkconfig --list hsflowd
endif
schedule-sflowovsd:
ifeq ($(DEBIAN),yes)
	update-rc.d sflowovsd defaults
else
	/sbin/chkconfig --add sflowovsd
	/sbin/chkconfig --list sflowovsd
endif
#### CLEAN ####

clean: clean-hsflowd clean-sflowovsd

clean-hsflowd:
	rm -f $(HSFLOW_OBJS) $(READ_OBJS) hsflowd

clean-sflowovsd:
	rm -f $(SFLOWOVS_OBJS) sflowovsd

#### dependencies ####

.c.o: $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c

hsflowconfig.o: hsflowconfig.c $(HEADERS)
dnsSD.o: dnsSD.c $(HEADERS)
hsflowd.o: hsflowd.c $(HEADERS)
hsflowd_xen.o: hsflowd_xen.c $(HEADERS)
hsflowd_vrt.o: hsflowd_vrt.c $(HEADERS)
hsflowd_docker.o: hsflowd_docker.c $(HEADERS)
readInterfaces.o: readInterfaces.c $(HEADERS)
readCpuCounters.o: readCpuCounters.c $(HEADERS)
readNvmlCounters.o: readNvmlCounters.c $(HEADERS)
readMemoryCounters.o: readMemoryCounters.c $(HEADERS)
readDiskCounters.o: readDiskCounters.c $(HEADERS)
readHidCounters.o: readHidCounters.c $(HEADERS)
readNioCounters.o: readNioCounters.c $(HEADERS)
readPackets.o: readPackets.c $(HEADERS)
readJSON.o: readJSON.c $(HEADERS)
sflowovsd.o: sflowovsd.c $(HEADERS)
readContainerCounters.o: readContainerCounters.c $(HEADERS)
readAsicCounters.o: readAsicCounters.c $(HEADERS)
readBroadcomCounters.o: readBroadcomCounters.c $(HEADERS)
readTcpipCounters.o: readTcpipCounters.c $(HEADERS)

