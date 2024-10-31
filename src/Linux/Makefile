# This software is distributed under the following license:
# http://sflow.net/license.html

#########  platform checks  #########

# detect Debian systems
ifndef DEBIAN
  DEBIAN=$(shell if [ -r /etc/debian_version ]; then echo "yes"; else echo "no"; fi)
endif

# detect Red Hat systems
ifndef REDHAT
  REDHAT=$(shell if [ -r /etc/redhat-release ]; then echo "yes"; else echo "no"; fi)
endif

# learn kernel version
# KVER=$(shell ./kernelVersion.sh)
# KERNEL54PLUS=$(shell if test $(KVER) -ge 5004000; then echo "yes"; else echo "no"; fi)

HSFLOWD_CONF=scripts/hsflowd.conf
HSFLOWD_INITSCRIPT=scripts/hsflowd
HSFLOWD_SYSTEMD_SERVICE=scripts/hsflowd.service
HSFLOWD_DBUS_CONF=scripts/net.sflow.hsflowd.conf

ifeq ($(DEBIAN),yes)
  HSFLOWD_INITSCRIPT=scripts/hsflowd.deb
endif
ifeq ($(REDHAT),yes)
  HSFLOWD_INITSCRIPT=scripts/hsflowd.redhat
endif

INSTALL=install

# gcov support
CFLAGS_GCOV=
LDFLAGS_GCOV=
ifeq ($(GCOV),yes)
  CFLAGS_GCOV=-fprofile-arcs -ftest-coverage
  LDFLAGS_GCOV=-fprofile-arcs -ftest-coverage -lgcov
endif

#########  object files  #########
FEATURES_ALL= ULOG NFLOG PSAMPLE DROPMON PCAP TCP DOCKER KVM XEN NVML OVS CUMULUS DENT OS10 OPX SONIC DBUS SYSTEMD EAPI CONTAINERD CONTAINERDGO K8S NLROUTE VPP
FEATURES_CUMULUS= CUMULUS NFLOG PSAMPLE SYSTEMD DROPMON
FEATURES_DENTOS= DENT PSAMPLE SYSTEMD DROPMON
FEATURES_EOS= EAPI
FEATURES_OS10= OS10 DBUS SYSTEMD
FEATURES_OPX= OPX DBUS SYSTEMD
FEATURES_SONIC= SONIC PSAMPLE DOCKER DROPMON
FEATURES_XEN= XEN OVS
FEATURES_HOST= NFLOG PCAP TCP DOCKER KVM OVS DBUS SYSTEMD PSAMPLE DENT DROPMON NLROUTE
FEATURES_CONTAINERD= CONTAINERDGO
FEATURES_VPP= VPP PSAMPLE DROPMON

BINDIR     ?= /usr/sbin
INITDIR    ?= /etc/init.d
CONFDIR    ?= /etc
MODDIR     ?= /etc/hsflowd/modules
SYSTEMDDIR ?= /lib/systemd/system
DBUSDIR    ?= /etc/dbus-1/system.d

# in FEATURES2 every token has spaces before and after
FEATURES2=" $(FEATURES) "
$(info $$FEATURES is [$(FEATURES)] from $(origin FEATURES))
$(info $$FEATURES2 is [$(FEATURES2)] from $(origin FEATURES))

XTGTS= $(FEATURES)
CFLAGS_LOAD=

ifneq ($(shell echo $(FEATURES2)|grep -c " ALL "),0)
  XTGTS += $(FEATURES_ALL)
endif

ifneq ($(shell echo $(FEATURES2)|grep -c " CUMULUS "),0)
  XTGTS += $(FEATURES_CUMULUS)
  CFLAGS_LOAD += -DHSP_LOAD_CUMULUS
  HSFLOWD_CONF=scripts/hsflowd.conf.cumulus
  HSFLOWD_SYSTEMD_SERVICE=scripts/hsflowd.service.cumulus
endif

ifneq ($(shell echo $(FEATURES2)|grep -c " DENTOS "),0)
  XTGTS += $(FEATURES_DENT)
  CFLAGS_LOAD += -DHSP_LOAD_DENT
  HSFLOWD_CONF=scripts/hsflowd.conf.dent
  HSFLOWD_SYSTEMD_SERVICE=scripts/hsflowd.service.dent
endif

ifneq ($(shell echo $(FEATURES2)|grep -c " EOS "),0)
  XTGTS += $(FEATURES_EOS)
  CFLAGS_LOAD += -DHSP_LOAD_EOS
endif

ifneq ($(shell echo $(FEATURES2)|grep -c " OS10 "),0)
  # almost the same as OPX...
  XTGTS += $(FEATURES_OS10)
  CFLAGS_LOAD += -DHSP_LOAD_OPX
  HSFLOWD_SYSTEMD_SERVICE=scripts/hsflowd.service.os10
endif

ifneq ($(shell echo $(FEATURES2)|grep -c " OPX "),0)
  XTGTS += $(FEATURES_OPX)
  CFLAGS_LOAD += -DHSP_LOAD_OPX
  HSFLOWD_SYSTEMD_SERVICE=scripts/hsflowd.service.opx
endif

ifneq ($(shell echo $(FEATURES2)|grep -c " SONIC "),0)
  XTGTS += $(FEATURES_SONIC)
  CFLAGS_LOAD += -DHSP_LOAD_SONIC
  HSFLOWD_CONF=scripts/hsflowd.conf.sonic
  # hsflowd runs as container with --net=host and some host-fs mountpoints. Expect something like:
  # make deb FEATURES=SONIC PROCFS=/rootfs/proc SYSFS=/rootfs/sys VARFS=/rootfs/var ETCFS=/tmp/etc
  # so that docker run command can expose host directories selectively
endif

ifneq ($(shell echo $(FEATURES2)|grep -c " XEN "),0)
  XTGTS += $(FEATURES_XEN)
  CFLAGS_LOAD += -DHSP_LOAD_XEN
endif

ifneq ($(shell echo $(FEATURES2)|grep -c " HOST "),0)
  XTGTS += $(FEATURES_HOST)
endif

ifneq ($(shell echo $(FEATURES2)|grep -c " VPP "),0)
  XTGTS += $(FEATURES_VPP)
endif

# CONTAINERD and K8S require CONTAINERDGO, but it is
# easier not to capture this dependency so that the
# Go program can more easily be compiled separately
# (e.g. using golang docker hub image)
#ifneq ($(shell echo $(FEATURES2)|grep -c " CONTAINERD "),0)
#  XTGTS += $(FEATURES_CONTAINERD)
#endif
#ifneq ($(shell echo $(FEATURES2)|grep -c " K8S "),0)
#  XTGTS += $(FEATURES_CONTAINERD)
#endif

# in XTGTS2 every token has spaces before and after
XTGTS2=" $(XTGTS) "
$(info $$XTGTS is [$(XTGTS)])
$(info $$XTGTS2 is [$(XTGTS2)])

# alternative mount points (to support hsflowd running in container
# and/or with no root privileges)

ifndef PROCFS
  PROCFS=/proc
endif
ifndef SYSFS
  SYSFS=/sys
endif
ifndef ETCFS
  ETCFS=/etc
endif
ifndef VARFS
  VARFS=/var
endif

CFLAGS_MOUNTPOINTS=-DPROCFS=$(PROCFS) -DSYSFS=$(SYSFS) -DETCFS=$(ETCFS) -DVARFS=$(VARFS)

# INSTROOT may be passed in
BIN_D=$(BINDIR)
INIT_D=$(INITDIR)
CONF_D=$(CONFDIR)
MOD_D=$(MODDIR)
SYSTEMD_D=$(SYSTEMDDIR)
DBUS_D=$(DBUSDIR)
ifneq ($(INSTROOT),)
	BIN_D=$(INSTROOT)$(BINDIR)
	INIT_D=$(INSTROOT)$(INITDIR)
	CONF_D=$(INSTROOT)$(CONFDIR)
	MOD_D=$(INSTROOT)$(MODDIR)
	SYSTEMD_D=$(INSTROOT)$(SYSTEMDDIR)
	DBUS_D=$(INSTROOT)$(DBUSDIR)
endif

#########  compilation flags  #########

HEADERS= util.h util_dbus.h util_netlink.h evbus.h hsflowd.h hsflowtokens.h hsflow_ethtool.h cpu_utils.h dropPoints_sw.h dropPoints_hw.h Makefile

# compiler
#CC= g++
CC= gcc -std=gnu99
#LD=ld
LD=gcc

# optimization
OPT_ALL= -O3 -DNDEBUG
OPT_REG= -g -O2
OPT_DBG= -g -ggdb

# use "UTHEAP=no OPT=-g" to turn off buffer-recycling
# so that "valgrind --leak-check=yes hsflowd -d" can find leaks.
ifndef UTHEAP
  UTHEAP=yes
endif

ifndef OPT
  OPT=$(OPT_REG)
endif

# option to use gperftools
CFLAGS_GPROF=
LDFLAGS_GPROF=
LIBS_GPROF=
ifeq ($(GPROF),yes)
  CFLAGS_GPROF= -DGPROF -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free
  LDFLAGS_GPROF=
  LIBS_GPROF= -ltcmalloc_and_profiler
  LIBS_GPROF += -lunwind # only for 64-bit?
endif

# other source directories
SFLOWDIR=../sflow
JSONDIR=../json

# CFLAGS and LIBS - for hsflowd main
CFLAGS_HSFLOWD= -I. -I$(JSONDIR) -I$(SFLOWDIR)
LDFLAGS_HSFLOWD= -rdynamic
LDFLAGS_HSFLOWD += $(LDFLAGS_GCOV)
LDFLAGS_HSFLOWD += $(LDFLAGS_GPROF)
LIBS_HSFLOWD= $(JSONDIR)/libcjson.a $(SFLOWDIR)/libsflow.a -lm -pthread -ldl -lrt
LIBS_HSFLOWD += $(LIBS_GPROF)

# CFLAGS and LIBS - for all shared-library modules
CFLAGS_SHARED= -fPIC
LDFLAGS_SHARED= -shared
LDFLAGS_SHARED += $(LDFLAGS_GCOV)
LDFLAGS_SHARED += $(LDFLAGS_GPROF)
# LDFLAGS_SHARED += --build-id

# CFLAGS and LIBS - for individual modules
CFLAGS_JSON=
LIBS_JSON=

CFLAGS_DNSSD=
LIBS_DNSSD=-lresolv

CFLAGS_XEN=
LIBS_XEN= -lxenstore -lxenctrl

# KVM requires libvirt-del(el), libxml2-dev(el)
CFLAGS_KVM= -I/usr/include/libvirt -I/usr/include/libxml2
LIBS_KVM= -lvirt -lxml2

CFLAGS_DOCKER=
LIBS_DOCKER= -lm

CFLAGS_ULOG=
LIBS_ULOG=

# NFLOG requires libnfnetlink-dev(el)
CFLAGS_NFLOG= -I/usr/include/libnfnetlink
LIBS_NFLOG= -lnfnetlink

CFLAGS_PSAMPLE=
LIBS_PSAMPLE=

CFLAGS_DROPMON=
LIBS_DROPMON=

# PCAP requires libpcap-dev(el)
CFLAGS_PCAP=
LIBS_PCAP=-lpcap

CFLAGS_TCP=
LIBS_TCP=

# For dependencies, compile using CUDA docker image
CFLAGS_NVML ?= -I/usr/local/cuda/include/
LIBDIR_NVML ?= /usr/local/cuda/lib64/stubs/
LIBS_NVML= -L$(LIBDIR_NVML) -lnvidia-ml

CFLAGS_CUMULUS=
LIBS_CUMULUS=

CFLAGS_DENT=
LIBS_DENT=

CFLAGS_OVS=
LIBS_OVS=

# OPX requires libsystemd-daemon-dev
CFLAGS_OPX= -I/usr/include/opx
LIBS_OPX= -lsystemd -lopx_cps_api_common -lopx_cps_class_map
# For OS10 the same libraries are under different names:
ifneq ($(shell echo $(FEATURES2)|grep -c " OS10 "),0)
  CFLAGS_OPX= -I/usr/include/ngos
  LIBS_OPX= -lsystemd -lcps-api-common -lcps-class-map-util
endif

# SONIC requires libhiredis-dev(el)
CFLAGS_SONIC=
LIBS_SONIC=-lhiredis
ifeq ($(REDISONLY),yes)
  CFLAGS_SONIC += -DHSP_SONIC_TEST_REDISONLY
endif

# DBUS requires dbus-dev(el) or libdbus-1-dev
CFLAGS_DBUS=$(shell pkg-config dbus-1 --cflags)
LIBS_DBUS=$(shell pkg-config dbus-1 --libs)

CFLAGS_NETLINK=
LIBS_NETLINK=

# SYSTEMD requires DBUS, (lib)uuid-dev(el), openssl-dev(el)
CFLAGS_SYSTEMD=$(CFLAGS_DBUS)
LIBS_SYSTEMD=$(LIBS_DBUS) -luuid -lcrypto

CFLAGS_EAPI=
LIBS_EAPI=

# CONTAINERD requires golang, openssl-dev(el)
CFLAGS_CONTAINERD=-Wno-deprecated-declarations
LIBS_CONTAINERD= -lm -lcrypto

# K8S requires golang, (lib)uuid-dev(el)
CFLAGS_K8S=
LIBS_K8S= -lm -luuid

CFLAGS_NLROUTE=
LIBS_NLROUTE=

CFLAGS_VPP=
LIBS_VPP=

# common CFLAGS and LIBS	
CFLAGS = $(CFLAGS_HSFLOWD) $(CFLAGS_LOAD) $(CFLAGS_SHARED) $(OPT) -D_GNU_SOURCE -DHSP_VERSION=$(VERSION)
CFLAGS += $(CFLAGS_MOUNTPOINTS)
ifeq ($(UTHEAP),yes)
  CFLAGS += -DUTHEAP
endif
CFLAGS += -DHSP_OPTICAL_STATS
CFLAGS += -DHSP_MOD_DIR=$(MODDIR)
CFLAGS += -Wall -Wstrict-prototypes -Wunused-value
CFLAGS += -Wunused-function
CFLAGS += $(CFLAGS_GCOV)
CFLAGS += $(CFLAGS_GPROF)
CFLAGS += -DSFL_USE_SFDG -DSFL_USE_32BIT_INDEX

# xs.h became xenstore.h by 6.5. Detect that and set a flag.  Could drive this by reading
# /etc/redhat-release to get the version number as in xenserver-ddk/Makefile,  but then it
# might not work properly for a XenSource build.  Seems safer to just check for the file:
ifndef XENSTORE_H	
  XENSTORE_H=$(shell if ls /usr/include/xenstore.h 2>&1 >/dev/null; then echo "yes"; else echo "no"; fi)
endif
ifeq ($(XENSTORE_H),yes)
  CFLAGS_XEN += -DHSP_XENSTORE_H
endif


OBJS_HSFLOWD= hsflowconfig.o \
              hsflowd.o \
	      evbus.o \
              util.o \
	      readInterfaces.o \
              readCpuCounters.o \
              readMemoryCounters.o \
              readDiskCounters.o \
              readHidCounters.o \
              readNioCounters.o \
	      readTcpipCounters.o \
	      readPackets.o

OBJS_JSON=mod_json.o
OBJS_DNSSD=mod_dnssd.o
OBJS_XEN=mod_xen.o
OBJS_KVM=mod_kvm.o
OBJS_DOCKER=mod_docker.o
OBJS_ULOG=mod_ulog.o
OBJS_NFLOG=mod_nflog.o
OBJS_PSAMPLE=mod_psample.o util_netlink.o
OBJS_DROPMON=mod_dropmon.o util_netlink.o
OBJS_PCAP=mod_pcap.o
OBJS_TCP=mod_tcp.o util_netlink.o
OBJS_NVML=mod_nvml.o
OBJS_OVS=mod_ovs.o
OBJS_CUMULUS=mod_cumulus.o
OBJS_DENT=mod_dent.o
OBJS_OPX=mod_opx.o
OBJS_SONIC=mod_sonic.o
OBJS_DBUS=mod_dbus.o util_dbus.o
OBJS_SYSTEMD=mod_systemd.o util_dbus.o util_netlink.o
OBJS_EAPI=mod_eapi.o
OBJS_CONTAINERD=mod_containerd.o
OBJS_K8S=mod_k8s.o
OBJS_NLROUTE=mod_nlroute.o util_netlink.o
OBJS_VPP=mod_vpp.o util_netlink.o

BUILDTGTS= mod_json.so \
           mod_dnssd.so \
           $(XTGTS)

all: $(BUILDTGTS) hsflowd

#########  feature dependencies #########

ALL:

EOS:

HOST:

XEN: mod_xen.so OVS

KVM: mod_kvm.so

DOCKER: mod_docker.so

ULOG: mod_ulog.so

NFLOG: mod_nflog.so

PSAMPLE: mod_psample.so

DROPMON: mod_dropmon.so

PCAP: mod_pcap.so

TCP: mod_tcp.so

NVML: mod_nvml.so

OVS: mod_ovs.so

CUMULUS: mod_cumulus.so

DENT: mod_dent.so

OS10: mod_opx.so

OPX: mod_opx.so

SONIC: mod_sonic.so

DBUS: mod_dbus.so

SYSTEMD: mod_systemd.so

EAPI: mod_eapi.so

CONTAINERD: mod_containerd.so

CONTAINERDGO: hsflowd_containerd

K8S: mod_k8s.so

NLROUTE: mod_nlroute.so

VPP: mod_vpp.so

#########  hsflowd  #########

hsflowd: $(OBJS_HSFLOWD) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(OBJS_HSFLOWD) $(LIBS_HSFLOWD) $(LDFLAGS_HSFLOWD)

#########  hsflowd_containerd  #########

hsflowd_containerd:
	cd containerd; \
	echo "=== go mod init hsflowd_containerd ==="; \
	go mod init hsflowd_containerd; \
	echo "=== go get github.com/containerd/containerd@v1.6.26 ==="; \
	go get github.com/containerd/containerd@v1.6.26; \
	echo "=== go build hsflowd_containerd ==="; \
	go build hsflowd_containerd; \
	echo "=== compile hsflowd_containerd done ==="

######## DBUS utils ##########

util_dbus.o: util_dbus.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_DBUS)

######## Netlink utils ##########

util_netlink.o: util_netlink.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_NETLINK)

#########  modules  #########

mod_dnssd.o: mod_dnssd.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_DNSSD)

mod_dnssd.so: $(OBJS_DNSSD)
	$(LD) -o $@ $(OBJS_DNSSD) $(LDFLAGS_SHARED) $(LIBS_DNSSD)

#----------------------------

mod_json.o: mod_json.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_JSON)

mod_json.so: $(OBJS_JSON)
	$(LD) -o $@ $(OBJS_JSON) $(LDFLAGS_SHARED) $(LIBS_JSON)

#----------------------------


mod_ulog.o: mod_ulog.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_ULOG)

mod_ulog.so: $(OBJS_ULOG)
	$(LD) -o $@ $(OBJS_ULOG) $(LDFLAGS_SHARED) $(LIBS_ULOG)

#----------------------------


mod_nflog.o: mod_nflog.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c  $(CFLAGS_NFLOG)

mod_nflog.so: $(OBJS_NFLOG)
	$(LD) -o $@ $(OBJS_NFLOG) $(LDFLAGS_SHARED) $(LIBS_NFLOG)

#----------------------------


mod_psample.o: mod_psample.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c  $(CFLAGS_PSAMPLE)

mod_psample.so: $(OBJS_PSAMPLE)
	$(LD) -o $@ $(OBJS_PSAMPLE) $(LDFLAGS_SHARED) $(LIBS_PSAMPLE)

#----------------------------


mod_dropmon.o: mod_dropmon.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c  $(CFLAGS_DROPMON)

mod_dropmon.so: $(OBJS_DROPMON)
	$(LD) -o $@ $(OBJS_DROPMON) $(LDFLAGS_SHARED) $(LIBS_DROPMON)

#----------------------------

mod_pcap.o: mod_pcap.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_PCAP)

mod_pcap.so: $(OBJS_PCAP)
	$(LD) -o $@ $(OBJS_PCAP) $(LDFLAGS_SHARED) $(LIBS_PCAP)

#----------------------------

mod_tcp.o: mod_tcp.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_TCP)

mod_tcp.so: $(OBJS_TCP)
	$(LD) -o $@ $(OBJS_TCP) $(LDFLAGS_SHARED) $(LIBS_TCP)

#----------------------------


mod_xen.o: mod_xen.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_XEN)

mod_xen.so: $(OBJS_XEN)
	$(LD) -o $@ $(OBJS_XEN) $(LDFLAGS_SHARED) $(LIBS_XEN)

#----------------------------


mod_kvm.o: mod_kvm.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_KVM)

mod_kvm.so: $(OBJS_KVM)
	$(LD) -o $@ $(OBJS_KVM) $(LDFLAGS_SHARED) $(LIBS_KVM)

#----------------------------


mod_docker.o: mod_docker.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_DOCKER)

mod_docker.so: $(OBJS_DOCKER)
	$(LD) -o $@ $(OBJS_DOCKER) $(LDFLAGS_SHARED) $(LIBS_DOCKER)

#----------------------------


mod_nvml.o: mod_nvml.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_NVML)

mod_nvml.so: $(OBJS_NVML)
	$(LD) -o $@ $(OBJS_NVML) $(LDFLAGS_SHARED) $(LIBS_NVML)

#----------------------------


mod_ovs.o: mod_ovs.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_OVS)

mod_ovs.so: $(OBJS_OVS)
	$(LD) -o $@ $(OBJS_OVS) $(LDFLAGS_SHARED) $(LIBS_OVS)

#----------------------------


mod_cumulus.o: mod_cumulus.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_CUMULUS)

mod_cumulus.so: $(OBJS_CUMULUS)
	$(LD) -o $@ $(OBJS_CUMULUS) $(LDFLAGS_SHARED) $(LIBS_CUMULUS)

#----------------------------

mod_dent.o: mod_dent.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_DENT)

mod_dent.so: $(OBJS_DENT)
	$(LD) -o $@ $(OBJS_DENT) $(LDFLAGS_SHARED) $(LIBS_DENT)

#----------------------------

mod_opx.o: mod_opx.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_OPX)

mod_opx.so: $(OBJS_OPX)
	$(LD) -o $@ $(OBJS_OPX) $(LDFLAGS_SHARED) $(LIBS_OPX)

#----------------------------

mod_sonic.o: mod_sonic.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_SONIC)

mod_sonic.so: $(OBJS_SONIC)
	$(LD) -o $@ $(OBJS_SONIC) $(LDFLAGS_SHARED) $(LIBS_SONIC)

#----------------------------


mod_dbus.o: mod_dbus.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_DBUS)

mod_dbus.so: $(OBJS_DBUS)
	$(LD) -o $@ $(OBJS_DBUS) $(LDFLAGS_SHARED) $(LIBS_DBUS)

#----------------------------


mod_systemd.o: mod_systemd.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_SYSTEMD)

mod_systemd.so: $(OBJS_SYSTEMD)
	$(LD) -o $@ $(OBJS_SYSTEMD) $(LDFLAGS_SHARED) $(LIBS_SYSTEMD)

#----------------------------

mod_eapi.o: mod_eapi.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_EAPI)

mod_eapi.so: $(OBJS_EAPI)
	$(LD) -o $@ $(OBJS_EAPI) $(LDFLAGS_SHARED) $(LIBS_EAPI)

#----------------------------

mod_containerd.o: mod_containerd.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_CONTAINERD)

mod_containerd.so: $(OBJS_CONTAINERD)
	$(LD) -o $@ $(OBJS_CONTAINERD) $(LDFLAGS_SHARED) $(LIBS_CONTAINERD)

#----------------------------

mod_k8s.o: mod_k8s.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_K8S)

mod_k8s.so: $(OBJS_K8S)
	$(LD) -o $@ $(OBJS_K8S) $(LDFLAGS_SHARED) $(LIBS_K8S)

#----------------------------

mod_nlroute.o: mod_nlroute.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c $(CFLAGS_NLROUTE)

mod_nlroute.so: $(OBJS_NLROUTE)
	$(LD) -o $@ $(OBJS_NLROUTE) $(LDFLAGS_SHARED) $(LIBS_NLROUTE)

#----------------------------

mod_vpp.o: mod_vpp.c $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c  $(CFLAGS_VPP)

mod_vpp.so: $(OBJS_VPP)
	$(LD) -o $@ $(OBJS_VPP) $(LDFLAGS_SHARED) $(LIBS_VPP)


#########  install  #########

install: all
	$(INSTALL) -d $(BIN_D)
	$(INSTALL) -m 700 hsflowd $(BIN_D)
	$(INSTALL) -d $(CONF_D)
	$(INSTALL) -m 644 $(HSFLOWD_CONF) $(CONF_D)/hsflowd.conf
	$(INSTALL) -d $(SYSTEMD_D)
	$(INSTALL) -m 644 $(HSFLOWD_SYSTEMD_SERVICE) $(SYSTEMD_D)/hsflowd.service
	$(INSTALL) -d $(INIT_D)
	$(INSTALL) -m 755 $(HSFLOWD_INITSCRIPT) $(INIT_D)/hsflowd
	$(INSTALL) -d $(MOD_D)
	$(INSTALL) -m 755 *.so $(MOD_D)
ifneq ($(strip $(HSFLOWD_DBUS_CONF)),)
	$(INSTALL) -d $(DBUS_D)
	$(INSTALL) -m 644 $(HSFLOWD_DBUS_CONF) $(DBUS_D)
endif
ifneq ($(shell echo $(XTGTS2)|grep -c " CONTAINERDGO "),0)
	$(INSTALL) -m 700 containerd/hsflowd_containerd $(BIN_D)
endif

#########  schedule  #########

ifndef SYSTEMD
  SYSTEMD=$(shell if hash systemctl 2>/dev/null; then echo "yes"; else echo "no"; fi)
endif

schedule:
ifeq ($(SYSTEMD),yes)
	systemctl daemon-reload
	systemctl enable hsflowd
else
  ifeq ($(DEBIAN),yes)
	update-rc.d hsflowd defaults
  else
	/sbin/chkconfig --add hsflowd
	/sbin/chkconfig --list hsflowd
  endif
endif

#########  clean   #########

clean: 
	rm -f hsflowd *.o *.so

#########  dependencies  #########

.c.o:
	$(CC) $(CFLAGS) -c $*.c

util.o: util.c $(HEADERS)
util_dbus.o: util_dbus.c $(HEADERS)
evbus.o: evbus.c $(HEADERS)
hsflowconfig.o: hsflowconfig.c $(HEADERS)
hsflowd.o: hsflowd.c $(HEADERS)
readInterfaces.o: readInterfaces.c $(HEADERS)
readCpuCounters.o: readCpuCounters.c $(HEADERS)
readMemoryCounters.o: readMemoryCounters.c $(HEADERS)
readDiskCounters.o: readDiskCounters.c $(HEADERS)
readHidCounters.o: readHidCounters.c $(HEADERS)
readNioCounters.o: readNioCounters.c $(HEADERS)
readPackets.o: readPackets.c $(HEADERS)
readContainerCounters.o: readContainerCounters.c $(HEADERS)
readTcpipCounters.o: readTcpipCounters.c $(HEADERS)
mod_json.o: mod_json.c $(HEADERS)
mod_dnssd.o: mod_dnssd.c $(HEADERS)
mod_xen.o: mod_xen.c $(HEADERS)
mod_kvm.o: mod_kvm.c $(HEADERS)
mod_docker.o: mod_docker.c $(HEADERS)
mod_ulog.o: mod_ulog.c $(HEADERS)
mod_nflog.o: mod_nflog.c $(HEADERS)
mod_psample.o: mod_psample.c $(HEADERS)
mod_dropmon.o: mod_dropmon.c $(HEADERS)
mod_pcap.o: mod_pcap.c $(HEADERS)
mod_tcp.o: mod_tcp.c $(HEADERS)
mod_nvml.o: mod_nvml.c $(HEADERS)
mod_cumulus.o: mod_cumulus.c $(HEADERS)
mod_dent.o: mod_dent.c $(HEADERS)
mod_ovs.o: mod_ovs.c $(HEADERS)
mod_opx.o: mod_opx.c $(HEADERS)
mod_dbus.o: mod_dbus.c $(HEADERS)
mod_systemd.o: mod_systemd.c $(HEADERS)
mod_eapi.o: mod_eapi.c $(HEADERS)
mod_containerd.o: mod_containerd.c $(HEADERS)
mod_k8s.o: mod_k8s.c $(HEADERS)
mod_nlroute.o: mod_nlroute.c $(HEADERS)
mod_vpp.o: mod_vpp.c $(HEADERS)
