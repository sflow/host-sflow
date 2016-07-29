# This software is distributed under the following license:
# http://sflow.net/license.html

HEADERS= hsflowd.h hsflowtokens.h sflowovsd.h Makefile

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
CFLAGS += -I. -I$(SFLOWDIR) $(OPT) -Wall -Wstrict-prototypes -Wunused-value -D_GNU_SOURCE -DHSP_VERSION=$(VERSION) # -DUTHEAP
#LIBS += $(SFLOWDIR)/libsflow.a -lresolv -lpthread
LIBS += $(SFLOWDIR)/libsflow.a -lpthread -lperfstat

# if ULOG is not set, assume it should be "no".
# (So you can use "make ULOG=no" to compile without this feature)
ifeq ($(ULOG),)
	ULOG=no
endif
ifeq ($(ULOG),yes)
	CFLAGS += -DHSF_ULOG
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

# if LIBVIRT is not set, then assume it should be "yes" if we find the /usr/lib/libvirt.so library. Maybe
# it would be stronger to test for the libvirt-devel rpm? or look for /usr/include/libvirt/libvirt.h?
ifeq ($(LIBVIRT),)
	LIBVIRT=$(shell if ls /usr/lib/libvirt.* >/dev/null 2>&1; then echo "yes"; else echo "no"; fi)
endif
ifeq ($(LIBVIRT),yes)
	CFLAGS += -DHSF_VRT -I/usr/include/libvirt -I/usr/include/libxml2
	LIBS += -lvirt -lxml2
else
  # if XEN_DDK is not set, then assume it should be "yes" if we are on a Xenserver DDK (or equivalent) system.
  # Just test if the xenstore and xenctrl libs are present.
  ifeq ($(XEN_DDK),)
	XEN_DDK=$(shell if ls /usr/lib/libxenctrl.* >/dev/null 2>&1 && ls /usr/lib/libxenstore.* >/dev/null 2>&1; then echo "yes"; else echo "no"; fi)
  endif
  # to compile with xen-sources instead, specify XEN_ROOT.  e.g. XEN_ROOT=/root/xen-3.2.0
  ifeq ($(XEN_ROOT),)
  else
	XEN_DDK=no
	include $(XEN_ROOT)/tools/Rules.mk
	CFLAGS += -DHSF_XEN -I$(XEN_XENSTORE) -I$(XEN_LIBXC)
	CFLAGS += -Wno-declaration-after-statement # turn off "mixed declarations and code" warning
	LIBS += -L$(XEN_XENSTORE) -L$(XEN_LIBXC) -lxenstore -lxenctrl
  endif
  ifeq ($(XEN_DDK),yes)
	CFLAGS += -DHSF_XEN
	LIBS += -lxenstore -lxenctrl
  endif
endif

# allow HSF_XEN_VBD_PATH to be overridden here.  For example: make HSF_XEN_VBD_PATH=/sys/devices
ifeq ($(HSF_XEN_VBD_PATH),)
else
	CFLAGS += -DHSF_XEN_VBD_PATH=$(HSF_XEN_VBD_PATH)
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

# detect Debian systems
ifeq ($(DEBIAN),)
	DEBIAN=$(shell if [ -r /etc/debian_version ]; then echo "yes"; else echo "no"; fi)
endif

ifeq ($(BINDIR),)
	BINDIR=/usr/sbin
endif
ifeq ($(INITDIR),)
	INITDIR=/etc/rc.d/init.d
endif
ifeq ($(CONFDIR),)
	CONFDIR=/etc
endif

INSTALL=installbsd
INSTALLDIR=mkdir -p

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
	  readJSON.o

HSFLOW_OBJS= hsflowconfig.o \
             hsflowd.o \
             util.o

SFLOWOVS_OBJS=sflowovsd.o util.o

#### BUILD ####

all: hsflowd sflowovsd

hsflowd: $(HSFLOW_OBJS) $(READ_OBJS)
	$(CC) $(CFLAGS) -o $@ $(HSFLOW_OBJS) $(READ_OBJS) $(LIBS)

sflowovsd: $(SFLOWOVS_OBJS)
	$(CC) $(CFLAGS) -o $@ $(SFLOWOVS_OBJS) $(LIBS)

#### INSTALL ####

install: install-hsflowd install-sflowovsd

install-hsflowd: hsflowd
	$(INSTALLDIR) $(BIN_D)
	$(INSTALL) -m 700 hsflowd $(BIN_D)
	if [ ! -e $(INIT_D)/hsflowd ]; then $(INSTALLDIR) $(INIT_D); $(INSTALL) -m 700 scripts/hsflowd $(INIT_D); fi
	if [ ! -e $(CONF_D)/hsflowd.conf ]; then $(INSTALLDIR) $(CONF_D); $(INSTALL) -m 644 scripts/hsflowd.conf $(CONF_D); fi

install-sflowovsd: sflowovsd
	$(INSTALLDIR) $(BIN_D)
	$(INSTALL) -m 700 sflowovsd $(BIN_D)
	if [ ! -e $(INIT_D)/sflowovsd ]; then $(INSTALLDIR) $(INIT_D); $(INSTALL) -m 700 scripts/sflowovsd $(INIT_D); fi

#### SCHEDULE ####

# the chkconfig command may not be available in your VM, but all it does it to put the
# necessary links into the /etc/init.d/rc*.d directories to start and stop the daemon
# at the required runlevels.

schedule: schedule-hsflowd schedule-sflowovsd

schedule-hsflowd:
# Seems like it's best to use mkssys(1) for this

schedule-sflowovsd:
# Seems like it's best to use mkssys(1) for this

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
hsflowd.o: hsflowd.c $(HEADERS)
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

