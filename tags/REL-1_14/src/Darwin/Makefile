# This software is distributed under the following license:
# http://host-sflow.sourceforge.net/license.html

# specify XEN_ROOT path to compile with xen-sources
# e.g. XEN_ROOT=/root/xen-3.2.0
ifeq ($(XEN_ROOT),)
else
	include $(XEN_ROOT)/tools/Rules.mk
	CFLAGS+= -DHSF_XEN -I$(XEN_XENSTORE) -I$(XEN_LIBXC)
	LIBS+= -L$(XEN_XENSTORE) -L$(XEN_LIBXC) -lxenstore -lxenctrl
endif

# alternatively, if compiling on the Citrix
# XenServer DDK VM just set XEN_DDK=yes
ifeq ($(XEN_DDK),yes)
	CFLAGS+= -DHSF_XEN
	LIBS+= -lxenstore -lxenctrl
endif

ifeq ($(BINDIR),)
	BINDIR=/usr/local/sbin
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

HEADERS= hsflowd.h hsflowtokens.h Makefile

SFLOWDIR=../sflow

OPT = -O3 -DNDEBUG
#OPT = -g -ggdb -O2
#OPT= -g -ggdb

#CC= g++
CC= gcc -std=gnu99

READ_OBJS=readInterfaces.o \
          readCpuCounters.o \
          readMemoryCounters.o \
          readDiskCounters.o \
          readHidCounters.o \
          readNioCounters.o

HSFLOW_OBJS= hsflowconfig.o \
             dnsSD.o \
             hsflowd.o

OBJS=$(HSFLOW_OBJS) $(READ_OBJS)

CFLAGS+= -I. -I$(SFLOWDIR) $(OPT) -Wall -D_GNU_SOURCE
LIBS+= $(SFLOWDIR)/libsflow.a -lresolv -lpthread

all: hsflowd

hsflowd: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

install: hsflowd
	$(INSTALL) -d $(BIN_D)
	$(INSTALL) -m 700 hsflowd $(BIN_D)
	if [ ! -e $(INIT_D)/hsflowd ]; then $(INSTALL) -d $(INIT_D); $(INSTALL) -m 700 scripts/hsflowd $(INIT_D); fi
	if [ ! -e $(CONF_D)/hsflowd.conf ]; then $(INSTALL) -d $(CONF_D); $(INSTALL) -m 644 scripts/hsflowd.conf $(CONF_D); fi

# the chkconfig command may not be available in your VM, but all it does it to put the
# necessary links into the /etc/init.d/rc*.d directories to start and stop the daemon
# at the required runlevels
schedule:
	/sbin/chkconfig --add hsflowd
	/sbin/chkconfig --list hsflowd

.c.o: $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c

clean:
	rm -f $(OBJS) hsflowd

# dependencies
hsflowconfig.o: hsflowconfig.c $(HEADERS)
dnsSD.o: dnsSD.c $(HEADERS)
hsflowd.o: hsflowd.c $(HEADERS)
readInterfaces.o: readInterfaces.c $(HEADERS)
readCpuCounters.o: readCpuCounters.c $(HEADERS)
readMemoryCounters.o: readMemoryCounters.c $(HEADERS)
readDiskCounters.o: readDiskCounters.c $(HEADERS)
readHidCounters.o: readHidCounters.c $(HEADERS)
readNioCounters.o: readNioCounters.c $(HEADERS)

