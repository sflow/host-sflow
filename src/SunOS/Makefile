# This software is distributed under the following license:
# http://sflow.net/license.html

SHELL=/bin/bash

ifeq ($(BINDIR),)
	BINDIR=/usr/sbin
endif
ifeq ($(METHODDIR),)
	METHODDIR=/lib/svc/method
endif
ifeq ($(MANIFESTDIR),)
	MANIFESTDIR=/var/svc/manifest/site
endif
ifeq ($(CONFDIR),)
	CONFDIR=/etc
endif

ifeq ($(SOLARISVERSION),)
	SOLARISVERSION=$(shell ./get_solaris_version)
endif

INSTALL=/usr/sbin/install

# INSTROOT may be passed in, e.g. RPM_BUILD_ROOT
ifeq ($(INSTROOT),)
	BIN_D=$(BINDIR)
	METH_D=$(METHODDIR)
	MANI_D=$(MANIFESTDIR)
	CONF_D=$(CONFDIR)
else
	BIN_D=$(INSTROOT)/$(BINDIR)
	METH_D=$(INSTROOT)/$(METHODDIR)
	MANI_D=$(INSTROOT)/$(MANIFESTDIR)
	CONF_D=$(INSTROOT)/$(CONFDIR)
endif

HEADERS= hsflowd.h hsflowtokens.h sflowovsd.h Makefile

SFLOWDIR=../sflow

#CC= g++
CC= gcc -std=gnu99
#CC=sparc-sun-solaris2.11-gcc -std=gnu99


OPT_FULL = -O3 -DNDEBUG
OPT_DEBUG = -g -ggdb
ifeq ($(OPT),)
	OPT=$(OPT_FULL)
endif

READ_OBJS=readInterfaces.o \
          readCpuCounters.o \
          readMemoryCounters.o \
          readDiskCounters.o \
          readHidCounters.o \
          readNioCounters.o \
	  readJSON.o

HSFLOW_OBJS= hsflowconfig.o \
             dnsSD.o \
             hsflowd.o \
             util.o

SFLOWOVS_OBJS=sflowovsd.o util.o

CFLAGS+= -I. -I$(SFLOWDIR) $(OPT) -Wall -DHSP_VERSION=$(VERSION) -DHSP_SOLARIS=$(SOLARISVERSION) -DUTHEAP
LIBS+= $(SFLOWDIR)/libsflow.a -lresolv -lpthread -lsocket -lnsl -lkstat -ldlpi

# if JSON is not set, assume it should be "yes".
# (So you can use "make JSON=no" to compile without this feature)
ifeq ($(JSON),)
	JSON=yes
endif
ifeq ($(JSON),yes)
	JSONDIR=../json
	CFLAGS += -DHSF_JSON -I$(JSONDIR)
	LIBS += $(JSONDIR)/libcjson.a -lm
endif

#### BUILD ####

all: hsflowd sflowovsd

hsflowd: $(HSFLOW_OBJS) $(READ_OBJS)
	$(CC) $(CFLAGS) -o $@ $(HSFLOW_OBJS) $(READ_OBJS) $(LIBS)

sflowovsd: $(SFLOWOVS_OBJS)
	$(CC) $(CFLAGS) -o $@ $(SFLOWOVS_OBJS) $(LIBS)

#### INSTALL ####

install: install-hsflowd

install-hsflowd: hsflowd
	$(INSTALL) -d $(BIN_D)
	$(INSTALL) -f $(BIN_D) -m 755 hsflowd
	if [ ! -e $(METH_D)/svc-hsflowd ]; then $(INSTALL) -d $(METH_D); $(INSTALL) -f $(METH_D) -m 555 scripts/svc-hsflowd; fi
	if [ ! -e $(MANI_D)/hsflowd.xml ]; then $(INSTALL) -d $(MANI_D); $(INSTALL) -f $(MANI_D) -m 444 scripts/hsflowd.xml; fi
	if [ ! -e $(CONF_D)/hsflowd.conf ]; then $(INSTALL) -d $(CONF_D); $(INSTALL) -f $(CONF_D) -m 644 scripts/hsflowd.conf; fi

install-sflowovsd: sflowovsd
	$(INSTALL) -d $(BIN_D)
	$(INSTALL) -m 700 sflowovsd $(BIN_D)
	if [ ! -e $(METH_D)/sflowovsd ]; then $(INSTALL) -d $(METH_D); $(INSTALL) -m 700 scripts/sflowovsd $(METH_D); fi

#### SCHEDULE ####

# the chkconfig command may not be available in your VM, but all it does it to put the
# necessary links into the /etc/init.d/rc*.d directories to start and stop the daemon
# at the required runlevels.

schedule: schedule-hsflowd

schedule-hsflowd:
	/usr/sbin/svccfg import $(MANI_D)/hsflowd.xml
	/usr/sbin/svcadm enable hsflowd

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
readInterfaces.o: readInterfaces.c $(HEADERS)
readCpuCounters.o: readCpuCounters.c $(HEADERS)
readMemoryCounters.o: readMemoryCounters.c $(HEADERS)
readDiskCounters.o: readDiskCounters.c $(HEADERS)
readHidCounters.o: readHidCounters.c $(HEADERS)
readJSON.o: readJSON.c $(HEADERS)
readNioCounters.o: readNioCounters.c $(HEADERS)
sflowovsd.o: sflowovsd.c $(HEADERS)

