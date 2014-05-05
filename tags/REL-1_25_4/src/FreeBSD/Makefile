# This software is distributed under the following license:
# http://host-sflow.sourceforge.net/license.html

.if empty $(BINDIR)
   BINDIR=/usr/sbin
.endif

.if empty $(INITDIR)
   INITDIR=/etc/rc.d
.endif

.if empty $(CONFDIR)
   CONFDIR=/etc
.endif

INSTALL=install

# INSTROOT may be passed in, e.g. RPM_BUILD_ROOT
.if empty $(INSTROOT)
  BIN_D=$(BINDIR)
  INIT_D=$(INITDIR)
  CONF_D=$(CONFDIR)
.else
  BIN_D=$(INSTROOT)/$(BINDIR)
  INIT_D=$(INSTROOT)/$(INITDIR)
  CONF_D=$(INSTROOT)/$(CONFDIR)
.endif

HEADERS= hsflowd.h hsflowtokens.h Makefile

SFLOWDIR=../sflow

#CC= g++
CC= gcc -std=gnu99

OPT_FULL = -O3 -DNDEBUG
OPT_DEBUG = -g -ggdb

.if empty $(OPT)
  OPT=$(OPT_FULL)
.endif

READ_OBJS=readInterfaces.o \
          readCpuCounters.o \
          readMemoryCounters.o \
          readDiskCounters.o \
          readHidCounters.o \
          readNioCounters.o

HSFLOW_OBJS= hsflowconfig.o \
             dnsSD.o \
             hsflowd.o \
             util.o

CFLAGS+= -I. -I$(SFLOWDIR) -DFreeBSD $(OPT) -Wall -D_GNU_SOURCE -DHSP_VERSION=$(VERSION)
LIBS+= $(SFLOWDIR)/libsflow.a -lpthread -ldevstat -lkvm

#### BUILD ####

all: hsflowd

hsflowd: $(HSFLOW_OBJS) $(READ_OBJS)
	$(CC) $(CFLAGS) -o $@ $(HSFLOW_OBJS) $(READ_OBJS) $(LIBS)

#### INSTALL ####

install: install-hsflowd 

install-hsflowd: hsflowd
	$(INSTALL) -d $(BIN_D)
	$(INSTALL) -m 700 hsflowd $(BIN_D)
	if [ ! -e $(INIT_D)/hsflowd ]; then $(INSTALL) -d $(INIT_D); $(INSTALL) -m 700 scripts/hsflowd $(INIT_D); fi
	if [ ! -e $(CONF_D)/hsflowd.conf ]; then $(INSTALL) -d $(CONF_D); $(INSTALL) -m 644 scripts/hsflowd.conf $(CONF_D); fi

#### SCHEDULE ####

schedule: schedule-hsflowd

schedule-hsflowd:
	@/bin/sh -c 'if grep -c hsflowd_enable /etc/rc.conf > /dev/null; then echo "already scheduled"; else echo "hsflowd_enable=\"YES\"" >> /etc/rc.conf; fi'

#### CLEAN ####

clean: clean-hsflowd

clean-hsflowd:
	rm -f $(HSFLOW_OBJS) $(READ_OBJS) hsflowd

#### dependencies ####

.c.o: $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c

util.o: util.c $(HEADERS)
hsflowconfig.o: hsflowconfig.c $(HEADERS)
dnsSD.o: dnsSD.c $(HEADERS)
hsflowd.o: hsflowd.c $(HEADERS)
readInterfaces.o: readInterfaces.c $(HEADERS)
readCpuCounters.o: readCpuCounters.c $(HEADERS)
readMemoryCounters.o: readMemoryCounters.c $(HEADERS)
readDiskCounters.o: readDiskCounters.c $(HEADERS)
readHidCounters.o: readHidCounters.c $(HEADERS)
readNioCounters.o: readNioCounters.c $(HEADERS)


