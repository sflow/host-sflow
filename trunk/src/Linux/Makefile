# This software is distributed under the following license:
# http://host-sflow.sourceforge.net/license.html

ifeq ($(BINDIR),)
	BINDIR=/usr/local/sbin
endif
ifeq ($(INITDIR),)
	INITDIR=/etc/init.d
endif
ifeq ($(CONFDIR),)
	CONFDIR=/etc
endif

HEADERS= hsflowd.h hsflowtokens.h Makefile

SFLOWDIR=../sflow

OPT = -O3 -DNDEBUG
#OPT = -g -ggdb -O2
OPT= -g -ggdb

CFLAGS= -D_GNU_SOURCE -DSTDC_HEADERS $(OPT) -Wall -Wcast-align

#CC= g++
CC= gcc -std=c99

READ_OBJS=readInterfaces.o \
          readCpuCounters.o \
          readMemoryCounters.o \
          readDiskCounters.o \
          readHidCounters.o \
          readNioCounters.o

HSFLOW_OBJS= hsflowconfig.o \
             hsflowd.o

OBJS=$(HSFLOW_OBJS) $(READ_OBJS)

LIBS=$(SFLOWDIR)/libsflow.a

all: hsflowd

hsflowd: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

install: hsflowd
	install -m 700 hsflowd $(BINDIR)
	if [ ! -e $(INITSDIR)/hsflowd ]; then install -m 700 scripts/hsflowd $(INITDIR); fi
	if [ ! -e $(CONFDIR)/hsflowd.conf ]; then install -m 700 scripts/hsflowd.conf $(CONFDIR); fi

# the chkconfig command may not be available in your VM, but all it does it to put the
# necessary links into the /etc/init.d/rc*.d directories to start and stop the daemon
# at the required runlevels
schedule:
	/sbin/chkconfig --level 345 hsflowd on
	/sbin/chkconfig --list hsflowd

.c.o: $(HEADERS)
	$(CC) $(CFLAGS) -I. -I$(SFLOWDIR) -c $*.c

clean:
	rm -f $(OBJS) hsflowd

# dependencies
hsflowconfig.o: hsflowconfig.c $(HEADERS)
hsflowd.o: hsflowd.c $(HEADERS)
readInterfaces.o: readInterfaces.c $(HEADERS)
readCpuCounters.o: readCpuCounters.c $(HEADERS)
readMemoryCounters.o: readMemoryCounters.c $(HEADERS)
readDiskCounters.o: readDiskCounters.c $(HEADERS)
readHidCounters.o: readHidCounters.c $(HEADERS)
readNioCounters.o: readNioCounters.c $(HEADERS)

