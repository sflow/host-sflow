# This software is distributed under the following license:
# http://sflow.net/license.html

APP_D     ?= /Applications/hsflowd.app/Contents/
CTL_D     ?= /Library/LaunchDaemons
CONF_D    ?= /etc
BIN_D = $(APP_D)/MacOS

#########  compilation flags  #########

HEADERS= util.h evbus.h hsflowd.h hsflowtokens.h cpu_utils.h Makefile

# compiler
#CC= g++
CC= gcc -std=gnu99
#CC= clang
#LD=ld
LD=gcc

# optimization
OPT_ALL= -O3 -DNDEBUG
OPT_REG= -g -O2
OPT_DBG= -g -ggdb
ifndef OPT
#  OPT=$(OPT_REG)
  OPT=$(OPT_DBG)
endif

# other source directories
SFLOWDIR=../sflow
JSONDIR=../json

# CFLAGS and LIBS - common
CFLAGS_HSFLOWD= -I. -I$(JSONDIR) -I$(SFLOWDIR) -dynamic -fPIC
#LIBS_HSFLOWD= $(JSONDIR)/libcjson.a $(SFLOWDIR)/libsflow.a -lm -pthread -ldl -lrt
LIBS_HSFLOWD= $(JSONDIR)/libcjson.a $(SFLOWDIR)/libsflow.a -ldl -fPIC -dynamic

# CFLAGS and LIBS - modules
CFLAGS_JSON=
LIBS_JSON=

CFLAGS_DNSSD=
LIBS_DNSSD=-lresolv

CFLAGS_PCAP=
LIBS_PCAP=-lpcap

# common CFLAGS and LIBS	
CFLAGS = $(CFLAGS_HSFLOWD) $(CFLAGS_SHARED) $(OPT) -D_GNU_SOURCE -DHSP_VERSION=$(VERSION)
CFLAGS += -DUTHEAP
CFLAGS += -DHSP_OPTICAL_STATS
CFLAGS += -DHSP_MOD_DIR=$(MODDIR)
CFLAGS += -Wall -Wstrict-prototypes -Wunused-value
CFLAGS += -Wunused-function
LIBS=

INSTALL=install

#########  object files  #########

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
OBJS_PCAP=mod_pcap.o

CFLAGS_HSFLOWD += $(CFLAGS_JSON) $(CFLAGS_DNSSD) $(CFLAGS_PCAP)
OBJS_HSFLOWD += $(OBJS_JSON) $(OBJS_DNSSD) $(OBJS_PCAP)
LIBS_HSFLOWD += $(LIBS_JSON) $(LIBS_DNSSD) $(LIBS_PCAP)

BUILDTGTS=hsflowd

all: $(BUILDTGTS)

#########  hsflowd  #########

hsflowd: $(OBJS_HSFLOWD) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(OBJS_HSFLOWD) $(LIBS) $(LIBS_HSFLOWD)

#########  install  #########

install:
	$(INSTALL) -d $(APP_D)
	$(INSTALL) -m 644 scripts/net.sflow.hsflowd.plist $(APP_D)
	$(INSTALL) -d $(BIN_D)
	$(INSTALL) -m 700 hsflowd $(BIN_D)
	$(INSTALL) -d $(CONF_D)
	$(INSTALL) -m 644 scripts/hsflowd.conf $(CONF_D)
	ln -s $(APP_D)/net.sflow.hsflowd.plist $(CTL_D)

#########  schedule  #########

schedule:

#########  clean   #########

clean: 
	rm -f hsflowd *.o *.so

#########  dependencies  #########

.c.o: $(HEADERS)
	$(CC) $(CFLAGS) -c $*.c

util.o: util.c $(HEADERS)
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
readTcpipCounters.o: readTcpipCounters.c $(HEADERS)
mod_json.o: mod_json.c $(HEADERS)
mod_dnssd.o: mod_dnssd.c $(HEADERS)
mod_pcap.o: mod_pcap.c $(HEADERS)
