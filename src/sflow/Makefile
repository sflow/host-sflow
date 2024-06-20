# This software is distributed under the following license:
# http://sflow.net/license.html

HEADERS= sflow_api.h sflow_xdr.h sflow.h Makefile

#OPT = -O3 -DNDEBUG
OPT = -g -ggdb -O2
#OPT= -g -ggdb

CFLAGS= -D_GNU_SOURCE -DSTDC_HEADERS $(OPT) -Wall -Wcast-align
CFLAGS += -DSFL_USE_32BIT_INDEX -Wno-unused-function
LDFLAGS=

#CC= g++
#CC= gcc -std=c99
CC= gcc

OBJS= sflow_agent.o \
      sflow_sampler.o \
      sflow_poller.o \
      sflow_notifier.o \
      sflow_receiver.o \
      sflow_xdr.o

libsflow.a: $(OBJS)
	ar cru $@ $(OBJS)
	ranlib $@

all: libsflow.a

install:

.c.o: $(HEADERS)
	$(CC) $(CFLAGS) -I. -c $*.c

clean:
	rm -f $(OBJS) libsflow.a

# dependencies
sflow_agent.o: sflow_agent.c $(HEADERS)
sflow_sampler.o: sflow_sampler.c $(HEADERS)
sflow_poller.o: sflow_poller.c $(HEADERS)
sflow_notifier.o: sflow_notifier.c $(HEADERS)
sflow_receiver.o: sflow_receiver.c $(HEADERS)
sflow_xdr.o: sflow_xdr.c $(HEADERS)

