# This software is distributed under the following license:
# http://host-sflow.sourceforge.net/license.html

HEADERS= sflow_api.h sflow.h Makefile

OPT = -O3 -DNDEBUG
#OPT = -g -ggdb -O2
#OPT= -g -ggdb

CFLAGS= -D_GNU_SOURCE -DSTDC_HEADERS $(OPT) -Wall -Wcast-align
LDFLAGS=

#CC= g++
#CC= gcc -std=c99
CC= gcc

OBJS= sflow_agent.o \
      sflow_sampler.o \
      sflow_poller.o \
      sflow_receiver.o

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
sflow_receiver.o: sflow_receiver.c $(HEADERS)

