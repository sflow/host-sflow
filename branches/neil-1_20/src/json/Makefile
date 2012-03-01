# This software is distributed under the following license:
# http://host-sflow.sourceforge.net/license.html

HEADERS= cJSON.h Makefile

OPT = -O3 -DNDEBUG
#OPT = -g -ggdb -O2
#OPT= -g -ggdb

CFLAGS= -D_GNU_SOURCE -DSTDC_HEADERS $(OPT) -Wall -Wcast-align
LDFLAGS=

#CC= g++
#CC= gcc -std=c99
CC= gcc

OBJS= cJSON.c
LIB=libjson.a

$(LIB): $(OBJS)
	ar cru $@ $(OBJS)
	ranlib $@

all: $(LIB)

install:

.c.o: $(HEADERS)
	$(CC) $(CFLAGS) -I. -c $*.c

clean:
	rm -f $(OBJS) $(LIB)

# dependencies
cJSON.o: cJSON.c $(HEADERS)

