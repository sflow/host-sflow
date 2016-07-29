# This software is distributed under the following license:
# http://sflow.net/license.html

HEADERS= cJSON.h Makefile

OPT = -O3 -DNDEBUG
#OPT = -g -ggdb -O2
#OPT= -g -ggdb

CFLAGS= -D_GNU_SOURCE -DSTDC_HEADERS $(OPT) -Wall -Wcast-align
LDFLAGS=

#CC= g++
#CC= gcc -std=c99
CC= gcc

OBJS= cJSON.o
LIB=libjson.a

$(LIB): $(OBJS)
	ar cru $@ $(OBJS)
	ranlib $@

all: $(LIB)

test: $(OBJS) test.o
	$(CC) -o $@ test.o $(OBJS) -lm

install:

.c.o: $(HEADERS)
	$(CC) $(CFLAGS) -I. -c $*.c

clean:
	rm -f $(OBJS) $(LIB) test.o

# dependencies
cJSON.o: cJSON.c $(HEADERS)
test.o: test.c $(HEADERS)
