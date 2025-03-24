#
# use options below when compiling with gcc
#
CPPFLAGS=-I/usr/lib/gcc/x86_64-linux-gnu/13/include
CPPFLAGS+=-D_GNU_SOURCE
LDFLAGS+=-ldl
LDFLAGS+=-L/usr/lib/gcc/x86_64-linux-gnu/13/
LDFLAGS+=-lgcc_s
CFLAGS=-64 -g -O0 -Wall -Wno-format

#
# use options below when building with clang on OpenBSD
#
# pulls libunwind.h header supplied by clang
# perhaps specific to OpenBSD.
#
#CPPFLAGS=-I/usr/include/c++/v1/
#CPPFLAGS+=-DUSE_LIBUNWIND
#CFLAGS=-g -O0 -Wall
##
## This is perhaps specific to OpenBSD. Other
## systems might differ. -lLLVM pulls all
## libraries which come form clang including libunwind
## For other systems you need to bit of googling.
## last resort is to build libunind on your own:
##	https://github.com/libunwind/libunwind
## you may use clang options:
##	 --rtlib=compiler-rt --unwindlib=libunwind
## as described here:
##	https://maskray.me/blog/2020-11-08-stack-unwinding
## libundwind is part of libc++ we need to grab it
#LDFLAGS=-lLLVM
#LDFLAGS+=-lc++
#LDFLAGS+=-lm

#
# common options to add libcrypto
#
CPPFLAGS+=-D_WITH_STACKTRACE
CPPFLAGS+=-fPIC
CPPFLAGS+=-I$(OPENSSL_HEADERS)
OSSLLIB=$(OPENSSL_LIB_PATH)

all: libmprofile.so

init.o: init.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o init.o init.c

ksyms.o: ksyms.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o ksyms.o ksyms.c

record.o: record.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o record.o record.c

stack.o: stack.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o stack.o stack.c

libmprofile.so: init.o ksyms.o record.o stack.o
	$(CC) -pthread -shared -fPIC -o libmprofile.so init.o record.o \
	    stack.o ksyms.o -lelf $(LDFLAGS) -L$(OSSLLIB) -lcrypto

clean:
	rm -f *.o
	rm -f libmprofile.so
