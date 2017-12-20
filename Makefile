#
# This Makefile assumes that PF_RING is installed as a binary package: see http://packages.ntop.org 
#
#
# DNA Support
DNA_DEFINE = #-DENABLE_DNA_SUPPORT

#
# PF_RING aware libpcap
#
O_FLAG     = -O2 -DHAVE_PF_RING

#
# MONGODB
#
#MONGODIR  = /usr/local/include/libmongoc-1.0
#BSONDIR   = /usr/local/include/libbson-1.0
#MONGOLIBDIR = /usr/local/lib
# Search directories
#
#INCLUDE    =  -I${MONGODIR} -I${BSONDIR} 

#
# C compiler and flags
#
#
# CROSS_COMPILE=arm-mv5sft-linux-gnueabi-
#-std=gnu9
CC         = ${CROSS_COMPILE}g++ 
CFLAGS     =  ${O_FLAG} -Wall -std=gnu99 ${DNA_DEFINE} -D HAVE_ZERO -D ENABLE_BPF -D HAVE_LIBNUMA -D HAVE_PTHREAD_SETAFFINITY_NP -O2  -g -pg -std=c++0x
# LDFLAGS  =

#
# User and System libraries
#
LIBS       = -lpcap -lpthread -lpfring  -lrt   -lnuma -lrt -lmongoc-1.0 -lbson-1.0 -lcrypto -lssl -lmysqlcppconn

# How to make an object file
%.o: %.cc 
	@echo "=*= making object $@ =*="
	${CC} ${CFLAGS} -c $< -o $@

#
# Main targets
#
PFPROGS   = amon-red read detect profile

TARGETS   = ${PFPROGS} 

all: ${TARGETS}

read: read.o
	${CC} ${CFLAGS} read.o ${LIBS} -o $@

detect: detect.o
	${CC} ${CFLAGS} detect.o ${LIBS} -o $@

profile: profile.o utils.o
	${CC} ${CFLAGS} profile.o utils.o ${LIBS} -o $@

amon:  amon.o 
	${CC} ${CFLAGS} amon.o  ${LIBS} -o $@

amon-red:  amon-red.o utils.o
	${CC} ${CFLAGS} amon-red.o utils.o ${LIBS} -o $@

clean:
	@rm -f ${TARGETS} *.o *~
