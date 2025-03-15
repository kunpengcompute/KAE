
INCDIR = -I ../include/ -I ../ -I /usr/include/
# Include Libs.
LIBDIR := -L../.libs -pthread -lcrypto -lwd

# The flags
CFLAGS    := -g -lz -Wall -O0 -fno-strict-aliasing
LDFLAGS   := $(LIBDIR)

all: test_wd_hpre
objects = test_hisi_hpre.c test_hisi_hpre.h

test_wd_hpre : $(objects)
	gcc $(CFLAGS) $(LDFLAGS) $(INCDIR) -o test_wd_hpre $(objects)

.PHONY : clean
clean :
	-rm -f test_wd_hpre
