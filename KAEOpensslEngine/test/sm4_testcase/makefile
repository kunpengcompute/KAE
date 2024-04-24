
# Include Libs.
# LIBDIR := -L./openssl-OpenSSL_1_1_1u/
LIBS := -lcrypto

# The flags
CFLAGS    := -g -Wall
LDFLAGS   := $(LIBS)
LDFLAGS   += $(LIBDIR)

all: sm4Demo
objects = sm4_demo.c

sm4Demo : $(objects)
	gcc $(CFLAGS) $(LDFLAGS) $(INCDIR) -o  sm4Demo $(objects)

.PHONY : clean
clean :
	-rm -f sm4Demo
