
INCDIR := -I ./openssl-OpenSSL_1_1_1u/include/
INCDIR += -I ./openssl-OpenSSL_1_1_1u/test/
# Include Libs.
LIBDIR := -L./openssl-OpenSSL_1_1_1u/
LIBS := -lssl -ldl -lpthread

# The flags
CFLAGS    := -g -lz -Wall
LDFLAGS   := $(LIBS)
LDFLAGS   += $(LIBDIR)

all: sm2_test_perf
objects = sm2_function_test.c

sm2_test_perf : $(objects)
	gcc $(CFLAGS) $(LDFLAGS) $(INCDIR) -o  sm2_test_perf $(objects) ./openssl-OpenSSL_1_1_1u/libcrypto.a ./openssl-OpenSSL_1_1_1u/test/libtestutil.a

.PHONY : clean
clean :
	-rm -f sm2_test_perf
