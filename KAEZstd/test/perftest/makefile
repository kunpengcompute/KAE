# 注：make 前先 install kae_zstd  

INCDIR += -I/usr/local/kaezstd/include/
# Include Libs.
LIBDIR := -L/usr/local/kaezstd/lib -lzstd -lwd_comp -lwd -lkaezstd

# The flags
CFLAGS    := -g -Wall
LDFLAGS   := $(LIBDIR)

all: kaezstd_perf
objects = kaezstd_perf.c

kaezstd_perf : $(objects)
	gcc $(CFLAGS) $(LDFLAGS) $(INCDIR) -o kaezstd_perf $(objects)

.PHONY : clean
clean :
	-rm -f kaezstd_perf
