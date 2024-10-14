
# Include Libs.
LIBDIR := -L/usr/local/kaelz4/lib -llz4 -lkaelz4
# The flags
CFLAGS    := -Wall
LDFLAGS   := $(LIBDIR)

all: kaelz4_perf
objects = kaelz4_perf.c

kaelz4_perf : $(objects)
	gcc $(CFLAGS) $(LDFLAGS) -o kaelz4_perf $(objects)

.PHONY : clean
clean :
	-rm -f kaelz4_perf
