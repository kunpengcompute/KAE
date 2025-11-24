# Include Libs.
LIBDIR := -I/usr/local/kaesnappy/include -L/usr/local/kaesnappy/lib -lsnappy -lkaesnappy
# The flags
CFLAGS    := -Wall
LDFLAGS   := $(LIBDIR)

all: kaesnappy_perf
objects = kaesnappy_perf.c

kaesnappy_perf : $(objects)
	gcc $(CFLAGS) $(LDFLAGS) -o kaesnappy_perf $(objects)

.PHONY : clean
clean :
	-rm -f kaesnappy_perf
