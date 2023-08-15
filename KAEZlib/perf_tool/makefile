
INCDIR += -I /usr/local/kaezip/include/
# Include Libs.
LIBDIR := -L/usr/local/kaezip/lib

# The flags
CFLAGS    := -g -lz -Wall
LDFLAGS   := $(LIBDIR)

all: kaezip_perf zip_perf
objects = kaezip_tool.c

kaezip_perf : $(objects)
	gcc $(CFLAGS) $(LDFLAGS) $(INCDIR) -Wl,-rpath=/usr/local/kaezip/lib -o kaezip_perf $(objects)
zip_perf : $(objects)
	gcc $(CFLAGS) -o zip_perf $(objects)	

.PHONY : clean
clean :
	-rm -f kaezip_perf zip_perf
