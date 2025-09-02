# The flags
CFLAGS    := -g -lz -Wall

all: sm2_test
objects = sm2_test.cpp

sm2_test : $(objects)
	g++ $(CFLAGS) -I /usr/include/ -lcrypto -lssl -o  sm2_test $(objects)

.PHONY : clean
clean :
	-rm -f sm2_test
