CC=g++
FLAGS=-g -std=c++11 -Wall
PROGS = ssl_server ssl_client
#INCLUDE=-I${shell pwd} -I/home/nwq/debug/ssl1_1w/include
#LIBPATH= -L${shell pwd} -lssl -lcrypto -lboost_system -lboost_filesystem -lboost_thread -lpthread
#LIBPATH= -L${shell pwd} -L/home/nwq/debug/ssl1_1w/lib  -lssl -lcrypto -lboost_system -lboost_filesystem -lboost_thread -lpthread

INCLUDE=-I${shell pwd} 

LIBPATH= -L${shell pwd} -lssl -lcrypto -lboost_system -lboost_filesystem -lboost_thread -lpthread

RPATH=-Wl,-rpath,'$$ORIGIN'

all: ${PROGS}

ssl_server: ssl_server.cpp
	${CC} ${FLAGS} -g -o ssl_server ssl_server.cpp ${INCLUDE} ${RPATH} ${LIBPATH}

ssl_client: ssl_client.cpp
	${CC} ${FLAGS} -g -o ssl_client ssl_client.cpp ${INCLUDE} ${RPATH} ${LIBPATH}

clean:
	rm -fr ${PROGS} *dSYM
