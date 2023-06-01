#
# Generic Makefile for C Program
# Description:
# compile for accelerator
#
# Usage:
#   $ make           compile and link the program.
#   $ make rebuild   rebuild the program. The same as make clean && make all.
#   $ make clean     clean the objective, dependent and executable files.
#==============================================================================
WORK_PATH := $(shell pwd)
CC:=gcc
CXX:=g++

TARGET := kaetest

ifndef SILENCE
	SILENCE = @
endif

# Src
SRCDIRS   := ${WORK_PATH}/
SRCEXTS   := .c .cpp # C program

# Include
INCDIR += -I $(WORK_PATH)/
INCDIR += -I $(WORK_PATH)/../../kae_engine/src/utils
INCDIR += -I /usr/include/openssl
# INCDIR += -I $(WORK_PATH)/../../uadk
INCDIR += -I $(WORK_PATH)/../../uadk/include
# INCDIR += -I /usr/include/gtest
INCDIR += -I $(WORK_PATH)/../../gtest-download/googletest-release-1.11.0/googletest/include

# Include Libs.
LIBDIR := -L/usr/local/lib
LIBDIR += -L/usr/lib/
LIBDIR += -L $(WORK_PATH)/../test_tool_bins/gtest

#LIBS += -L/usr/lib/lgtest.a
#LIBS += -L/usr/lib/lgtest_main.a
LIBS += -lgtest_main -lgtest -lcrypto -lpthread -lm -lcrypto -lssl 

# The flags
CFLAGS    := -g -pipe -Wall -Wextra -Wshadow -fPIC -std=c++11 -Wl,-rpath,/usr/local/lib
LDFLAGS   := $(LIBDIR)
LDFLAGS   += $(LIBS)

# The command used to delete file.
RM        = rm -f

#SOURCES = $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)*,$(SRCEXTS))))
SOURCES = 
SOURCES += testsuit_common.cpp
SOURCES += testsuit_common.h
ifeq (y,${UTESTCONF_TEST_RSA_NORMAL})
SOURCES += testsuit_rsa.cpp
endif
ifeq (y,${UTESTCONF_TEST_RSA_QUEUE})
SOURCES += test_rsa_queue.cpp
endif
ifeq (y,${UTESTCONF_TEST_RSA_MULTI})
SOURCES += test_rsa_multithread_queue.cpp
endif
ifeq (y,${UTESTCONF_TEST_SM3_NORMAL})
SOURCES += testsuit_sm3_digest.cpp
endif
ifeq (y,${UTESTCONF_TEST_SM3_QUEUE})
SOURCES += test_sm3_queue.cpp
endif
ifeq (y,${UTESTCONF_TEST_SM3_MULTI})
SOURCES += test_sm3_multithread_queue.cpp
endif
ifeq (y,${UTESTCONF_TEST_SM4_NORMAL})
SOURCES += testsuit_sm4_cipher.cpp
endif
ifeq (y,${UTESTCONF_TEST_SM4_QUEUE})
SOURCES += test_sm4_queue.cpp
endif
ifeq (y,${UTESTCONF_TEST_SM4_MULTI})
SOURCES += test_sm4_multithread_queue.cpp
endif
ifeq (y,${UTESTCONF_TEST_DH})
SOURCES += test_dh.cpp
endif
ifeq (y,${UTESTCONF_TEST_ASYNC_CIPHER})
SOURCES += testsuit_cihper.cpp
endif
ifeq (y,${UTESTCONF_TEST_ASYNC_DIGEST})
SOURCES += testsuit_digest.cpp
endif
ifeq (y,${UTESTCONF_TEST_AES})
SOURCES += testsuit_aes.cpp
endif
ifeq (y,${UTESTCONF_TEST_SM4_AES_MULTITHREAD})
SOURCES += testsuit_sm4_aes_multithread.cpp
endif

ifeq (y,${ALL})
SOURCES = 
SOURCES = $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)*,$(SRCEXTS))))
endif


OBJS    = $(foreach x,$(SRCEXTS), \
      $(patsubst %$(x), %.o, $(filter %$(x),$(SOURCES))))

.PHONY : all objs clean cleanall rebuild

all : deps $(TARGET)
  

deps:
	
# Rules for creating the dependency files (.d).
%.d : %.cpp
	$(CXX) -MM -MD $(CFLAGS)  $<

# Rules for producing the objects.
objs : $(OBJS)
%.o : %.c
	@echo compiling $(notdir $<)
	$(SILENCE) $(CC) -c $(CFLAGS) $(INCDIR) $(LDFLAGS) -o $@ $<

%.o : %.cpp
	@echo compiling $(notdir $<)
	$(SILENCE) $(CXX) -c $(CFLAGS) $(INCDIR) $(LDFLAGS) -o $@ $<

$(TARGET): $(OBJS)
	@echo Linking $@
   
	$(SILENCE) $(CXX) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(INCDIR) -o ./$(TARGET) $(OBJS)

rebuild: clean all

clean :
	@-$(RM) *.d *.a *.so $(TARGET)
	@-$(RM)	
	@find ${WORK_PATH} -name '*.o' -exec $(RM) {} \;
	@echo all clean
