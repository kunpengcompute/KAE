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

TARGET := kaedemo

ifndef SILENCE
	SILENCE = @
endif

# Src
SRCDIRS   := ${WORK_PATH}/
SRCEXTS   := .c .cpp # C program

#openssl header and lib
INCDIR := -I /opt/boringssl/install/include
INCDIR += -I /usr/local/boringssl/include
LIBDIR := -L /opt/boringssl/install/lib64
LIBDIR += -L /usr/local/boringssl/lib/engines-1.1

# Include
INCDIR += -I $(WORK_PATH)/
INCDIR += -I $(WORK_PATH)/../../uadk/include
INCDIR += -I $(WORK_PATH)/../../gtest-download/googletest-release-1.11.0/googletest/include

# Include Libs.
LIBDIR += -L $(WORK_PATH)/../test_tool_bins/gtest
LIBS += -lgtest_main -lgtest -lcrypto -lssl -l:kae_bssl.so

# The flags
CFLAGS    :=  -g -Wall -pipe -Wall -Wextra -Wshadow -fPIC  -Wl,-rpath,/usr/local/lib # -std=c++11

LDFLAGS   := $(LIBDIR)
LDFLAGS   += $(LIBS)

# The command used to delete file.
RM        = rm -f

#SRCDIRS c & cpp file
SOURCES = $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)*,$(SRCEXTS))))

INCDIR += -I $(SRCDIRS)/utils
SOURCES += $(foreach d,$(SRCDIRS)/utils/,$(wildcard $(addprefix $(d)*,$(SRCEXTS))))

ifeq (y,${KAE_DEMO_RSA})
INCDIR += -I $(SRCDIRS)/rsa
SOURCES += $(foreach d,$(SRCDIRS)/rsa/,$(wildcard $(addprefix $(d)*,$(SRCEXTS))))
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
   
	$(SILENCE) $(CXX) $(CPPFLAGS) $(CFLAGS)  $(LDFLAGS) -o ./$(TARGET) $(OBJS)


rebuild: clean all

clean :
	@-$(RM) *.d *.a *.so $(TARGET)
	@-$(RM)	
	@find ${WORK_PATH} -name '*.o' -exec $(RM) {} \;
	@echo all clean
