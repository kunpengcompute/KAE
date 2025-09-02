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
INCDIR += -I /usr/include/openssl
LIBDIR := -L/usr/local/lib
LIBDIR += -L/usr/lib/

# Include
INCDIR += -I $(WORK_PATH)/
INCDIR += -I $(WORK_PATH)/../../uadk/include
INCDIR += -I $(WORK_PATH)/../../gtest-download/googletest-release-1.11.0/googletest/include

# Include Libs.
LIBDIR += -L $(WORK_PATH)/../test_tool_bins/gtest
LIBS += -lgtest_main -lgtest -lcrypto -lpthread -lm -lssl 

# The flags
CFLAGS    := -g -pipe -Wall -Wextra -Wshadow -fPIC -std=c++11 -Wl,-rpath,/usr/local/lib

LDFLAGS   := $(LIBDIR)
LDFLAGS   += $(LIBS)

# The command used to delete file.
RM        = rm -f

#SRCDIRS c & cpp file
SOURCES = $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)*,$(SRCEXTS))))

ifeq (y,${KAE_DEMO_CIPHER})
INCDIR += -I $(SRCDIRS)/cipher/
SOURCES += $(foreach d,$(SRCDIRS)/cipher/,$(wildcard $(addprefix $(d)*,$(SRCEXTS))))
endif

ifeq (y,${KAE_DEMO_RSA})
INCDIR += -I $(SRCDIRS)/rsa/
SOURCES += $(foreach d,$(SRCDIRS)/rsa/,$(wildcard $(addprefix $(d)*,$(SRCEXTS))))
endif

ifeq (y,${KAE_DEMO_DIGEST})
INCDIR += -I $(SRCDIRS)/digest/
SOURCES += $(foreach d,$(SRCDIRS)/digest/,$(wildcard $(addprefix $(d)*,$(SRCEXTS))))
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
