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

TARGET := kaezlibtest

ifndef SILENCE
	SILENCE = @
endif

# Src
SRCDIRS   := ${WORK_PATH}/src
SRCEXTS   := .c .cpp # C program

# header and lib
INCDIR := -I /usr/local/kaezip/include/
LIBDIR := -L /usr/local/kaezip/lib/
LIBDIR += -L/usr/lib/

# Include
INCDIR += -I $(SRCDIRS)/
# INCDIR += -I $(WORK_PATH)/../../uadk/include
INCDIR += -I $(WORK_PATH)/gtest-download/googletest-release-1.11.0/googletest/include

# Include Libs.
LIBDIR += -L $(WORK_PATH)/test_tool_bins/gtest
LIBS +=  -lgtest_main -lgtest -lz

# The flags
CFLAGS    := -g -pipe -Wall -Wextra -Wshadow -fPIC -std=c++11 #-Wl,-rpath,/usr/local/kaezip/lib
LDFLAGS   += $(LIBDIR)
LDFLAGS   += $(LIBS)

# The command used to delete file.
RM        = rm -f

SOURCES = $(SRCDIRS)/original_case.cpp
SOURCES += $(SRCDIRS)/zlib_compress.cpp
SOURCES += $(SRCDIRS)/zlib_inflate.cpp

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
