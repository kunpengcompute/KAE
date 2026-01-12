# direct GNU Make to search the directories relative to the
# parent directory of this file
SOURCE_PATH=$(dir $(lastword $(MAKEFILE_LIST)))
vpath
vpath %.c $(SOURCE_PATH)
vpath %.cc $(SOURCE_PATH)
vpath %.cpp $(SOURCE_PATH)

CC?=gcc
CXX?=g++
COMPILER = $(shell $(CC) -v 2>&1 | grep -q "clang version" && echo clang || echo gcc)

# Basic flags for dynamic library linking
DEFINES     += -I$(SOURCE_PATH)
CODE_FLAGS  += -Wno-unknown-pragmas -Wno-sign-compare -Wno-conversion
OPT_FLAGS   ?= -fomit-frame-pointer -fstrict-aliasing -ffast-math

ifeq ($(BUILD_TYPE),debug)
	OPT_FLAGS_O2 = $(OPT_FLAGS) -g
	OPT_FLAGS_O3 = $(OPT_FLAGS) -g
else
	OPT_FLAGS_O2 = $(OPT_FLAGS) -O2 -DNDEBUG
	OPT_FLAGS_O3 = $(OPT_FLAGS) -O3 -DNDEBUG
endif

CFLAGS = $(MOREFLAGS) $(CODE_FLAGS) $(OPT_FLAGS_O3) $(DEFINES)
CXXFLAGS = $(CFLAGS) -std=c++11
LDFLAGS += $(MOREFLAGS)

# Link with dynamic libraries
LDFLAGS += -lz -lzstd -llz4 -lsnappy -lpthread -lrt

# Platform specific settings
detected_OS := $(shell uname)
ifeq ($(detected_OS), Darwin)
    CXXFLAGS += -std=c++14
endif

ifneq (,$(filter Windows%,$(OS)))
	LDFLAGS += -lshell32 -lole32 -loleaut32
else
	LDFLAGS += -pthread -lrt
endif

# Object files
OBJS = compressors.o lzbench.o

all: lzbench

MKDIR = mkdir -p

# Pattern rules for compilation
%.o: %.cpp
	@$(MKDIR) $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

lzbench: $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf lzbench *.o

.PHONY: all clean