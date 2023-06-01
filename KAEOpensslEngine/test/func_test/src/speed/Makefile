
CC:=gcc

TARGET := speedtest

ifndef SILENCE
	SILENCE = @
endif

# Src
SRCDIRS   := $(shell pwd)/
SRCEXTS   := .c .cpp # C program

# Include
INCDIR += -I /usr/local/openssl/include/
INCDIR += -I /usr/include/openssl/
# Include Libs.
LIBDIR := -L/usr/local/openssl/lib
LIBDIR += -L/usr/lib/

LIBS += -lcrypto -lpthread -lm -lcrypto -lssl 

# The flags
CFLAGS    := -g -pipe -Wall -Wextra -Wshadow -fPIC -std=c++11
LDFLAGS   := $(LIBDIR)
LDFLAGS   += $(LIBS)

# The command used to delete file.
RM        = rm -f

ifeq (y,${MD5_SPEED_TEST})
SOURCES = md5_speed.c
TARGET := md5_speed
endif
ifeq (y,${DH_SPEED_TEST})
SOURCES = dh_speed.c
TARGET := dh_speed
endif

#SOURCES = $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)*,$(SRCEXTS))))


OBJS    = $(foreach x,$(SRCEXTS), \
      $(patsubst %$(x), %.o, $(filter %$(x),$(SOURCES))))

.PHONY : all objs clean cleanall rebuild

all : deps $(TARGET)
  

deps:
	
# Rules for producing the objects.
objs : $(OBJS)
%.o : %.c
	@echo compiling $(notdir $<)
	$(SILENCE) $(CC) -c $(CFLAGS) $(INCDIR) $(LDFLAGS) -o $@ $<

$(TARGET): $(OBJS)
	@echo Linking $@
	$(SILENCE) $(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(INCDIR) -o ./$(TARGET) $(OBJS)
   
rebuild: clean all

clean :
	@-$(RM) md5_speed dh_speed speedtest
	@find ${WORK_PATH} -name '*.o' -exec $(RM) {} \;
	@echo all clean