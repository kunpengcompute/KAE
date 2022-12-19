#
# Date:   2020/2/10

# Description:
# compile for KAEzip 
#
# Usage:
#   $ make           compile and link the program.
#   $ make rebuild   rebuild the program. The same as make clean && make all.
#   $ make clean     clean the objective, dependent and executable files.
#   $ make install   copy to the system directory.
#   $ make uninstall clean the executable file from the system directory.
#==============================================================================
WORK_PATH := .
ENGINE_INSTALL_PATH := /usr/local/kaezip

CC=gcc

LIBNAME := libkaezip.so
VERSION = 1.3.11
TARGET = ${LIBNAME}.${VERSION}
SOFTLINK = libkaezip.so

ifndef SILENCE
	SILENCE = @
endif

# Src
SRCDIRS   := ${WORK_PATH}/
SRCDIRS   += ${WORK_PATH}/src

SRCEXTS   := .c # C program

# Include
INCDIR += -I $(WORK_PATH)/
INCDIR += -I $(WORK_PATH)/include
INCDIR += -I $(WORK_PATH)/open_source/zlib-1.2.11
INCDIR += -I $(WORK_PATH)/open_source/zlib-1.2.7
INCDIR += -I /usr/local/include/warpdrive/
INCDIR += -I /usr/include/warpdrive/
# Include Libs.
LIBDIR += -L/usr/local/lib
LIBDIR += -L/usr/lib64
LIBDIR += -L$(WORK_PATH)/open_source/zlib-1.2.11
LIBDIR += -L$(WORK_PATH)/open_source/zlib-1.2.7
LIBS := -lz -lwd -pthread
LIBS += -lc_nonshared

# The flags
CFLAGS    := -Wall -Werror -fstack-protector-all -fPIC -D_GNU_SOURCE -shared
LDFLAGS   := $(LIBDIR)
LDFLAGS   += $(LIBS) 
LDFLAGS   += -Wl,-z,relro,-z,now,-z,noexecstack  #safe link option

# The command used to delete file.
RM        = rm -f
LN        = ln -sf

SOURCES = $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))

OBJS    = $(foreach x,$(SRCEXTS), \
      $(patsubst %$(x), %.o, $(filter %$(x),$(SOURCES))))

.PHONY : all objs clean cleanall rebuild

all : $(TARGET)

# Rules for creating the dependency files (.d).
%.d : %.c
	$(CC) -MM -MD $(CFLAGS)  $<

# Rules for producing the objects.
objs : $(OBJS)
%.o : %.c
	@echo compiling $(notdir $<)
	$(SILENCE) $(CC) -c $(CFLAGS) $(INCDIR) $(LDFLAGS) -o $@ $<

$(TARGET): $(OBJS)
	@echo Linking $@
	$(SILENCE) $(CC) $(CFLAGS) $(INCDIR) -o ./$(TARGET) $(OBJS) $(LDFLAGS)
rebuild: clean all

clean :
	@-$(RM) *.d *.a *.so *.symbol $(TARGET)
	@-$(RM)
	@find ${WORK_PATH} -name '*.o' -exec $(RM) {} \;
	@echo all clean

install :
	mkdir -p $(ENGINE_INSTALL_PATH)/include
	mkdir -p $(ENGINE_INSTALL_PATH)/lib
	install -m 755 $(TARGET) $(ENGINE_INSTALL_PATH)/lib
	$(LN) $(ENGINE_INSTALL_PATH)/lib/$(TARGET)  $(ENGINE_INSTALL_PATH)/lib/$(SOFTLINK)
	$(LN) $(ENGINE_INSTALL_PATH)/lib/$(TARGET)  $(ENGINE_INSTALL_PATH)/lib/$(SOFTLINK).0
	install -m 755 $(WORK_PATH)/include/kaezip.h $(ENGINE_INSTALL_PATH)/include
uninstall :
	$(RM) $(ENGINE_INSTALL_PATH)/lib/$(SOFTLINK)
	$(RM) $(ENGINE_INSTALL_PATH)/lib/$(SOFTLINK).0
	$(RM) $(ENGINE_INSTALL_PATH)/lib/$(TARGET)
	$(RM) $(ENGINE_INSTALL_PATH)/include/kaezip.h
	$(RM) /var/log/kaezip.log
	$(RM) /var/log/kaezip.log.old