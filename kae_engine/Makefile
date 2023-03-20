#
# Author: wudinggui
# Date:   2019/7/4

# Description:
# compile for accelerator
#
# Usage:
#   $ make           compile and link the program.
#   $ make rebuild   rebuild the program. The same as make clean && make all.
#   $ make clean     clean the objective, dependent and executable files.
#   $ make install   copy to the system directory.
#   $ make uninstall clean the executable file from the system directory.
#==============================================================================
WORK_PATH := .
ENGINE_INSTALL_PATH := $(OPENSSL_WORK_PATH)/lib/engines-1.1

CC=gcc

LIBNAME := libkae.so
VERSION = 1.3.11
TARGET = ${LIBNAME}.${VERSION}
SOFTLINK = kae.so

ifndef SILENCE
	SILENCE = @
endif

# Src
SRCDIRS   := ${WORK_PATH}/
SRCDIRS   += ${WORK_PATH}/alg/pkey
SRCDIRS   += ${WORK_PATH}/alg/dh
SRCDIRS   += ${WORK_PATH}/alg/ciphers
SRCDIRS   += ${WORK_PATH}/alg/digests
SRCDIRS   += ${WORK_PATH}/async
SRCDIRS   += ${WORK_PATH}/wdmngr
SRCDIRS   += ${WORK_PATH}/utils

SRCEXTS   := .c # C program

# Include
INCDIR += -I $(WORK_PATH)/
INCDIR += -I $(WORK_PATH)/alg/pkey
INCDIR += -I $(WORK_PATH)/alg/dh
INCDIR += -I $(WORK_PATH)/alg/ciphers
INCDIR += -I $(WORK_PATH)/alg/digests
INCDIR += -I $(WORK_PATH)/async
INCDIR += -I $(WORK_PATH)/wdmngr
INCDIR += -I $(WORK_PATH)/utils
INCDIR += -I $(OPENSSL_WORK_PATH)/include

# Include Libs.
LIBDIR := -L$(OPENSSL_WORK_PATH)/lib
LIBDIR += -L/usr/lib64
LIBS := -lcrypto -lwd -pthread
LIBS += -lc_nonshared

# The flags
CFLAGS    := -Wall -Werror -fstack-protector-all -fPIC -D_GNU_SOURCE -shared -fgnu89-inline
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
	-@objcopy --only-keep-debug ./$(TARGET) $(TARGET).symbol
	-@strip ./$(TARGET)
rebuild: clean all

clean :
	@-$(RM) *.d *.a *.so *.symbol $(TARGET)
	@-$(RM)
	@find ${WORK_PATH} -name '*.o' -exec $(RM) {} \;
	@echo all clean

install :
	mkdir -p $(ENGINE_INSTALL_PATH)
	install -m 755 $(TARGET) $(ENGINE_INSTALL_PATH)
	$(LN) $(ENGINE_INSTALL_PATH)/$(TARGET)  $(ENGINE_INSTALL_PATH)/$(SOFTLINK)
	$(LN) $(ENGINE_INSTALL_PATH)/$(TARGET)  $(ENGINE_INSTALL_PATH)/$(SOFTLINK).0
uninstall :
	$(RM) $(ENGINE_INSTALL_PATH)/$(SOFTLINK)
	$(RM) $(ENGINE_INSTALL_PATH)/$(SOFTLINK).0
	$(RM) $(ENGINE_INSTALL_PATH)/$(TARGET)
	$(RM) /var/log/kae.log
	$(RM) /var/log/kae.log.old
