#
# Date:   2024/7/6

# Description:
# compile for KAELz4
#
# Usage:
#   $ make           compile and link the program.
#   $ make rebuild   rebuild the program. The same as make clean && make all.
#   $ make clean     clean the objective, dependent and executable files.
#   $ make install   copy to the system directory.
#   $ make uninstall clean the executable file from the system directory.
#==============================================================================

WORK_PATH := .
ENGINE_INSTALL_PATH := /usr/local/kaelz4

CC=gcc

LIBNAME := libkaelz4.so
VERSION = 2.0.4
TARGET = ${LIBNAME}.${VERSION}
SOFTLINK = libkaelz4.so

ifndef SILENCE
	SILENCE = @
endif

# Src
SRCDIRS   += ${WORK_PATH}/src
SRCDIRS   += ${WORK_PATH}/src/utils
SRCDIRS   += ${WORK_PATH}/src/v1
SRCDIRS   += ${WORK_PATH}/src/v2

SRCEXTS   := .c # C program

# Include
INCDIR += -I $(WORK_PATH)/include
INCDIR += -I $(WORK_PATH)/src/utils
INCDIR += -I $(WORK_PATH)/open_source/lz4-1.9.4/lib
INCDIR += -I ${WORK_PATH}/../uadk/include/
INCDIR += -I ${WORK_PATH}/../kae_build/head/

# Include Libs.
LIBDIR += -L/usr/local/lib
LIBDIR += -L/usr/lib64
LIBDIR += -L/usr/lib
LIBDIR += -L$(WORK_PATH)/../kae_build/lib/
LIBS := -pthread -Wl,-rpath,/usr/local/lib -lwd -lwd_comp
LIBS += -lc_nonshared

# The flags
CFLAGS    := -Wall -Werror -fstack-protector-all -fPIC -D_GNU_SOURCE -shared -O2 -march=armv8.2-a+crypto
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

all : $(TARGET) libkaelz4.a symlinks

symlinks : $(TARGET)
	@echo Creating symbolic links
	$(SILENCE) $(LN) $(TARGET) $(SOFTLINK)
	$(SILENCE) $(LN) $(TARGET) $(SOFTLINK).0

# Rules for creating the dependency files (.d).
%.d : %.c
	$(CC) -MM -MD $(CFLAGS)  $<

# Rules for producing the objects.
objs : $(OBJS)
%.o : %.c
	@echo compiling $(notdir $<)
	$(SILENCE) $(CC) -c $(CFLAGS) $(INCDIR) $(LDFLAGS) -o $@ $<

libkaelz4.a: $(OBJS)
	@echo compling static library
	@ar rcs $@ $^

$(TARGET): $(OBJS)
	@echo Linking $@
	$(SILENCE) $(CC) $(CFLAGS) $(INCDIR) -o ./$(TARGET) $(OBJS) $(LDFLAGS)

rebuild: clean all

clean :
	@-$(RM) *.d *.a *.so *.symbol $(TARGET)
	@-$(RM) $(SOFTLINK) $(SOFTLINK).0
	@-$(RM)
	@find ${WORK_PATH} -name '*.o' -exec $(RM) {} \;
	@echo all clean

install :
	mkdir -p $(ENGINE_INSTALL_PATH)/include
	mkdir -p $(ENGINE_INSTALL_PATH)/lib
	install -m 755 libkaelz4.a $(ENGINE_INSTALL_PATH)/lib
	install -m 755 $(TARGET) $(ENGINE_INSTALL_PATH)/lib
	$(LN) $(ENGINE_INSTALL_PATH)/lib/$(TARGET)  $(ENGINE_INSTALL_PATH)/lib/$(SOFTLINK)
	$(LN) $(ENGINE_INSTALL_PATH)/lib/$(TARGET)  $(ENGINE_INSTALL_PATH)/lib/$(SOFTLINK).0
	install -m 755 $(WORK_PATH)/include/kaelz4.h $(ENGINE_INSTALL_PATH)/include
	install -m 755 $(WORK_PATH)/include/kaelz4_dev.h $(ENGINE_INSTALL_PATH)/include
	install -m 755 $(WORK_PATH)/src/utils/kaelz4_log.h $(ENGINE_INSTALL_PATH)/include
uninstall :
	$(RM) $(ENGINE_INSTALL_PATH)/lib/$(SOFTLINK)
	$(RM) $(ENGINE_INSTALL_PATH)/lib/$(SOFTLINK).0
	$(RM) $(ENGINE_INSTALL_PATH)/lib/$(TARGET)
	$(RM) $(ENGINE_INSTALL_PATH)/lib/libkaelz4.a
	$(RM) $(ENGINE_INSTALL_PATH)/include/kaelz4.h
	$(RM) $(ENGINE_INSTALL_PATH)/include/kaelz4_dev.h
	$(RM) $(ENGINE_INSTALL_PATH)/include/kaelz4_log.h
	$(RM) $(ENGINE_INSTALL_PATH)/include/lz4.h
	$(RM) $(ENGINE_INSTALL_PATH)/include/lz4frame.h