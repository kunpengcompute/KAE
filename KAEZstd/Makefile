#
# Date:   2021/6/15

# Description:
# compile for KAEZSTD
#
# Usage:
#   $ make           compile and link the program.
#   $ make rebuild   rebuild the program. The same as make clean && make all.
#   $ make clean     clean the objective, dependent and executable files.
#   $ make install   copy to the system directory.
#   $ make uninstall clean the executable file from the system directory.
#==============================================================================

WORK_PATH := .
ENGINE_INSTALL_PATH := /usr/local/kaezstd

CC=gcc

LIBNAME := libkaezstd.so
VERSION = 0.0.1
TARGET = ${LIBNAME}.${VERSION}
SOFTLINK = libkaezstd.so

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
INCDIR += -I $(WORK_PATH)/open_source/zstd/lib
INCDIR += -I $(WORK_PATH)/open_source/zstd/lib/common
INCDIR += -I $(WORK_PATH)/open_source/zstd/lib/compress

# Include Libs.
LIBDIR += -L/usr/local/lib
LIBDIR += -L/usr/lib64
LIBDIR += -L/usr/lib
LIBS := -pthread -Wl,-rpath,/usr/local/lib -lwd -lwd_comp
LIBS += -lc_nonshared

# The flags
CFLAGS    := -Wall -Werror -fstack-protector-all -fPIC -D_GNU_SOURCE -DBUILD_KAEZSTD -shared
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

all : $(TARGET) libkaezstd.a

# Rules for creating the dependency files (.d).
%.d : %.c
	$(CC) -MM -MD $(CFLAGS)  $<

# Rules for producing the objects.
objs : $(OBJS)
%.o : %.c
	@echo compiling $(notdir $<)
	$(SILENCE) $(CC) -c $(CFLAGS) $(INCDIR) $(LDFLAGS) -o $@ $<

libkaezstd.a: $(OBJS)
	@echo compling static library
	@ar rcs $@ $^

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
	install -m 755 libkaezstd.a $(ENGINE_INSTALL_PATH)/lib
	install -m 755 $(TARGET) $(ENGINE_INSTALL_PATH)/lib
	$(LN) $(ENGINE_INSTALL_PATH)/lib/$(TARGET)  $(ENGINE_INSTALL_PATH)/lib/$(SOFTLINK)
	$(LN) $(ENGINE_INSTALL_PATH)/lib/$(TARGET)  $(ENGINE_INSTALL_PATH)/lib/$(SOFTLINK).0
	install -m 755 $(WORK_PATH)/include/kaezstd.h $(ENGINE_INSTALL_PATH)/include
uninstall :
	$(RM) $(ENGINE_INSTALL_PATH)/lib/$(SOFTLINK)
	$(RM) $(ENGINE_INSTALL_PATH)/lib/$(SOFTLINK).0
	$(RM) $(ENGINE_INSTALL_PATH)/lib/$(TARGET)
	$(RM) $(ENGINE_INSTALL_PATH)/lib/libkaezstd.a
	$(RM) $(ENGINE_INSTALL_PATH)/include/kaezstd.h
