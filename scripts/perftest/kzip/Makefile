# 编译器
CC = gcc
CFLAGS = -g -O3 -fstack-protector-all -Wall -Werror
LDFLAGS = -lz -lnuma -lrt -lpthread

# 目标可执行文件
TARGET = kzip

INCLD = -I alg/common -I include

# 主程序源文件
MAIN_SRC = $(wildcard framework/*.c)
MAIN_SRC += $(wildcard alg/common/*.c)
#MAIN_SRC += $(wildcard scene_test_functions/*.c)

# 模块选择（默认编译所有模块）
MODULES ?= $(notdir $(wildcard alg/kae))
MODULES_ALL ?= $(notdir $(wildcard alg/*))

MODULE_DEFINES := $(foreach mod,$(MODULES),-DCONFIG_$(shell echo $(mod) | tr '[:lower:]' '[:upper:]'))
CFLAGS += $(MODULE_DEFINES)
CFLAGS += $(INCLD)

# 定义每个模块需要的链接库
MODULE_LIBS_kaelz4 := -L/usr/local/kaelz4/lib -llz4 -lkaelz4
# MODULE_LIBS_kaezlib := -L/usr/local/kaezip/lib -lkaezip

# 收集所有模块的链接库
MODULE_LDLIBS := $(foreach mod,$(MODULES),$(MODULE_LIBS_$(mod)))

# 添加到全局链接选项
LDFLAGS += $(MODULE_LDLIBS)

# 递归编译模块（子 Makefile 负责生成 OBJS）
MAIN_SRC += $(foreach mod,$(MODULES), $(wildcard alg/$(mod)/*.c))
MAIN_OBJ = $(MAIN_SRC:.c=.o)

ALL_SRC += $(foreach mod,$(MODULES_ALL), $(wildcard alg/$(mod)/*.c))
ALL_OBJS = $(ALL_SRC:.c=.o)

# 最终所有目标文件
OBJS = $(MAIN_OBJ)

# 默认目标
all: $(TARGET)

# 链接生成可执行文件
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

# 主程序编译
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理（递归清理所有模块）
clean:
	rm -f $(OBJS) $(TARGET) $(ALL_OBJS)

# 打印帮助信息
help:
	@echo "Usage:"
	@echo "  make              # 编译所有模块"
	@echo "  make MODULES=\"module1 module2\"  # 选择性编译模块"
	@echo "  make clean        # 清理所有生成的文件"

.PHONY: all clean help FORCE
