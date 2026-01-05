# 编译器设置
CC := gcc
CFLAGS := -g -Wall -O2
LDFLAGS := -Wl,--as-needed

# 目录设置
KAEDIR := /usr/local/kaezstd
INCDIR := -I$(KAEDIR)/include -I.
LIBDIR := -L$(KAEDIR)/lib

# 库依赖设置
KAE_LIBS := -lkaezstd -lwd_comp -lwd -lzstd
SYS_LIBS := -lzstd

# 目标设置
TARGETS := kaezstd_perf zstd_perf
SRC := kaezstd_perf.c

# 使用-v=1查看详细构建信息
ifeq ($(v),1)
  Q :=
else
  Q := @
endif

# 默认目标
all: $(TARGETS)

# KA-EZSTD版本：使用KA-EZSTD库并设置rpath
kaezstd_perf: $(SRC)
	@echo "Building $@ (with KA-EZSTD)..."
	$(Q)$(CC) $(CFLAGS) $(INCDIR) -DUSE_KAEZSTD -o $@ $< \
		$(LIBDIR) -Wl,-rpath,$(KAEDIR)/lib $(KAE_LIBS)

# 系统ZSTD版本：使用系统zstd库
zstd_perf: $(SRC)
	@echo "Building $@ (with system ZSTD)..."
	$(Q)$(CC) $(CFLAGS) -Wl,-rpath,/usr/local/lib $(INCDIR) -o $@ $< $(SYS_LIBS)

# 检查KA-EZSTD库是否存在
check-kae:
	@echo "Checking KA-EZSTD installation..."
	@if [ ! -d "$(KAEDIR)" ]; then \
		echo "Error: KA-EZSTD not found at $(KAEDIR)"; \
		echo "Please install it first: make install-kae"; \
		exit 1; \
	fi
	@echo "KA-EZSTD found at $(KAEDIR)"

# 安装KA-EZSTD的模拟目标（实际需要您手动安装）
install-kae:
	@echo "Please install KA-EZSTD manually:"
	@echo "1. Download from the appropriate source"
	@echo "2. Build and install to $(KAEDIR)"
	@echo "3. Run 'make check-kae' to verify"

# 清理
clean:
	-rm -f $(TARGETS) *.o

# 显示帮助
help:
	@echo "可用目标:"
	@echo "  make all               - 构建所有目标 (默认)"
	@echo "  make kaezstd_perf      - 构建KA-EZSTD版本"
	@echo "  make zstd_perf         - 构建系统ZSTD版本"
	@echo "  make check-kae         - 检查KA-EZSTD安装"
	@echo "  make clean             - 清理构建文件"
	@echo "  make help              - 显示此帮助"
	@echo ""
	@echo "构建选项:"
	@echo "  v=1                    - 显示详细构建信息"
	@echo "                         例如: make all v=1"

# 测试运行目标
test: $(TARGETS)
	@echo "=== 测试KA-EZSTD版本 ==="
	@-./kaezstd_perf --help 2>/dev/null || echo "运行失败，可能需要设置LD_LIBRARY_PATH"
	@echo ""
	@echo "=== 测试系统ZSTD版本 ==="
	@-./zstd_perf --help 2>/dev/null || echo "运行失败"

.PHONY: all clean help check-kae install-kae test