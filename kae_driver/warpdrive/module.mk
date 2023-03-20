LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := warpdrive

warpdrive_get_install_lib_dir = $(call get-installed-usr-path,$(PRIVATE_INSTALL_DIR),lib)
warpdrive_get_install_bin_dir = $(call get-installed-usr-path,$(PRIVATE_INSTALL_DIR),sbin)
warpdrive_get_src_dir = $(abspath $(PRIVATE_PATH))

warpdriver_make_cmd = $(make-cmd) $1 $(if $(print_cmd),,1>/dev/null)

define warpdrive_cmd_configure
	$(call update_source_map_if_needed,$(PRIVATE_BUILD_DIR),$(PRIVATE_PATH))
endef

define warpdrive_cmd_build
	@mkdir -p $(PRIVATE_BUILD_DIR)
	@mkdir -p $(PRIVATE_PATH)/m4
	cd $(PRIVATE_BUILD_DIR);\
	autoreconf -vfi  $(call warpdrive_get_src_dir);\
	CC="$(TARGET_COMPILER_PREFIX)gcc" \
	LD=$(TARGET_COMPILER_PREFIX)ld \
	$(if $(DEVEL_DEBUG),CFLAGS="-fsanitize=address -fno-omit-frame-pointer -ggdb") \
	$(call warpdrive_get_src_dir)/configure --host aarch64-linux-gnu --target aarch64-linux-gnu \
	--with-openssl_dir=$(abspath $(PRIVATE_PATH))/../openssl;\
	$(call warpdriver_make_cmd)
endef

define warpdrive_cmd_install
	@mkdir -p $(call warpdrive_get_install_lib_dir)
	@mkdir -p $(call warpdrive_get_install_bin_dir)
	cp -rf -P $(PRIVATE_BUILD_DIR)/.libs/libwd* $(call warpdrive_get_install_lib_dir)
	cp -rf $(PRIVATE_BUILD_DIR)/test/hisi_zip_test/test_hisi_zip $(call warpdrive_get_install_bin_dir)
	cp -rf $(PRIVATE_BUILD_DIR)/test/hisi_zip_test/test_hisi_zlib $(call warpdrive_get_install_bin_dir)
	cp -rf $(PRIVATE_BUILD_DIR)/test/hisi_zip_test/wd_zip_test $(call warpdrive_get_install_bin_dir)
	cp -rf $(PRIVATE_BUILD_DIR)/test/hisi_hpre_test/test_hisi_hpre $(call warpdrive_get_install_bin_dir)
	cp -rf $(PRIVATE_BUILD_DIR)/test/hisi_hpre_test/hpre_test_tools $(call warpdrive_get_install_bin_dir)
	cp -rf $(PRIVATE_BUILD_DIR)/test/hisi_trng_test/test_hisi_trngu $(call warpdrive_get_install_bin_dir)
	cp -rf $(PRIVATE_BUILD_DIR)/test/hisi_trng_test/test_hisi_trngk $(call warpdrive_get_install_bin_dir)
	cp -rf $(PRIVATE_BUILD_DIR)/test/test_mm/test_wd_mem $(call warpdrive_get_install_bin_dir)
	cp -rf $(PRIVATE_BUILD_DIR)/test/bmm_test/bmm_test $(call warpdrive_get_install_bin_dir)
endef

define warpdrive_cmd_clean
	@ rm -f $(PRIVATE_BUILD_DIR)
	@ rm -f $(PRIVATE_INSTALL_DIR)
endef

LOCAL_DEF_CMD_CONFIGURE := warpdrive_cmd_configure
LOCAL_DEF_CMD_BUILD := warpdrive_cmd_build
LOCAL_DEF_CMD_INSTALL := warpdrive_cmd_install
LOCAL_DEF_CMD_CLEAN := warpdrive_cmd_clean

include $(BUILD_SYSTEM)/opensource_commom.mk
