KERNEL_VERSION_BY_BUILDENV :=`uname -r`
KERNEL_PATH := /lib/modules/$(KERNEL_VERSION_BY_BUILDENV)/build
# KSP :=	$(shell if test -d /lib/modules/$(KERNEL_VERSION_BY_BUILDENV)/source; then  \
#                     echo /lib/modules/$(KERNEL_VERSION_BY_BUILDENV)/source; \
# 	        else  \
#                     echo /lib/modules/$(KERNEL_VERSION_BY_BUILDENV)/build;  \
#                 fi)

obj-m += uacce/
obj-m += hisilicon/

DIRS := $(shell find . -maxdepth 3 -type d)
TARGET = $(foreach dir,$(DIRS),$(wildcard \
	$(dir)/*.o) $(dir)/*.ko $(dir)/*.tmp_versions $(dir)/*.depend $(dir)/*.mod.c $(dir)/*.order $(dir)/*.symvers)

CONFIG_FLAGS = CONFIG_CC_STACKPROTECTOR_STRONG=y \
		CONFIG_UACCE=m \
		CONFIG_CRYPTO_QM_UACCE=m \
		CONFIG_CRYPTO_DEV_HISI_SGL=m \
		CONFIG_CRYPTO_DEV_HISI_QM=m \
		CONFIG_CRYPTO_DEV_HISI_ZIP=m \
		CONFIG_CRYPTO_DEV_HISI_HPRE=m \
		CONFIG_CRYPTO_DEV_HISI_SEC2=m \
		CONFIG_CRYPTO_DEV_HISI_TRNG=m

ifeq ($(ENABLE_MIGRATION), y)
CONFIG_FLAGS += CONFIG_HISI_ACC_VFIO_PCI=m
else
CONFIG_FLAGS += CONFIG_HISI_ACC_VFIO_PCI=n
endif

default: 
	$(MAKE) -C $(KERNEL_PATH) M=$(shell pwd) modules $(CONFIG_FLAGS)

#copy:
#	cp -f $(shell pwd)/include_linux/uacce.h $(KSP)/include/linux
#	cp -f $(shell pwd)/include_uapi_linux/uacce.h $(KSP)/include/uapi/linux

install:
	$(shell mkdir -p /lib/modules/$(KERNEL_VERSION_BY_BUILDENV)/extra)
	$(shell find . -name "*.ko" -exec cp -f {} /lib/modules/$(KERNEL_VERSION_BY_BUILDENV)/extra \;)
	depmod -a
	$(shell if test -e /etc/modprobe.d/10-unsupported-modules.conf; then \
		sed -i "s/^allow_unsupported_modules.*/allow_unsupported_modules 1/" /etc/modprobe.d/10-unsupported-modules.conf; \
	fi)
	-modprobe uacce
	-modprobe hisi_qm
	-modprobe hisi_sec2 uacce_mode=1 pf_q_num=256
	-modprobe hisi_hpre uacce_mode=1 pf_q_num=256
	-modprobe hisi_zip  uacce_mode=1 pf_q_num=256
	$(shell if [ "$(ENABLE_MIGRATION)" = "y" ]; then \
		modprobe hisi_acc_vfio_pci; \
	fi)
	-echo "options hisi_sec2 uacce_mode=1 pf_q_num=256" > /etc/modprobe.d/hisi_sec2.conf
	-echo "options hisi_hpre uacce_mode=1 pf_q_num=256" > /etc/modprobe.d/hisi_hpre.conf
	-echo "options hisi_zip  uacce_mode=1 pf_q_num=256" > /etc/modprobe.d/hisi_zip.conf
	dracut -f

TARGET_MODULES := uacce.ko* hisi_qm.ko* hisi_sec2.ko* hisi_hpre.ko* hisi_zip.ko*

delete-modules:
	@echo "[WARN] This will delete the following files:"
	$(foreach mod, $(TARGET_MODULES), find /lib/modules/ -type f -name "$(mod)" -print ;)
	@echo -n "[WARN] Are you sure? (y/N) " && read ans && [ $${ans:-N} = y ]
	$(foreach mod, $(TARGET_MODULES), find /lib/modules/ -type f -name "$(mod)" -delete ;)
	@echo "[INFO] Modules deleted. Run 'sudo depmod -a' to update dependencies."

check:
	@echo "[WARN] The following files are accelerator driver:"
	@for mod in $(TARGET_MODULES); do \
		find /lib/modules/ -type f -name "$$mod" -print; \
	done

uninstall:
	$(shell if [ "$(ENABLE_MIGRATION)" = "y" ]; then \
		modprobe -r hisi_acc_vfio_pci; \
	fi)
	modprobe -r hisi_zip
	modprobe -r hisi_hpre
	modprobe -r hisi_sec2
	modprobe -r hisi_qm
	modprobe -r uacce
	dracut -f
	rm -rf /lib/modules/$(KERNEL_VERSION_BY_BUILDENV)/extra/uacce.ko
	rm -rf /lib/modules/$(KERNEL_VERSION_BY_BUILDENV)/extra/hisi_qm.ko
	rm -rf /lib/modules/$(KERNEL_VERSION_BY_BUILDENV)/extra/hisi_sec2.ko
	rm -rf /lib/modules/$(KERNEL_VERSION_BY_BUILDENV)/extra/hisi_hpre.ko
	rm -rf /lib/modules/$(KERNEL_VERSION_BY_BUILDENV)/extra/hisi_zip.ko
	$(shell if [ "$(ENABLE_MIGRATION)" = "y" ]; then \
		rm -rf /lib/modules/$(KERNEL_VERSION_BY_BUILDENV)/extra/hisi_acc_vfio_pci.ko; \
	fi)
	rm -rf /etc/modprobe.d/hisi_sec2.conf
	rm -rf /etc/modprobe.d/hisi_hpre.conf
	rm -rf /etc/modprobe.d/hisi_zip.conf
	depmod -a
nosva:
	$(shell mkdir -p /lib/modules/$(KERNEL_VERSION_BY_BUILDENV)/extra)
	$(shell find . -name "*.ko" -exec cp -f {} /lib/modules/$(KERNEL_VERSION_BY_BUILDENV)/extra \;)
	depmod -a
	$(shell if test -e /etc/modprobe.d/10-unsupported-modules.conf; then \
			sed -i "s/^allow_unsupported_modules.*/allow_unsupported_modules 1/" /etc/modprobe.d/10-unsupported-modules.conf; \
	fi)
	-modprobe uacce
	-modprobe hisi_qm
	-modprobe hisi_sec2 uacce_mode=2 pf_q_num=256
	-modprobe hisi_hpre uacce_mode=2 pf_q_num=256
	-modprobe hisi_zip  uacce_mode=2 pf_q_num=256
	$(shell if [ "$(ENABLE_MIGRATION)" = "y" ]; then \
		modprobe hisi_acc_vfio_pci; \
	fi)
	-echo "options hisi_sec2 uacce_mode=2 pf_q_num=256" > /etc/modprobe.d/hisi_sec2.conf
	-echo "options hisi_hpre uacce_mode=2 pf_q_num=256" > /etc/modprobe.d/hisi_hpre.conf
	-echo "options hisi_zip  uacce_mode=2 pf_q_num=256" > /etc/modprobe.d/hisi_zip.conf
	dracut -f
clean:
	rm -rf $(TARGET) 
