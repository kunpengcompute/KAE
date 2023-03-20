KERNEL_PATH := /lib/modules/`uname -r`/build
KSP :=	$(shell if test -d /lib/modules/`uname -r`/source; then  \
                    echo /lib/modules/`uname -r`/source; \
	        else  \
                    echo /lib/modules/`uname -r`/build;  \
                fi)

obj-m += uacce/
obj-m += hisilicon/

DIRS := $(shell find . -maxdepth 3 -type d)
TARGET = $(foreach dir,$(DIRS),$(wildcard \
	$(dir)/*.o) $(dir)/*.ko $(dir)/*.tmp_versions $(dir)/*.depend $(dir)/*.mod.c $(dir)/*.order $(dir)/*.symvers)

defaul:
	$(MAKE) -C $(KERNEL_PATH) M=$(shell pwd) modules \
		CONFIG_CC_STACKPROTECTOR_STRONG=y \
		CONFIG_UACCE=m \
		CONFIG_CRYPTO_QM_UACCE=m \
		CONFIG_CRYPTO_DEV_HISI_SGL=m \
		CONFIG_CRYPTO_DEV_HISI_QM=m \
		CONFIG_CRYPTO_DEV_HISI_ZIP=m \
		CONFIG_CRYPTO_DEV_HISI_HPRE=m \
		CONFIG_CRYPTO_DEV_HISI_SEC2=m \
		CONFIG_CRYPTO_DEV_HISI_RDE=m

install:
	$(shell mkdir -p /lib/modules/`uname -r`/extra)
	$(shell find . -name "*.ko" -exec cp -f {} /lib/modules/`uname -r`/extra \;)
	$(shell if [ ! -f /etc/modprobe.d/hisi_hpre.conf ]; then cp -rf conf/hisi_hpre.conf /etc/modprobe.d/; fi;)
	$(shell if [ ! -f /etc/modprobe.d/hisi_sec2.conf ]; then cp -rf conf/hisi_sec2.conf /etc/modprobe.d/; fi;)
	$(shell if [ ! -f /etc/modprobe.d/hisi_rde.conf ]; then cp -rf conf/hisi_rde.conf /etc/modprobe.d/; fi;)
	$(shell if [ ! -f /etc/modprobe.d/hisi_zip.conf ]; then cp -rf conf/hisi_zip.conf /etc/modprobe.d/; fi;)
	depmod -a

uninstall:
	rm -rf /lib/modules/`uname -r`/extra/uacce.ko
	rm -rf /lib/modules/`uname -r`/extra/hisi_qm.ko
	rm -rf /lib/modules/`uname -r`/extra/hisi_sec2.ko
	rm -rf /lib/modules/`uname -r`/extra/hisi_hpre.ko
	rm -rf /lib/modules/`uname -r`/extra/hisi_zip.ko
	rm -rf /lib/modules/`uname -r`/extra/hisi_rde.ko
	rm -rf /etc/modprobe.d/hisi_sec2.conf
	rm -rf /etc/modprobe.d/hisi_hpre.conf
	rm -rf /etc/modprobe.d/hisi_rde.conf
	rm -rf /etc/modprobe.d/hisi_zip.conf
	depmod -a

clean:
	rm -f $(KSP)/include/linux/uacce.h
	rm -f $(KSP)/include/uapi/linux/uacce.h
	rm -rf $(TARGET) 
