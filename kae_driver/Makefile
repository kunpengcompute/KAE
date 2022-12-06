KERNEL_PATH := /lib/modules/5.10*/build
KSP :=	$(shell if test -d /lib/modules/5.10*/source; then  \
                    echo /lib/modules/5.10*/source; \
	        else  \
                    echo /lib/modules/5.10*/build;  \
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
		CONFIG_CRYPTO_DEV_HISI_TRNG=m
#copy:
#	cp -f $(shell pwd)/include_linux/uacce.h $(KSP)/include/linux
#	cp -f $(shell pwd)/include_uapi_linux/uacce.h $(KSP)/include/uapi/linux

install:
	$(shell mkdir -p /lib/modules/5.10*/extra)
	$(shell find . -name "*.ko" -exec cp -f {} /lib/modules/5.10*/extra \;)
	depmod -a
	$(shell if test -e /etc/modprobe.d/10-unsupported-modules.conf; then \
		sed -i "s/^allow_unsupported_modules.*/allow_unsupported_modules 1/" /etc/modprobe.d/10-unsupported-modules.conf; \
	fi)
	-modprobe uacce
	-modprobe hisi_qm
	-modprobe hisi_sec2 uacce_mode=2 enable_sm4_ctr=1 pf_q_num=256
	-modprobe hisi_hpre uacce_mode=2 pf_q_num=256
	-modprobe hisi_zip  uacce_mode=2 pf_q_num=256
	-modprobe hisi_trng_v2  uacce_mode=2 pf_q_num=256
	-echo "options hisi_sec2 uacce_mode=2 enable_sm4_ctr=1 pf_q_num=256" > /etc/modprobe.d/hisi_sec2.conf
	-echo "options hisi_hpre uacce_mode=2 pf_q_num=256" > /etc/modprobe.d/hisi_hpre.conf
	-echo "options hisi_zip  uacce_mode=2 pf_q_num=256" > /etc/modprobe.d/hisi_zip.conf
	-echo "options hisi_trng_v2 uacce_mode=2 pf_q_num=256" > /etc/modprobe.d/hisi_trng_v2.conf
uninstall:
	modprobe -r hisi_zip
	modprobe -r hisi_hpre
	modprobe -r hisi_sec2
	modprobe -r hisi_trng_v2
	modprobe -r hisi_qm
	modprobe -r uacce
	rm -rf /lib/modules/5.10*/extra/uacce.ko
	rm -rf /lib/modules/5.10*/extra/hisi_qm.ko
	rm -rf /lib/modules/5.10*/extra/hisi_sec2.ko
	rm -rf /lib/modules/5.10*/extra/hisi_hpre.ko
	rm -rf /lib/modules/5.10*/extra/hisi_trng_v2.ko
	rm -rf /lib/modules/5.10*/extra/hisi_zip.ko
	rm -rf /etc/modprobe.d/hisi_sec2.conf
	rm -rf /etc/modprobe.d/hisi_hpre.conf
	rm -rf /etc/modprobe.d/hisi_zip.conf
	rm -rf /etc/modprobe.d/hisi_trng_v2.conf
	depmod -a

clean:
	rm -rf $(TARGET) 
