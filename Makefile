export ROOT			?= $(CURDIR)/../../..
export V 			?= 0
export TA_CPU 			?= cortex-a53
#export TA_CROSS_COMPILE 	?= $(ROOT)/toolchains/aarch32/bin/arm-linux-gnueabihf-
export TA_DEV_KIT_DIR 		?= /storage/ge34yuf/OPTEE/zcu102-2018.3/build/tmp/deploy/images/zcu102-zynqmp/optee/export-ta_arm64
#export TA_DEV_KIT_DIR 		?= /storage/ge34yuf/OPTEE_2019.1/zcu102-2019.1/build/tmp/deploy/images/zcu102-zynqmp/optee/export-ta_arm64
export CFG_TEE_TA_LOG_LEVEL 	?= 3

#CROSS_COMPILE			?= /usr/bin/ccache $(TA_CROSS_COMPILE)

BINARY=bc50d971-d4c9-42c4-82cb-123456789123

O ?= out
WOLF_ROOT := lib/external/wolfssl

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

clean: clean_stripped_file
.PHONY: clean_stripped_file
clean_stripped_file:
	rm -f $(BINARY).stripped.elf


TA_FILE="bc50d971-d4c9-42c4-82cb-123456789123.ta"
help:
	@echo "Mount alias on device / QEMU:" && \
	echo "\n   alias setup_ftpm='mkdir -p /host && mount -t 9p -o trans=virtio host /host && cd /lib/optee_armtz && ln -sf /host/ms-tpm-20-ref/out/$(TA_FILE) $(TA_FILE)'" && \
	echo "\n   alias ftpm_mod='cd /lib && ln -s /host/linux/lib/modules . && modprobe tpm_ftpm_optee'" && \
	echo "\n   alias tss='cd /lib && cp /host/ibmtpm20tss/utils/libibmtss* .'" && \
	echo "\n   alias tpm_rand='cd /host/ibmtpm20tss/utils && ./getrandom -by 8'" && \
	echo "\n   alias ftpm='setup_ftpm && ftpm_mod && tss && tpm_rand'"

