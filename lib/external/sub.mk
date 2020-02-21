WOLF_SSL_FLAGS = -DCTYPE_USER \
		 -DNO_FILESYSTEM \
		 -DNO_WOLFSSL_CLIENT \
		 -DNO_WOLFSSL_SERVER \
		 -DOPENSSL_EXTRA \
		 -DSINGLE_THREADED \
		 -DSTRING_USER \
		 -DTIME_OVERRIDES \
		 -DWOLFSSL_USER_SETTINGS \
		 -DWOLFSSL_SHA3 \
		 -DWOLFSSL_XILINX_CRYPT

# Wolfcrypt has multiple unused functions, unfortunately the OPTEE build system
# can only turn off compiler flags for files in the same directory as the
# sub.mk file. It is not possible to place sub.mk files in the git submodules
# without creating a new fork of each submodule repo. To avoid spurious
# warnings these warnings are disabled here globally.

WOLF_WARNING_SUPPRESS = -Wno-unused-function

cflags-y += $(WOLF_SSL_FLAGS) $(WOLF_WARNING_SUPPRESS)

global-incdirs-y += wolfssl


libdirs += /storage/ge34yuf/MLE_Download/optee-for-zuplus_src_v20191213-rc/ps/petalinux/build/xsdk/optee_os_bsp/psu_cortexa53_0/lib
libnames += xilfpga xilsecure xilskey xilisf xil utils

srcs-y += wolfssl/wolfcrypt/src/aes.c
srcs-y += wolfssl/wolfcrypt/src/asn.c
srcs-y += wolfssl/wolfcrypt/src/ecc.c
srcs-y += wolfssl/wolfcrypt/src/integer.c
srcs-y += wolfssl/wolfcrypt/src/memory.c
srcs-y += wolfssl/wolfcrypt/src/sha.c
srcs-y += wolfssl/wolfcrypt/src/sha3.c
srcs-y += wolfssl/wolfcrypt/src/sha256.c
srcs-y += wolfssl/wolfcrypt/src/sha512.c
srcs-y += wolfssl/wolfcrypt/src/tfm.c
srcs-y += wolfssl/wolfcrypt/src/wolfmath.c
srcs-y += wolfssl/wolfcrypt/src/des3.c
srcs-y += wolfssl/wolfcrypt/src/random.c
srcs-y += wolfssl/wolfcrypt/src/port/xilinx/xil-sha3.c
srcs-y += wolfssl/wolfcrypt/src/port/xilinx/xil-aesgcm.c
