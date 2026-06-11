# ----------------------------------------------------------------------------
# piqaso_sdk — OP-TEE sub.mk
#
# Drop this file (or include it) from your TA's sub.mk / Makefile.
#
# Expected variables (set before including this file or in your TA Makefile):
#   PIQASO_SDK_DIR   — absolute path to the piqaso_sdk root
#   WOLFSSL_DIR      — absolute path to the WolfSSL source/install root
#                      (must have been built with OPTEE target)
# ----------------------------------------------------------------------------

# SDK sources
srcs-y += $(PIQASO_SDK_DIR)/src/mldsa.c
srcs-y += $(PIQASO_SDK_DIR)/src/mlkem.c
srcs-y += $(PIQASO_SDK_DIR)/src/lms.c
srcs-y += $(PIQASO_SDK_DIR)/src/xmss.c
srcs-y += $(PIQASO_SDK_DIR)/src/aes.c

# SDK headers
global-incdirs-y += $(PIQASO_SDK_DIR)/include

# WolfSSL headers
global-incdirs-y += $(WOLFSSL_DIR)/include

# Project root — required so wolfssl/wolfcrypt/settings.h can find user_settings.h
global-incdirs-y += $(PIQASO_SDK_DIR)

# WolfSSL static archive
libdirs-y  += $(WOLFSSL_DIR)/lib
libnames-y += wolfssl

# Trigger user_settings.h (all feature flags live there)
cflags-y += -DOPTEE
cflags-y += -DWOLFSSL_USER_SETTINGS
