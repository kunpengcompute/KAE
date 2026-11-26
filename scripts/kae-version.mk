# Variables only: including this file must not change make's default target.
KAE_VERSION_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
KAE_VERSION_FILE := $(abspath $(KAE_VERSION_DIR)/../VERSION)
KAE_VERSION := $(shell sh "$(KAE_VERSION_DIR)/kae-version.sh")
ifeq ($(KAE_VERSION),)
$(error Cannot read a valid KAE release from $(KAE_VERSION_FILE))
endif
KAE_VERSION_CPPFLAGS = -DKAE_VERSION_STRING=\"$(KAE_VERSION)\"
KAE_VERSION_DEPS = $(KAE_VERSION_FILE) $(KAE_VERSION_DIR)/kae-version.sh $(KAE_VERSION_DIR)/kae-version.mk
