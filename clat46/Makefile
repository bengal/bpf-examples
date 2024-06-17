# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := clat46
BPF_TARGETS    := clat46_kern
BPF_SKEL_OBJ := clat46_kern.o

#LDLIBS     += -pthread
USER_LIBS = -lmnl
EXTRA_DEPS += clat46.h

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk
