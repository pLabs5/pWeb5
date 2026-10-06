# pWeb5 payload dispatcher.
#
# Builds a payload .elf the same way the SDK's own samples do, so elfldr on
# :9021 can load it exactly like any other plugin.
#
#   PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk make
#
# The site origin is baked in because a payload has no page to be relative
# to; override with CLOUD_BASE=... if the deployment moves.

ifndef PS5_PAYLOAD_SDK
    $(error PS5_PAYLOAD_SDK is undefined - point it at your ps5-payload-sdk checkout)
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

CLOUD_BASE ?= https://pweb5.pages.dev
LOCAL_ROOT ?= /data/autoldr

ELF := dispatcher.elf

CFLAGS := -Wall -Wextra -Werror -g -O2 \
          -DCLOUD_BASE='"$(CLOUD_BASE)"' \
          -DLOCAL_ROOT='"$(LOCAL_ROOT)"' \
          -lkernel -lSceNet -lSceSsl -lSceHttp2

# prospero-clang resolves clang and lld through llvm-config's --bindir. Some
# layouts ship those in separate packages, so that bindir may hold neither.
# llvm-shim.sh finds a working one (and assembles it if need be).
LLVM_CONFIG ?= $(shell bash llvm-shim.sh)
export LLVM_CONFIG

all: $(ELF)

$(ELF): main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(ELF)

.PHONY: all clean
