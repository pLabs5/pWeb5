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
          -DDISPATCHER_USE_CURL \
          -Icore -Ithird_party/curl/include

# The Pages build has no SDK, so payloads/dispatcher.elf has to be committed
# rather than produced at deploy time. That only stays honest if the build is
# reproducible, and lld's default GNU build-id is a fresh random UUID per link -
# the only reason two builds of identical source differed. Dropping it makes
# "rebuild and diff the committed binary" a real check.
LDFLAGS := -Wl,--build-id=none
CURL_LIBS := third_party/curl/lib/libcurl.a \
             third_party/curl/lib/libmbedtls.a \
             third_party/curl/lib/libmbedx509.a \
             third_party/curl/lib/libmbedcrypto.a
PAYLOAD_LIBS := -lkernel -lpthread

SRCS := main.c core/dns.c core/stub_cfg.c core/bundled_ca.c

# prospero-clang resolves clang and lld through llvm-config's --bindir. Some
# layouts ship those in separate packages, so that bindir may hold neither.
# llvm-shim.sh finds a working one (and assembles it if need be).
LLVM_CONFIG ?= $(shell bash llvm-shim.sh)
export LLVM_CONFIG

all: $(ELF)

core/bundled_ca.c: third_party/cacert.pem tools/embed.c
	$(HOSTCC) $(HOSTCFLAGS) -o build/embed tools/embed.c
	build/embed --out $@ --dec kCaPem=$<:kCaPemSize

$(ELF): $(SRCS) $(CURL_LIBS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS) $(CURL_LIBS) $(PAYLOAD_LIBS)

clean:
	rm -f $(ELF)

.PHONY: all clean
