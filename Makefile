# Top-level pWeb5 Makefile. dist/ is assembled by tools/build/build (compiled
# from tools/build/build.c), the fake DNS responder by the fakedns target, and
# the dispatcher has its own Makefile under dispatcher/.

ifndef PS5iP
PS5iP := $(shell echo)
endif

CC ?= cc

# `make build` compiles the C build tool (which replaces tools/build.sh) and
# assembles dist/ with it. Set PS5_PAYLOAD_SDK to also rebuild
# payloads/dispatcher.elf from source.
build: tools/build/build
	./tools/build/build

tools/build/build: tools/build/build.c
	$(CC) -O2 -Wall -Wextra -o $@ $<

# `make send-elf` compiles the elfldr sender, the C replacement for
# tools/send_elf.py, reusing dRPC5's tools/deploy code.
send-elf: tools/send_elf

tools/send_elf: tools/send_elf.c
	$(CC) -O2 -Wall -Wextra -o $@ $<

# `make fakedns PS5iP=192.0.2.5` compiles the fake DNS responder and runs it.
# The fake DNS answers PlayStation-shaped names with NXDOMAIN, redirects
# manuals.playstation.com to pweb5.pages.dev's IPs, and relays the rest to
# the upstream resolver (8.8.8.8 by default). Port 53 binds require root -
# via sudo here and iptables below.
fakedns: tools/fakedns/fakedns
	@if [ -z "$(PS5iP)" ]; then \
	  echo "usage: make fakedns PS5iP=<playstationsIP>"; \
	  rm -f tools/fakedns/fakedns; \
	  exit 2; \
	fi
	sudo tools/fakedns/fakedns --ps5 "$(PS5iP)"

tools/fakedns/fakedns: tools/fakedns/fakedns.c
	$(CC) -O2 -Wall -Wextra -o $@ $<

clean:
	rm -f tools/fakedns/fakedns tools/send_elf tools/build/build

.PHONY: build send-elf fakedns clean