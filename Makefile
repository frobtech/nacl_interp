CC = gcc
ARM_CC = arm-linux-gnueabi-gcc
CFLAGS = -std=gnu99 -Wall -ffreestanding -fPIC -O2 -g
LDFLAGS = -shared -nostdlib -nostartfiles

.PHONY: all clean install-x86 install-arm install

all: ld-nacl-x86-32.so.1 ld-nacl-x86-64.so.1 ld-nacl-arm.so.1

ld-nacl-x86-32.so.1: nacl_interp.c
	$(CC) -o $@ $< $(CFLAGS) -m32 $(LDFLAGS)

ld-nacl-x86-64.so.1: nacl_interp.c
	$(CC) -o $@ $< $(CFLAGS) -m64 $(LDFLAGS)

ld-nacl-arm.so.1: nacl_interp.c
	$(ARM_CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

clean:
	rm -f *.o *.so.1

machine := $(shell uname -m)
ifneq (,$(filter arm%,$(machine)))
install: install-arm
endif
ifneq (,$(filter x86_64% i%86,$(machine)))
install: install-x86
endif

install-x86: ld-nacl-x86-32.so.1 ld-nacl-x86-64.so.1
	install -c -m 755 ld-nacl-x86-32.so.1 /lib/ld-nacl-x86-32.so.1
	install -c -m 755 ld-nacl-x86-64.so.1 /lib64/ld-nacl-x86-64.so.1
	$(post-install)

install-arm: ld-nacl-arm.so.1
	install -c -m 755 ld-nacl-arm.so.1 /lib/ld-nacl-arm.so.1
	$(post-install)

define post-install
@echo "Please manually set up nacl_interp_loader.sh and set NACL_INTERP_LOADER env variable to point to nacl_interp_loader.sh"
endef
