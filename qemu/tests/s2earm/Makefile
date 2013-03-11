TOOLS_PREFIX ?= arm-none-eabi-
CC ?= $(TOOLS_PREFIX)gcc
OBJCOPY ?= $(TOOLS_PREFIX)objcopy
S2E_QEMU ?= ~/s2e-build/qemu-release/arm-s2e-softmmu/qemu-system-arm
LDFLAGS += -Ttext=0x0  -nostdlib -nostdinc
CFLAGS += -march=armv5te

TARGET = \
	 base-forking_test.bin \
	 base-sleep_test.bin \
	 hello.bin

.SECONDARY:

all: $(TARGET)

%.elf: %.S s2earm-inst.S
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@

.PHONY: run
run: $(TARGET)
	$(S2E_QEMU) -M integratorcp -m 1M -s2e-config-file config.lua -s2e-verbose -kernel $<

.PHONY: clean
clean:
	rm -f *.bin *.elf *.o
	rm -Rf s2e-last s2e-out-*
