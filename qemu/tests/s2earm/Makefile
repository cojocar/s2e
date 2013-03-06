TOOLS_PREFIX = arm-none-eabi-
CC = $(TOOLS_PREFIX)gcc
OBJCOPY = $(TOOLS_PREFIX)objcopy
S2E_QEMU = ~/s2e-build/qemu-release/arm-s2e-softmmu/qemu-system-arm
TARGET = base-forking_test.bin

.SECONDARY:

all: $(TARGET)

%.elf: %.S
	$(CC) -Ttext=0x0  -nostdlib -nostdinc -o $@ $^

%.bin:%.elf
	$(OBJCOPY) -O binary $< $@

.PHONY: run
run: $(TARGET)
	$(S2E_QEMU) -M integratorcp -m 1M -s2e-config-file config.lua -s2e-verbose -kernel $<

.PHONY: clean
clean:
	rm -f *.bin *.elf *.o
	rm -Rf s2e-last s2e-out-*
