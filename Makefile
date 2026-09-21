ifneq ($(KERNELRELEASE),)

obj-m += nitro.o
nitro-y := nitro_kmod.o

else

KDIR ?= $(abspath $(CURDIR)/../linux-riscv-security-tool)
ARCH ?= riscv
CROSS_COMPILE ?= /opt/spacemit-toolchain-linux-glibc-x86_64-v1.2.4/bin/riscv64-unknown-linux-gnu-
VMLINUX_SYMVERS ?= $(KDIR)/vmlinux.symvers
SYMVERS_ARG := $(if $(wildcard $(KDIR)/Module.symvers),,KBUILD_EXTRA_SYMBOLS=$(VMLINUX_SYMVERS))

.PHONY: all clean

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) ARCH=$(ARCH) \
		CROSS_COMPILE=$(CROSS_COMPILE) \
		$(SYMVERS_ARG) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) ARCH=$(ARCH) \
		CROSS_COMPILE=$(CROSS_COMPILE) clean

endif
