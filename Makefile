obj-m := ipt_l7pm.o

KERNEL_SRC       := /local/paul/8572_nov_rel/linux-2.6.30-fsl
KERNEL_ARGS      := SUBDIRS=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE)

.PHONY: build_modules clean
default: build_modules

build_modules:
	make -C  $(KERNEL_SRC) $(KERNEL_ARGS) modules

install_modules:
	make -C  $(KERNEL_SRC) $(KERNEL_ARGS) INSTALL_MOD_PATH=$(INSTALL_MOD_PATH) modules_install

clean:
	make -C  $(KERNEL_SRC) $(KERNEL_ARGS) clean
	rm -f modules.order
