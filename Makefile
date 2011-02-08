#***********************< BEGIN COPYRIGHT >************************
#
# Copyright (C) 2007-2011 Freescale Semiconductor, Inc. All rights reserved.
#
# This is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
#***********************< END COPYRIGHT >***************************/

obj-m       := ipt_l7pm.o
KERNEL_ARGS := SUBDIRS=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE)

.PHONY: build_modules clean
default: build_modules

build_modules:
	make -C  $(KERNEL_SRC) $(KERNEL_ARGS) modules

install_modules:
	make -C  $(KERNEL_SRC) $(KERNEL_ARGS) INSTALL_MOD_PATH=$(INSTALL_MOD_PATH) modules_install

clean:
	make -C  $(KERNEL_SRC) $(KERNEL_ARGS) clean
	rm -f modules.order
