#
# define the directories to build in
#
obj-m := ipt_l7pm.o

# -----=[BEGIN CONFIGURABLE MACROS]=-----
#
# Specify the path to the full linux kernel source tree
#
KERNEL_SRC := /local/paul/kumar/linux-2.6
KERNEL_VER := 2.6.27.2

#
# define a macro to check whether this is a release.
#
export KERNEL_RELEASE := 1

#
# specify the cross compiler prefix including trailing "-"
#
CROSS_COMPILE_PREFIX := powerpc-linux-gnu-

# -----=[END CONFIGURABLE MACROS]=-----


# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# NOTHING BELOW THIS LINE SHOULD BE CHANGED
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


#
# extra include path to pass to the kbuild process
#
PM_SOFTWARE_DIR  := $(dir $(PWD))
KERNEL_INCLUDE   :=
KERNEL_MODULE_DIR:= $(PWD)


# 
# set up a cleaner commandline for readability
#
KERNEL_ARGS     :=  $(KERNEL_SRC) EXTRA_CFLAGS="$(KERNEL_INCLUDE)" 
KERNEL_ARGS     += SUBDIRS=$(KERNEL_MODULE_DIR) ARCH=powerpc
KERNEL_ARGS     += CROSS_COMPILE=$(CROSS_COMPILE_PREFIX)

.PHONY: build_pm_modules clean
default: build_pm_modules


#
# Walk the directories in obj-m above and make sure the correct kernel root path
# is specified in .kernel_root.
#
build_pm_modules: 
	@make -C $(KERNEL_ARGS) modules
ifndef LOCAL
	@make -C $(KERNEL_ARGS) modules_install
endif


clean:
	@make -C $(KERNEL_ARGS) clean
	rm -f modules.order

