TOPDIR := $(dir $(lastword $(MAKEFILE_LIST)))..
include $(TOPDIR)/Makefile.defconfig.inc

DIRS := $(shell find . -maxdepth 1 -type d -name '[!.]*')

subdirs:
	for d in $(DIRS); do (cd $$d; $(MAKE)); done

include $(TOPDIR)/make/Makefile.common.inc
