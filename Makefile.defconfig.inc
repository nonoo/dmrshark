SRCTOPDIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

# If Makefile.config.inc exists, we include it.
ifeq ($(wildcard $(SRCTOPDIR)/Makefile.config.inc),$(SRCTOPDIR)/Makefile.config.inc)
include $(SRCTOPDIR)/Makefile.config.inc
endif
