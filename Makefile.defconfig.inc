SRCTOPDIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

# If you don't want to use libmbe then set DECODEVOICE to zero in Makefile.config.inc
DECODEVOICE := 1

# If Makefile.config.inc exists, we include it.
ifeq ($(wildcard $(SRCTOPDIR)/Makefile.config.inc),$(SRCTOPDIR)/Makefile.config.inc)
include $(SRCTOPDIR)/Makefile.config.inc
endif
