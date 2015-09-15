SRCTOPDIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

# If you don't want to use libmbe then set AMBEDECODEVOICE to 0 in Makefile.config.inc
AMBEDECODEVOICE := 1
# If you don't want to use libmp3lame then set MP3ENCODEVOICE to 0 in Makefile.config.inc
MP3ENCODEVOICE := 1

# If Makefile.config.inc exists, we include it.
ifeq ($(wildcard $(SRCTOPDIR)/Makefile.config.inc),$(SRCTOPDIR)/Makefile.config.inc)
include $(SRCTOPDIR)/Makefile.config.inc
endif
