GITHASH := $(shell git rev-parse HEAD)

ifeq ($(APP),)
APP := dmrshark
endif
ifneq ($(wildcard $(SRCTOPDIR)/config/app/$(APP).inc),)
include $(SRCTOPDIR)/config/app/$(APP).inc
endif

CC := gcc
CFLAGS := $(CFLAGS) -g -Wall -std=gnu99 -O0 -DGITHASH=\"$(GITHASH)\" \
	-DDEFAULTCONFIG="<config/defaults.h>" \
	-DAPPCONFIGFILE=\"$(SRCTOPDIR)/config/app/$(APP).h\" \
	$(shell pkg-config --cflags glib-2.0) \
	-DARCH_X86 -funsigned-bitfields -funsigned-char -Wno-unused-result

ifeq ($(AMBEDECODEVOICE), 1)
CFLAGS := $(CFLAGS) -DAMBEDECODEVOICE
endif
ifeq ($(MP3ENCODEVOICE), 1)
ifeq ($(AMBEDECODEVOICE),0)
$(error MP3ENCODEVOICE needs AMBEDECODEVOICE to be set.)
endif
CFLAGS := $(CFLAGS) -DMP3ENCODEVOICE
endif

LDAFTER := $(LDAFTER) $(shell pkg-config --libs glib-2.0)
