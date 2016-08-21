TOPDIR := $(dir $(lastword $(MAKEFILE_LIST)))..

# Checking if all lib directories exist.
$(foreach LIB, $(LIBS), $(if $(wildcard $(TOPDIR)/libs/$(LIB)),,$(error lib $(LIB) doesn't exist)))

EXECUTABLE := $(shell basename `pwd`)-build-$(shell git rev-parse HEAD | cut -c 1-6)
SOURCES := $(wildcard *.c)
HEADERS := $(wildcard *.h)
OBJECTS := $(patsubst %.c, %-$(APP).o, $(SOURCES))

INCLUDES := $(INCLUDES) -I$(TOPDIR)
NEEDEDLIBS := $(patsubst %, %-$(APP), $(LIBS))
LDFLAGS := $(LDFLAGS) -L$(TOPDIR)/libs -Wl,--start-group $(patsubst %, -l%, $(NEEDEDLIBS)) $(patsubst %, -l%, $(PREBUILTLIBS)) -Wl,--end-group -lm

DEPFILE := $(EXECUTABLE).dep

$(EXECUTABLE): $(DEPFILE) $(OBJECTS) $(patsubst %, $(TOPDIR)/libs/lib%.a, $(NEEDEDLIBS))
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJECTS) $(LDFLAGS) $(LDAFTER) -o $@

$(DEPFILE): $(SOURCES)
	$(CC) $(CFLAGS) -MM $(SOURCES) > $(DEPFILE)

$(OBJECTS): $(SOURCES) $(HEADERS) $(TOPDIR)/config/*.h $(TOPDIR)/config/app/*.h

%-$(APP).a: $(@D)/*
	cd $(@D)/$(subst -$(APP).a,,$(subst lib,,$(@F))); make
