TOPDIR := $(dir $(lastword $(MAKEFILE_LIST)))..
include $(TOPDIR)/Makefile.defconfig.inc

include $(TOPDIR)/make/Makefile.target.inc

ifndef SRCDIR
SRCDIR := .
endif

SOURCES := $(SOURCES) $(shell find $(SRCDIR) -name '[!.]*.c')
HEADERS := $(HEADERS) $(shell find $(SRCDIR) -name '[!.]*.h')
OBJECTS := $(patsubst %.c, %-$(APP).o, $(SOURCES))
INCLUDES := $(INCLUDES) -I$(TOPDIR)
LIBNAME := $(shell basename `pwd`)
LIBDEST := $(TOPDIR)/libs/lib$(LIBNAME)-$(APP).a
DEPFILE := $(LIBDEST).dep

$(LIBDEST): $(DEPFILE) $(OBJECTS)
	ar rcs $(LIBDEST) $(OBJECTS)

$(DEPFILE): $(SOURCES)
	$(CC) $(CFLAGS) -MM $(SOURCES) > $(DEPFILE)

$(OBJECTS): $(SOURCES) $(HEADERS) $(TOPDIR)/config/*.h $(TOPDIR)/config/app/*.h

include $(TOPDIR)/make/Makefile.subdir.inc
