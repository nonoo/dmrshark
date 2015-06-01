NPROCS := $(shell nproc)

all:
	@echo running $(NPROCS) jobs...
	@if [ -e /usr/bin/colormake ]; then colormake -j$(NPROCS) -f Makefile.goals; else make -j$(NPROCS) -f Makefile.goals; fi
	@echo
	@echo Success!

install:
	@echo running $(NPROCS) jobs...
	@if [ -e /usr/bin/colormake ]; then colormake -j$(NPROCS) -f Makefile.goals; else make -j$(NPROCS) -f Makefile.goals; fi
	@if [ -e /usr/bin/colormake ]; then colormake -j$(NPROCS) -f Makefile.goals install; else make -j$(NPROCS) -f Makefile.goals install; fi
	@echo
	@echo Success!

%:
	@echo running $(NPROCS) jobs...
	@if [ -e /usr/bin/colormake ]; then colormake -j$(NPROCS) -f Makefile.goals $@; else make -j$(NPROCS) -f Makefile.goals $@; fi
	@echo
	@echo Success!
