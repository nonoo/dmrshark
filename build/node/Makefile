NPROCS := $(shell nproc)

all:
	@echo running $(NPROCS) jobs...
	@colormake -j$(NPROCS) -f Makefile.goals
	@echo
	@echo Success!

install:
	@echo running $(NPROCS) jobs...
	@colormake -j$(NPROCS) -f Makefile.goals
	@colormake -f Makefile.goals install
	@echo
	@echo Success!

%:
	@echo running $(NPROCS) jobs...
	@colormake -j$(NPROCS) -f Makefile.goals $@
	@echo
	@echo Success!
