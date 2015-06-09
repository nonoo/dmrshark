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

test:
	@echo running $(NPROCS) jobs...
	@if [ -e /usr/bin/colormake ]; then colormake -j$(NPROCS) -f Makefile.goals; else make -j$(NPROCS) -f Makefile.goals; fi
	@dmrsharkpid=`ps ax | grep dmrshark | grep -v grep | sed -e 's/^[[:space:]]*//' | cut -f1 -d' '`; if [ ! -z "$$dmrsharkpid" ]; then sudo kill $$dmrsharkpid; fi
	@sudo ./`ls -1 -t | grep build | head -n1`
	@sudo ./`ls -1 -t | grep build | head -n1` -r

rc:
	@sudo ./`ls -1 -t | grep build | head -n1` -r

kill:
	@dmrsharkpid=`ps ax | grep dmrshark | grep -v grep | sed -e 's/^[[:space:]]*//' | cut -f1 -d' '`; if [ ! -z "$$dmrsharkpid" ]; then sudo kill $$dmrsharkpid; fi

%:
	@echo running $(NPROCS) jobs...
	@if [ -e /usr/bin/colormake ]; then colormake -j$(NPROCS) -f Makefile.goals $@; else make -j$(NPROCS) -f Makefile.goals $@; fi
	@echo
	@echo Success!
