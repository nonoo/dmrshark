NPROCS := $(shell nproc)

.PHONY: install test valgrind valgrind-memcheck instest rc kill kill9 grep check

all:
	@echo running $(NPROCS) jobs...
	@if [ -e /usr/bin/colormake ]; then colormake -j$(NPROCS) -f Makefile.goals; else make -j$(NPROCS) -f Makefile.goals; fi
	@echo
	@echo Success!

install: all
	@dstdir=/opt/dmrshark && sudo rm -f $$dstdir/*build* && sudo mkdir -p $$dstdir && sudo cp `ls -1 -t | grep build | head -n1` $$dstdir

test: all kill
	@sudo sh -c "ulimit 200000000 && exec ./`ls -1 -t | grep build | head -n1`"
	@sudo ./`ls -1 -t | grep build | head -n1` -r

valgrind: all kill
	@sudo valgrind --leak-check=full --track-origins=yes ./`ls -1 -t | grep build | head -n1` -f

valgrind-memcheck: all kill
	@sudo valgrind --tool=memcheck --leak-check=full ./`ls -1 -t | grep build | head -n1` -f

instest: install kill
	@cd /opt/dmrshark; sudo ./`ls -1 -t | grep build | head -n1`; sudo ./`ls -1 -t | grep build | head -n1` -r

rc:
	@sudo ./`ls -1 -t | grep build | head -n1` -r

kill:
	@dmrsharkpid=`ps ax | grep dmrshark | grep -v grep | sed -e 's/^[[:space:]]*//' | cut -f1 -d' '`; if [ ! -z "$$dmrsharkpid" ]; then sudo kill $$dmrsharkpid; fi

kill9:
	@dmrsharkpid=`ps ax | grep dmrshark | grep -v grep | sed -e 's/^[[:space:]]*//' | cut -f1 -d' '`; if [ ! -z "$$dmrsharkpid" ]; then sudo kill -9 $$dmrsharkpid; fi

grep:
	@ps aux | grep dmrshark | grep -v grep

check:
	@cppcheck --enable=all ../../

%:
	@echo running $(NPROCS) jobs...
	@if [ -e /usr/bin/colormake ]; then colormake -j$(NPROCS) -f Makefile.goals $@; else make -j$(NPROCS) -f Makefile.goals $@; fi
	@echo
	@echo Success!
