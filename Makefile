all:
	@$(MAKE) -f makefiles/Makefile.`uname` all

.DEFAULT:
	@$(MAKE) -f makefiles/Makefile.`uname` $@
