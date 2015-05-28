%.o:
	$(CC) -c $(CFLAGS) $(INCLUDES) $(subst -$(APP),,$*.c) -o $@

clean:
	find $(SRCTOPDIR) \( -name "*.o" -o -name "*.hex" -o -name "*.a" -o -name "*-build-*" -o -name "*.dep" \) -type f -delete -follow

pull:
	find $(SRCTOPDIR) -follow -name ".git" -type d -execdir echo git repo found: {} \; -execdir git pull \;
