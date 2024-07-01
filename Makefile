.PHONY: all clean

# create targets for server, client
# makefile rebuilds everything

# lib:
# Make -C lib

all: # lib server client
	$(MAKE) -C lib
	$(MAKE) -C _server
	$(MAKE) -C _client

clean:
	$(MAKE) -C lib clean
	$(MAKE) -C _server clean
	$(MAKE) -C _client clean

