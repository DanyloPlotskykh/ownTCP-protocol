.PHONY: all clean

all:
	$(MAKE) -C lib
	$(MAKE) -C _server
	$(MAKE) -C _client

clean:
	$(MAKE) -C lib clean
	$(MAKE) -C _server clean
	$(MAKE) -C _client clean

