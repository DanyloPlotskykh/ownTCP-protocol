.PHONY: all clean

all:
	$(MAKE) -C _server
	$(MAKE) -C _client

clean:
	$(MAKE) -C _server clean
	$(MAKE) -C _client clean
