
all: client server

server:
	cd cmd/autoygg-server && $(MAKE)

client:
	cd cmd/autoygg-client && $(MAKE)
