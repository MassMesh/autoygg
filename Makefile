
all: client server

client:
	cd cmd/autoygg-client && $(MAKE)

server:
	cd cmd/autoygg-server && $(MAKE)

dev: gofmt client-dev server-dev

gofmt:
	gofmt -s -w .

client-dev:
	cd cmd/autoygg-client && $(MAKE) dev

server-dev:
	cd cmd/autoygg-server && $(MAKE) dev
