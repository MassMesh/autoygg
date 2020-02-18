
all: client server

static: client-static server-static

client-static:
	cd cmd/autoygg-client && $(MAKE) static

server-static:
	cd cmd/autoygg-server && $(MAKE) static

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
