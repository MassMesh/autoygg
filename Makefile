
all: client server

build: client-amd64 server-amd64

static: client-static server-static

pi3: client-pi3 server-pi3

pi4: client-pi4 server-pi4

client:
	cd cmd/autoygg-client && $(MAKE)

server:
	cd cmd/autoygg-server && $(MAKE)

client-amd64:
	cd cmd/autoygg-client && $(MAKE) amd64

server-amd64:
	cd cmd/autoygg-server && $(MAKE) amd64

client-amd64-static:
	cd cmd/autoygg-client && $(MAKE) amd64-static

server-amd64-static:
	cd cmd/autoygg-server && $(MAKE) amd64-static

client-pi3:
	cd cmd/autoygg-client && $(MAKE) pi3

server-pi3:
	cd cmd/autoygg-server && $(MAKE) pi3

client-pi4:
	cd cmd/autoygg-client && $(MAKE) pi4

server-pi4:
	cd cmd/autoygg-server && $(MAKE) pi4

dev: gofmt client-dev server-dev

gofmt:
	gofmt -s -w .

client-dev:
	cd cmd/autoygg-client && $(MAKE) dev

server-dev:
	cd cmd/autoygg-server && $(MAKE) dev
