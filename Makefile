
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
mkfile_dir := $(dir $(mkfile_path))

all: client server

static: client-amd64-static server-amd64-static

amd64: client-amd64 server-amd64

pi3: client-rpi3 server-rpi3

pi4: client-rpi4 server-rpi4

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

client-rpi3:
	cd cmd/autoygg-client && $(MAKE) rpi3

server-rpi3:
	cd cmd/autoygg-server && $(MAKE) rpi3

client-rpi4:
	cd cmd/autoygg-client && $(MAKE) rpi4

server-rpi4:
	cd cmd/autoygg-server && $(MAKE) rpi4

dev: gofmt client-dev server-dev

gofmt:
	gofmt -s -w .

client-dev:
	cd cmd/autoygg-client && $(MAKE) dev

server-dev:
	cd cmd/autoygg-server && $(MAKE) dev

test: client-amd64 server-amd64
	cd docker-test && docker build . -t autoygg/test
	docker run --rm -ti --net=host --cap-add=NET_ADMIN --device=/dev/net/tun --name autoygg-test -v $(mkfile_dir):/autoygg autoygg/test
