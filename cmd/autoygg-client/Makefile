
all: amd64 pi3 pi4 amd64-static

amd64:
	go build -ldflags "-s -w" -o autoygg-client-amd64

amd64-static:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-s -w -extldflags "-static"' -o autoygg-client-amd64-static

pi3:
	GOOS=linux GOARCH=arm GOARM=7 go build -ldflags "-s -w" -o autoygg-client-pi3

pi4:
	GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o autoygg-client-pi4

dev: lint test
	go build -ldflags "-s -w"

test:
	go test -coverprofile=coverage.out

coverprofile_func:
	go tool cover -func=coverage.out

coverprofile_html:
	go tool cover -html=coverage.out

lint:
	cd ../../internal && golint; golangci-lint run
	golangci-lint run

compress: build
	upx --brute autoygg-client

