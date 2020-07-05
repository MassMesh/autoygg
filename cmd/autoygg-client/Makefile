# Calculate version: if this is a clean checkout, then use the first tag if there is one, otherwise the commit hash. If this is a modified checkout, use the word 'dev'
commit = $(shell git log -1 --pretty=format:"%H")
tag = $(shell git tag --points-at $(commit))
version = $(shell if `git diff --quiet`; then if [ "$(tag)" != "" ]; then echo "$(tag)"; else echo "$(commit)"; fi; else echo 'dev'; fi)

all: amd64 rpi3 rpi4

amd64:
	go build -ldflags "-s -w -X github.com/massmesh/autoygg/internal.version=$(version)" -o autoygg-client-amd64

amd64-static:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-s -w -extldflags "-static" -X github.com/massmesh/autoygg/internal.version=$(version)' -o autoygg-client-amd64-static

rpi3:
	GOOS=linux GOARCH=arm GOARM=7 go build -ldflags "-s -w -X github.com/massmesh/autoygg/internal.version=$(version)" -o autoygg-client-rpi3

rpi4:
	GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -X github.com/massmesh/autoygg/internal.version=$(version)" -o autoygg-client-rpi4

dev: lint test
	go build -ldflags "-s -w -X github.com/massmesh/autoygg/internal.version=$(version)"

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

