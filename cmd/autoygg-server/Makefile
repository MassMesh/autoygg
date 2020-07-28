# Calculate version
version = $(shell ../../version-at-commit.sh)

all: amd64 rpi3 rpi4

amd64:
	go build -ldflags "-s -w -X github.com/massmesh/autoygg/internal.version=$(version)" -o autoygg-server-amd64

# we use go-sqlite3 which requires CGO. The compile-time warnings about the use of getaddrinfo and dlopen do not seem
# to cause runtime issues.
amd64-static:
	CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -ldflags '-s -w -extldflags "-static" -X github.com/massmesh/autoygg/internal.version=$(version)' -o autoygg-server-amd64-static

rpi3:
	GOOS=linux GOARCH=arm GOARM=7 go build -ldflags "-s -w -X github.com/massmesh/autoygg/internal.version=$(version)" -o autoygg-server-rpi3

rpi4:
	GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -X github.com/massmesh/autoygg/internal.version=$(version)" -o autoygg-server-rpi4

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
	upx --brute autoygg-server

