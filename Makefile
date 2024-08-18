ifeq ($(OS),Windows_NT)
  EXECUTABLE_EXTENSION := .exe
else
  EXECUTABLE_EXTENSION :=
endif

GO_FILES = $(shell find . -type f -name '*.go')
TEST_MODULES ?= 

all: build

.PHONY: all build clean build-all gofmt

gofmt:
	goimports -w -l $(GO_FILES)

build:
	cd cmd/proxy2icmp && go build
	cd ../..

clean:
	cd cmd/proxy2icmp
	rm -f proxy2icmp
	go clean
	cd ../..

build-all:
	(cd cmd/proxy2icmp && \
	echo "windows 386" && \
	GOOS=windows GOARCH=386 CGO_ENABLED=0 go build -o proxy2icmp_windows-386.exe -ldflags="-extldflags=-static" && \
	echo "windows arm64" && \
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o proxy2icmp_windows-amd64.exe -ldflags="-extldflags=-static" && \
	echo "linux 386" && \
	GOOS=linux GOARCH=386 CGO_ENABLED=0 go build -o proxy2icmp_linux-386 -ldflags="-extldflags=-static" && \
	echo "linux amd64" && \
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o proxy2icmp_linux-amd64 -ldflags="-extldflags=-static" && \
	echo "linux arm64" && \
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o proxy2icmp_linux-arm64 -ldflags="-extldflags=-static")