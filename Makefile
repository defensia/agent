BINARY     = defensia-agent
BUILD_DIR  = build
CMD_PATH   = ./cmd/defensia-agent
VERSION    = 0.1.0
LDFLAGS    = -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: all build build-linux tidy test clean

all: build

## build: compile for the current platform
build:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) $(CMD_PATH)

## build-linux: cross-compile for Linux amd64 (for deployment)
build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) \
		-o $(BUILD_DIR)/$(BINARY)-linux-amd64 $(CMD_PATH)

## build-linux-arm: cross-compile for Linux arm64
build-linux-arm:
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) \
		-o $(BUILD_DIR)/$(BINARY)-linux-arm64 $(CMD_PATH)

## tidy: download deps and tidy go.mod
tidy:
	go mod tidy

## test: run all tests
test:
	go test ./...

## clean: remove build artifacts
clean:
	rm -rf $(BUILD_DIR)

## install: install to /usr/local/bin (requires root)
install: build-linux
	install -m 0755 $(BUILD_DIR)/$(BINARY)-linux-amd64 /usr/local/bin/$(BINARY)

help:
	@grep -E '^## ' Makefile | sed 's/## //'
