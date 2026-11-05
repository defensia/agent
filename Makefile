BINARY     = defensia-agent
BUILD_DIR  = build
CMD_PATH   = ./cmd/defensia-agent
VERSION    = 0.1.0
LDFLAGS    = -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: all build build-linux tidy test clean lab-up lab-down lab-reset lab-verify

# LAB_VMS: VM name(s) for the lab-* targets; empty = all 8 fixed lab VMs
# (lab/matrix.sh). LAB_DOWN_ARGS: extra flags for lab-down (--all also
# deletes goldens, --panel also tears down the lab panel compose project).
LAB_VMS =
LAB_DOWN_ARGS =

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

## lab-up: create/start the CSF test lab (OrbStack); idempotent
lab-up:
	lab/up.sh $(LAB_VMS)

## lab-down: delete lab VMs (LAB_DOWN_ARGS=--all also goldens, --panel stops lab panel)
lab-down:
	lab/down.sh $(LAB_DOWN_ARGS) $(LAB_VMS)

## lab-reset: restore lab VMs from their golden clones
lab-reset:
	lab/reset.sh $(LAB_VMS)

## lab-verify: health gate for the lab; non-zero if the lab is broken
lab-verify:
	lab/verify.sh $(LAB_VMS)
