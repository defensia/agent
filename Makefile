BINARY     = defensia-agent
BUILD_DIR  = build
CMD_PATH   = ./cmd/defensia-agent
VERSION    = 0.1.0
LDFLAGS    = -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: all build build-linux tidy test clean lab-build lab-up lab-down lab-reset lab-verify lab-test

# LAB_VMS: VM name(s) for the lab-* targets; empty = all 8 fixed lab VMs
# (lab/matrix.sh). LAB_DOWN_ARGS: extra flags for lab-down (--all also
# deletes goldens, --panel also tears down the lab panel compose project).
LAB_VMS =
LAB_DOWN_ARGS =

# LAB_ARCH: target arch for lab-build, derived from the host (OrbStack VMs
# follow the Mac's architecture; CI cross-compiles amd64 the same way).
LAB_ARCH ?= $(shell uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')

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

## lab-build: build agent + integration test binaries for the lab VMs (linux/$(LAB_ARCH))
lab-build:
	GOOS=linux GOARCH=$(LAB_ARCH) CGO_ENABLED=0 go build -o $(BUILD_DIR)/defensia-agent-linux-$(LAB_ARCH) $(CMD_PATH)
	GOOS=linux GOARCH=$(LAB_ARCH) CGO_ENABLED=0 go test -c -tags integration -o $(BUILD_DIR)/integration-linux-$(LAB_ARCH).test ./test/integration

## lab-up: create/start the CSF test lab (OrbStack); idempotent
lab-up: lab-build
	lab/up.sh $(LAB_VMS)

## lab-down: delete lab VMs (LAB_DOWN_ARGS=--all also goldens, --panel stops lab panel)
lab-down:
	lab/down.sh $(LAB_DOWN_ARGS) $(LAB_VMS)

## lab-reset: restore lab VMs from their golden clones
lab-reset: lab-build
	lab/reset.sh $(LAB_VMS)

## lab-verify: health gate for the lab; non-zero if the lab is broken
lab-verify:
	lab/verify.sh $(LAB_VMS)

## lab-test: run integration suites in every lab VM; report in lab/reports/; non-zero on any failure
lab-test: lab-build
	lab/test.sh $(LAB_VMS)
