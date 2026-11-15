ARCH ?= $(shell docker info -f '{{.Architecture}}' 2>/dev/null | sed 's/aarch64/arm64/;s/x86_64/amd64/')
ARCH := $(or $(ARCH),arm64)

.PHONY: build linux image test all clean

all: build linux image

# Host CLI
build:
	go build -o bin/blast ./cmd/blast

# Binaries that run inside the containers
linux:
	mkdir -p bin/linux-$(ARCH)
	GOOS=linux GOARCH=$(ARCH) CGO_ENABLED=0 go build -trimpath -o bin/linux-$(ARCH)/blast-shim ./cmd/blast-shim
	GOOS=linux GOARCH=$(ARCH) CGO_ENABLED=0 go build -trimpath -o bin/linux-$(ARCH)/blast-proxy ./cmd/blast-proxy

image:
	docker build -t blast-sandbox:dev sandbox/

test:
	go test ./...

clean:
	rm -rf bin
