SHELL := /bin/bash
BINARY_NAME := bin/aegis
SRC := $(shell find . -name '*.go' -not -path './vendor/*')

.PHONY: all build clean test bench fmt vet

all: build

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o $(BINARY_NAME) cmd/aegis/main.go
	@echo "Build complete: $(BINARY_NAME) ($$(ls -lh $(BINARY_NAME) | awk '{print $$5}'))"

clean:
	@rm -rf bin/
	@echo "Cleaned build artifacts"

test:
	go test -v -race ./...

bench:
	go test -bench=. -benchmem -run=^$$ ./...

fmt:
	go fmt ./...

vet:
	go vet ./...
