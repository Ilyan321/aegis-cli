SHELL := /bin/bash
BINARY_NAME := bin/aegis
SRC := $(shell find . -name '*.go' -not -path './vendor/*')

.PHONY: all build clean test bench fmt vet install cross-compile

all: build

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o $(BINARY_NAME) cmd/aegis/main.go
	@echo "Build complete: $(BINARY_NAME) ($$(ls -lh $(BINARY_NAME) | awk '{print $$5}'))"

install: build
	@if [ -w "/usr/local/bin" ]; then \
		cp $(BINARY_NAME) /usr/local/bin/aegis; \
	else \
		mkdir -p $(HOME)/.local/bin && cp $(BINARY_NAME) $(HOME)/.local/bin/aegis; \
		echo "Installed to $(HOME)/.local/bin/aegis (ensure this directory is in your PATH)"; \
	fi
	@echo "Installation complete! Run 'aegis --help' to get started."

cross-compile:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o dist/aegis_linux_amd64 cmd/aegis/main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o dist/aegis_linux_arm64 cmd/aegis/main.go
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o dist/aegis_darwin_amd64 cmd/aegis/main.go
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o dist/aegis_darwin_arm64 cmd/aegis/main.go
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o dist/aegis_windows_amd64.exe cmd/aegis/main.go
	@echo "Cross-compilation complete in dist/"

clean:
	@rm -rf bin/ dist/
	@echo "Cleaned build artifacts"

test:
	go test -v -race ./...

bench:
	go test -bench=. -benchmem -run=^$$ ./...

fmt:
	go fmt ./...

vet:
	go vet ./...
