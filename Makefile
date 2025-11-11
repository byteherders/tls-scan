# Makefile for tls-scan
# Usage examples:
#   make build
#   make run ARGS="example.com"
#   make test
#   make release

SHELL := /bin/bash

# --- Project metadata ---
BINARY      ?= tls-scan
MODULE      ?= github.com/byteherders/tls-scan
MAIN_PKG    ?= ./cmd/tls-scan
PKGS        := $(shell go list ./... | grep -v /vendor/)
DIST_DIR    ?= dist

# --- Docker image ---
GOOS ?= linux
GOARCH ?= amd64
APP_NAME = tls-scan
DOCKER_IMAGE = $(APP_NAME):latest

# --- Build metadata (best-effort if git not present) ---
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.0.0)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo 0000000)
DATE        ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# If you expose these in code, put:
#   package build
#   var Version = "dev"; var Commit = "none"; var Date = "unknown"
LDFLAGS     ?= -s -w \
  -X '$(MODULE)/internal/build.Version=$(VERSION)' \
  -X '$(MODULE)/internal/build.Commit=$(COMMIT)' \
  -X '$(MODULE)/internal/build.Date=$(DATE)'

GOFLAGS     ?=
CGO_ENABLED ?= 0

# Cross-compile matrix (expand if needed)
XC_OS_ARCH  ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: help tools fmt vet lint test cover build run install tidy clean docker release xbuild

default: help

help:
	@echo "Targets:"
	@echo "  tools     Install developer tools (staticcheck, golangci-lint)"
	@echo "  fmt       Format source code"
	@echo "  vet       Run go vet"
	@echo "  lint      Run static analysis (vet + staticcheck [+ golangci-lint if present])"
	@echo "  test      Run unit tests"
	@echo "  cover     Run tests with coverage and open HTML report"
	@echo "  build     Build $(BINARY) for host OS/ARCH"
	@echo "  run       Run $(BINARY) with ARGS=\"...\""
	@echo "  install   go install $(MAIN_PKG)"
	@echo "  tidy      go mod tidy"
	@echo "  release   Cross-compile into ./$(DIST_DIR)"
	@echo "  docker    Create a minimal docker image"
	@echo "  clean     Remove build artifacts"

tools:
	@echo "Installing tools..."
	@command -v staticcheck >/dev/null 2>&1 || go install honnef.co/go/tools/cmd/staticcheck@latest
	@command -v golangci-lint >/dev/null 2>&1 || \
	  (echo "golangci-lint not found; installing..." && \
	   curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$GOPATH/bin latest || true)
	@echo "Tools ready."

fmt:
	@echo "Formatting..."
	@go fmt ./...

vet:
	@echo "go vet..."
	@go vet $(PKGS)

lint: vet
	@echo "staticcheck..."
	@staticcheck $(PKGS) || true
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "golangci-lint..."; \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed; skipping."; \
	fi

test:
	@echo "Running tests..."
	@go test $(GOFLAGS) ./...

cover:
	@echo "Running coverage..."
	@go test $(GOFLAGS) -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -n 1
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage HTML: coverage.html"

build:
	@echo "Building $(BINARY)..."
	@mkdir -p $(DIST_DIR)
	@CGO_ENABLED=$(CGO_ENABLED) go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY) $(MAIN_PKG)
	@echo "Built $(DIST_DIR)/$(BINARY)"

run:
	@echo "Running $(BINARY) $(ARGS)"
	@go run $(GOFLAGS) -ldflags "$(LDFLAGS)" $(MAIN_PKG) $(ARGS)

install:
	@echo "Installing $(BINARY)..."
	@CGO_ENABLED=$(CGO_ENABLED) go install $(GOFLAGS) -ldflags "$(LDFLAGS)" $(MAIN_PKG)

tidy:
	@echo "Tidying modules..."
	@go mod tidy

docker:
	@if ! command -v docker >/dev/null 2>&1; then \
		echo "❌ Docker not found. Please install Docker first."; exit 1; \
	fi
	@echo "🔨 Building Linux/amd64 binary for Docker image..."
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o ./dist/$(APP_NAME) ./cmd/$(APP_NAME)
	@echo "🐋 Building Docker image $(DOCKER_IMAGE)..."
	docker build -t $(DOCKER_IMAGE) .
	@echo "✅ Docker image built: $(DOCKER_IMAGE)"

clean:
	@echo "Cleaning..."
	@rm -rf $(DIST_DIR) coverage.out coverage.html

release: clean xbuild
	@echo "Release artifacts in ./$(DIST_DIR)"

xbuild:
	@mkdir -p $(DIST_DIR)
	@set -e; \
	for pair in $(XC_OS_ARCH); do \
	  GOOS=$${pair%%/*}; GOARCH=$${pair##*/}; \
	  ext=""; \
	  [ $$GOOS = "windows" ] && ext=".exe"; \
	  out="$(DIST_DIR)/$(BINARY)-$(VERSION)-$$GOOS-$$GOARCH$$ext"; \
	  echo "Building $$out"; \
	  CGO_ENABLED=$(CGO_ENABLED) GOOS=$$GOOS GOARCH=$$GOARCH \
	    go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $$out $(MAIN_PKG); \
	  (cd $(DIST_DIR) && shasum -a 256 "$$(basename $$out)" > "$$(basename $$out).sha256"); \
	done
