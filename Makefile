BIN=verify-exec
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

.PHONY: help
## help: prints this help message
help:
	@echo "Usage:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

.PHONY: setup
## setup: setup go modules
setup:
	@go mod tidy \
		&& go mod download

.PHONY: build
## build: build the application
build: clean
	@echo "Building..."
	@go build $(LDFLAGS) -o ./dist/${BIN} ./cmd/verify-exec

.PHONY: build-all
## build-all: cross-build release binaries for darwin/linux amd64/arm64 into ./dist
build-all: clean
	@for os in darwin linux; do \
		for arch in amd64 arm64; do \
			echo "Building $$os/$$arch..."; \
			GOOS=$$os GOARCH=$$arch go build $(LDFLAGS) -o ./dist/${BIN}-$$os-$$arch ./cmd/verify-exec || exit 1; \
		done; \
	done

.PHONY: run
## run: runs go run ./cmd/verify-exec (pass args via ARGS="<cluster> <task-id>")
run:
	go run -race ./cmd/verify-exec $(ARGS)

.PHONY: clean
## clean: cleans the binary
clean:
	@echo "Cleaning"
	@go clean
	@rm -rf ./dist

.PHONY: test
## test: runs go test with default values
test:
	go test -v -count=1 -race ./...

.PHONY: fmt
## fmt: formats all go files
fmt:
	gofmt -w .

.PHONY: fmt-check
## fmt-check: fails if any file is not gofmt-formatted (for CI)
fmt-check:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi

.PHONY: vet
## vet: runs go vet
vet:
	go vet ./...

.PHONY: ci
## ci: runs the full CI pipeline (fmt-check, vet, test, build)
ci: fmt-check vet test build
