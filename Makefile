MODULE  := github.com/SandSoftwareSolutions/hallmark
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X $(MODULE)/internal/cli.Version=$(VERSION) -X $(MODULE)/internal/cli.Commit=$(COMMIT) -X $(MODULE)/internal/cli.Date=$(DATE)

.PHONY: all build test race vet fmt fmt-check check lint vuln fuzz dist install clean

all: check build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o hallmark .

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || (echo "These files need gofmt:"; gofmt -l .; exit 1)

check: fmt-check vet test

# Static analysis and known-vulnerability scan; they download the tools on first use.
lint:
	go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

fuzz:
	go test -run '^$$' -fuzz FuzzValidate -fuzztime 15s ./internal/manifest/
	go test -run '^$$' -fuzz FuzzMatch -fuzztime 15s ./internal/ignore/

dist:
	VERSION=$(VERSION) COMMIT=$(COMMIT) DATE=$(DATE) scripts/dist.sh

install:
	go install -trimpath -ldflags "$(LDFLAGS)" .

clean:
	rm -rf hallmark hallmark.exe dist
