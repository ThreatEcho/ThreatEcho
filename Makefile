# Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only
#
# ThreatEcho — Detection Engineering for AI Agents
# https://threatecho.com
#
# Usage:
#   make              Build the CLI binary
#   make help         Show all targets
#   make test         Run the full test suite
#   make ci           Full CI pipeline (fmt + vet + race + lint)

.PHONY: all build clean test vet fmt install coverage lint-campaigns gap-report \
        sigma-rules summary matrix coverage-report cross docker release-dry help

BINARY     = bin/threatecho
AGENT      = bin/threatecho-agent
MODULE     = github.com/ThreatEcho/threatecho
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS    = -s -w \
             -X $(MODULE)/pkg/version.Version=$(VERSION) \
             -X $(MODULE)/pkg/version.Commit=$(COMMIT) \
             -X $(MODULE)/pkg/version.BuildTime=$(BUILD_TIME)
PLATFORMS  = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

# --- Core targets ---

all: build ## Build both binaries (default)

build: ## Build the CLI and agent binaries
	go build -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/threatecho
	go build -buildvcs=false -ldflags "$(LDFLAGS)" -o $(AGENT) ./cmd/threatecho-agent

install: build ## Build and install to GOPATH/bin
	cp $(BINARY) $(GOPATH)/bin/threatecho 2>/dev/null || cp $(BINARY) ~/go/bin/threatecho
	cp $(AGENT) $(GOPATH)/bin/threatecho-agent 2>/dev/null || cp $(AGENT) ~/go/bin/threatecho-agent

clean: ## Remove build artifacts
	rm -rf bin/ dist/ coverage.out coverage.html

# --- Quality ---

test: ## Run all tests
	go test -buildvcs=false -count=1 ./...

test-race: ## Run tests with race detector
	go test -buildvcs=false -count=1 -race ./...

test-verbose: ## Run tests with verbose output
	go test -buildvcs=false -count=1 -v ./...

coverage: ## Generate coverage report
	go test -buildvcs=false -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

coverage-html: coverage ## Generate and open HTML coverage report
	go tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report written to coverage.html"

vet: ## Run go vet
	go vet -buildvcs=false ./...

fmt: ## Format all Go files
	gofmt -s -w .

fmt-check: ## Check formatting (CI gate — exits non-zero if unformatted)
	@test -z "$$(gofmt -s -l . 2>&1)" || { echo "Files need gofmt:"; gofmt -s -l .; exit 1; }

lint: ## Run golangci-lint (install: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

# --- Campaign validation ---

lint-campaigns: build
	@for dir in campaigns/*/; do \
		$(BINARY) validate "$$dir" || exit 1; \
	done
	$(BINARY) lint -dir campaigns/ || true
	@for dir in policies/*/; do \
		$(BINARY) policy validate "$$dir" || exit 1; \
	done

# --- Reports ---

gap-report: build
	$(BINARY) gap -format html -dir campaigns/ > bin/gap-report.html
	@echo "✓ Report written to bin/gap-report.html"

gap-report-md: build
	$(BINARY) gap -format md -dir campaigns/ > bin/gap-report.md
	@echo "✓ Report written to bin/gap-report.md"

sigma-rules: build
	@mkdir -p bin
	$(BINARY) export sigma -dir campaigns/ -output bin/sigma-rules.yml
	@echo "✓ Sigma rules written to bin/sigma-rules.yml"

summary: build
	$(BINARY) summary -dir campaigns/

matrix: build
	$(BINARY) matrix -dir campaigns/

matrix-compact: build
	$(BINARY) matrix -compact -dir campaigns/

coverage-report: build
	$(BINARY) coverage -dir campaigns/

coverage-json: build
	@mkdir -p bin
	$(BINARY) coverage -format json -dir campaigns/ > bin/coverage.json
	@echo "✓ Coverage report written to bin/coverage.json"

config-show: build
	$(BINARY) config show

config-path: build
	$(BINARY) config path

fingerprint: build
	@for dir in campaigns/*/; do \
		name=$$(basename "$$dir"); \
		hash=$$($(BINARY) simulate "$$dir" 2>/dev/null | head -1); \
		echo "$$name"; \
	done

# --- Search & analytics ---

search: build
	$(BINARY) search -dir campaigns/ $(ARGS)

stats: build
	$(BINARY) stats -dir campaigns/

stats-json: build
	@mkdir -p bin
	$(BINARY) stats -json -dir campaigns/ > bin/stats.json
	@echo "✓ Stats written to bin/stats.json"

score: build
	$(BINARY) score -dir campaigns/

enrich: build
	$(BINARY) enrich -dir campaigns/

convert-json: build
	@mkdir -p bin/converted
	$(BINARY) convert -format json -dir campaigns/ -output bin/converted/
	@echo "✓ Converted to bin/converted/"

convert-markdown: build
	@mkdir -p bin/converted
	$(BINARY) convert -format markdown -dir campaigns/ -output bin/converted/
	@echo "✓ Converted to bin/converted/"

# --- Import ---

import-atomic: build
	@test -n "$(SRC)" || (echo "Usage: make import-atomic SRC=path/to/atomics/" && exit 1)
	@mkdir -p campaigns/imported
	$(BINARY) import -source atomic -output campaigns/imported/ $(SRC)

# --- Cross-compilation ---

cross: ## Build both binaries for all supported OS/arch combinations
	@mkdir -p dist
	@for platform in $(PLATFORMS); do \
		os=$${platform%%/*}; \
		arch=$${platform##*/}; \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		outname="dist/threatecho-$$os-$$arch$$ext"; \
		agentname="dist/threatecho-agent-$$os-$$arch$$ext"; \
		echo "  → $$outname"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -buildvcs=false -ldflags "$(LDFLAGS)" -o $$outname ./cmd/threatecho; \
		echo "  → $$agentname"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -buildvcs=false -ldflags "$(LDFLAGS)" -o $$agentname ./cmd/threatecho-agent; \
	done
	@echo "✓ Cross-compilation complete ($(words $(PLATFORMS)) targets × 2 binaries)"

docker: ## Build the Docker image
	docker build -t threatecho:$(VERSION) -t threatecho:latest .

release-dry: ## Dry-run a GoReleaser build (no publish)
	goreleaser release --snapshot --clean

# --- CI pipeline (mirrors GitHub Actions) ---

ci: fmt-check vet test-race lint-campaigns ## Full CI pipeline (fmt + vet + race + lint)
	@echo "✓ CI pipeline passed"

# --- Help ---
help: ## Show all targets with descriptions
	@echo "ThreatEcho Makefile targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Additional targets (no description):"
	@echo "  lint-campaigns    Validate all campaign YAML files"
	@echo "  gap-report        Generate HTML gap report"
	@echo "  sigma-rules       Export Sigma detection rules"
	@echo "  summary           Show security posture dashboard"
	@echo "  matrix            Show ATT&CK coverage matrix"
	@echo "  stats             Show project analytics"
	@echo "  search            Search campaigns (ARGS=\"-technique T1059\")"
	@echo "  import-atomic     Import ART tests (SRC=path/to/atomics/)"
