.PHONY: build test lint integration self-scan tidy clean help \
        setup verify doctor install-tools install-gh install-git-filter-repo install-kingfisher \
        check-anthropic-key

BINARY := bin/leakfix
PKG    := ./cmd/leakfix
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-22s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the leakfix binary into bin/
	@mkdir -p bin
	go build -o $(BINARY) $(PKG)

test: ## Run unit tests with the race detector
	go test -race -count=1 ./...

lint: ## Run golangci-lint
	golangci-lint run

tidy: ## Tidy go.mod / go.sum
	go mod tidy

integration: ## Run integration tests (requires kingfisher on PATH)
	go test -race -count=1 -tags=integration ./...

self-scan: build verify ## Run leakfix scan against this repo and fail on any finding
	$(BINARY) scan . --strict

doctor: build ## Run leakfix doctor to verify prerequisites
	$(BINARY) doctor

verify: ## Verify scan-time prerequisites (just kingfisher)
	@if ! command -v kingfisher >/dev/null 2>&1; then \
	  echo ""; \
	  echo "  kingfisher is not on PATH — run 'make setup' or 'make install-kingfisher'"; \
	  echo "  install instructions: https://github.com/mongodb/kingfisher#installation"; \
	  echo ""; \
	  exit 1; \
	fi

clean: ## Remove build artifacts
	rm -rf bin/ dist/

# ---------------------------------------------------------------------------
# Setup: install the four external prerequisites listed in SPEC.md §17.1
# ---------------------------------------------------------------------------

setup: install-tools check-anthropic-key build verify ## Install all external prerequisites
	@echo ""
	@echo "  All set. Try: $(BINARY) doctor"

install-tools: install-gh install-git-filter-repo install-kingfisher ## Install gh, git-filter-repo, and kingfisher

install-gh: ## Install the GitHub CLI (gh)
	@if command -v gh >/dev/null 2>&1; then \
	  echo "[gh] already installed: $$(gh --version | head -1)"; \
	else \
	  echo "[gh] installing..."; \
	  if [ "$(UNAME_S)" = "Darwin" ] && command -v brew >/dev/null 2>&1; then \
	    brew install gh; \
	  elif command -v apt-get >/dev/null 2>&1; then \
	    sudo apt-get update && sudo apt-get install -y gh; \
	  else \
	    echo "  Please install gh manually: https://cli.github.com/"; \
	    exit 1; \
	  fi; \
	fi

install-git-filter-repo: ## Install git-filter-repo
	@if command -v git-filter-repo >/dev/null 2>&1; then \
	  echo "[git-filter-repo] already installed: $$(git-filter-repo --version 2>&1 | head -1)"; \
	else \
	  echo "[git-filter-repo] installing..."; \
	  if [ "$(UNAME_S)" = "Darwin" ] && command -v brew >/dev/null 2>&1; then \
	    brew install git-filter-repo; \
	  elif command -v pipx >/dev/null 2>&1; then \
	    pipx install git-filter-repo; \
	  elif command -v pip3 >/dev/null 2>&1; then \
	    pip3 install --user git-filter-repo; \
	  else \
	    echo "  Please install git-filter-repo manually:"; \
	    echo "  https://github.com/newren/git-filter-repo#how-do-i-install-it"; \
	    exit 1; \
	  fi; \
	fi

install-kingfisher: ## Install kingfisher (best-effort; falls back to pointing at releases)
	@if command -v kingfisher >/dev/null 2>&1; then \
	  echo "[kingfisher] already installed: $$(kingfisher --version 2>&1 | head -1)"; \
	else \
	  echo "[kingfisher] installing..."; \
	  if command -v brew >/dev/null 2>&1; then \
	    brew install kingfisher; \
	  elif command -v cargo >/dev/null 2>&1; then \
	    echo "  brew not found; using cargo install (requires Rust toolchain)"; \
	    cargo install --git https://github.com/mongodb/kingfisher kingfisher; \
	  else \
	    echo "  Could not auto-install. Choose one:"; \
	    echo "    1) Install Homebrew and rerun: brew install kingfisher"; \
	    echo "    2) Install Rust and rerun: cargo install --git https://github.com/mongodb/kingfisher kingfisher"; \
	    echo "    3) Download a prebuilt binary: https://github.com/mongodb/kingfisher/releases"; \
	    exit 1; \
	  fi; \
	fi

check-anthropic-key: ## Warn if ANTHROPIC_API_KEY is not set (non-fatal; only `remediate` needs it)
	@if [ -z "$$ANTHROPIC_API_KEY" ]; then \
	  echo ""; \
	  echo "  [warning] ANTHROPIC_API_KEY is not set."; \
	  echo "  Required only for 'leakfix remediate'. 'scan' and 'doctor' work without it."; \
	  echo "  Add to your shell profile:"; \
	  echo "    export ANTHROPIC_API_KEY=sk-ant-..."; \
	  echo "  Get a key at: https://console.anthropic.com/settings/keys"; \
	  echo ""; \
	else \
	  echo "[ANTHROPIC_API_KEY] set"; \
	fi
