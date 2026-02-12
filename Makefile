# -----------------------------
# Makefile for Go Crypto/Security Library
# -----------------------------

# Location where Go binaries are installed
TOOLS_BIN := $(shell go env GOPATH)/bin

.PHONY: tools fmt vet lint security test ci

# -----------------------------
# Install required dev tools
# -----------------------------
tools:
	@echo "Installing development tools..."
	@go install honnef.co/go/tools/cmd/staticcheck@latest
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install golang.org/x/tools/cmd/goimports@latest
	@echo "All tools installed."

# -----------------------------
# Formatting
# -----------------------------
fmt: tools
	@echo "Running gofmt..."
	gofmt -w .
	@echo "Running goimports..."
	goimports -w .

# -----------------------------
# Static analysis
# -----------------------------
vet: tools
	@echo "Running go vet..."
	go vet ./...

lint: tools
	@echo "Running staticcheck..."
	staticcheck ./...
	@echo "Running golangci-lint..."
	golangci-lint run

# -----------------------------
# Security checks
# -----------------------------
security: tools
	@echo "Running govulncheck..."
	govulncheck ./...

# -----------------------------
# Tests
# -----------------------------
test: tools
	@echo "Running tests with race detector and coverage..."
	go test -race -coverprofile=coverage.out -covermode=atomic ./...

# -----------------------------
# Full CI run (all checks)
# -----------------------------
ci: fmt vet lint security test
	@echo "All checks passed."
