# tamga-go dev tasks. Run `just` with no args to list recipes.

default:
    @just --list

# Run the full test suite with race detection and coverage.
test:
    go test ./... -race -cover

# Run golangci-lint (see .golangci.yml for the enabled linter set).
lint:
    golangci-lint run ./...

# Format all Go source (gofmt + goimports).
fmt:
    gofmt -l -w .
    goimports -w .

# Check formatting without writing changes (used in CI-equivalent local checks).
fmt-check:
    test -z "$(gofmt -l .)"

# Build every package, including internal/ and examples/.
build:
    go build ./...

# Full pre-PR gate: formatting, lint, tests. Mirrors (a subset of) CI —
# see CONTRIBUTING.md for how this differs from the authoritative CI gate.
check: fmt-check lint test
