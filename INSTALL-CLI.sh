#!/bin/bash -
set -e

echo 'Building oboron CLIs...' >&2

# The version is the in-code const (internal/version/version.go).

# Build ob (core CLI — authenticated schemes)
go install ./cmd/ob
echo "✓ ob installed to $(go env GOPATH)/bin/ob" >&2

# Build obu (unauthenticated layer CLI — upcbc, zdcbc)
go install ./cmd/obu
echo "✓ obu installed to $(go env GOPATH)/bin/obu" >&2

# Build obcrypt (crypto core CLI — bytes-in/bytes-out)
go install ./cmd/obcrypt
echo "✓ obcrypt installed to $(go env GOPATH)/bin/obcrypt" >&2

echo "" >&2
echo "Try it out:" >&2
echo "  ob --version" >&2
echo "  obu --version" >&2
echo "  obcrypt --version" >&2

