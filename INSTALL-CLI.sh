#!/bin/bash -
set -e

echo 'Building oboron CLIs...' >&2

# Get commit hash (needed for version logic)
COMMIT=$(git rev-parse --short HEAD 2> /dev/null || echo "unknown")

# Check if there are uncommitted changes
if [[ -n $(git status --porcelain) ]]; then
  # Uncommitted changes detected, use "dev" as version
  V="dev"
else
  # Clean status, get version from git tag or use commit hash
  V=$(git describe --tags --exact-match --match "v*.*" 2> /dev/null || echo "$COMMIT")
fi

# Get build time
BUILD_TIME=$(date -u '+%Y-%m-%d %H:%M:%S UTC')

echo "Version:    $V" >&2
echo "Commit:     $COMMIT" >&2
echo "Build time: $BUILD_TIME" >&2
echo "" >&2

LDFLAGS="-X 'main.Version=$V' -X 'main.Commit=$COMMIT' -X 'main.BuildTime=$BUILD_TIME'"

# Build ob (main CLI - secure schemes)
go install -ldflags "$LDFLAGS" ./cmd/ob
echo "✓ ob installed to $(go env GOPATH)/bin/ob" >&2

# Build obz (z-tier CLI - obfuscation schemes)
go install -ldflags "$LDFLAGS" ./cmd/obz
echo "✓ obz installed to $(go env GOPATH)/bin/obz" >&2

# Build obcrypt (crypto core CLI - bytes-in/bytes-out, a-tier + u-tier)
go install -ldflags "$LDFLAGS" ./cmd/obcrypt
echo "✓ obcrypt installed to $(go env GOPATH)/bin/obcrypt" >&2

echo "" >&2
echo "Try it out:" >&2
echo "  ob --version" >&2
echo "  obz --version" >&2
echo "  obcrypt --version" >&2

