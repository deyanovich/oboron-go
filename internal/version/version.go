// Package version holds the canonical version of the oboron-go module.
// The library and all three CLIs (ob, obz, obcrypt) share this single
// value, and uvar-version reads it (per .uvar-ci.yml) to derive the
// release git tag. Bump it when preparing a release.
package version

// Version is the module version, kept in sync with the git tag (vX.Y.Z).
const Version = "v0.3.0"
