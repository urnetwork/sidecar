//go:build !js

// FuzzCompileAcl (§22.6) itself, apart from its checks: go's fuzz corpus reader needs a file system, which the
// sidecar_http Worker has none of, so that leg runs the same seeds through TestCompileAclFuzzSeedsHold instead.

package sidecar

import (
	"testing"
)

func FuzzCompileAcl(f *testing.F) {
	for _, seed := range aclCompileFuzzSeeds() {
		f.Add([]byte(seed))
	}
	f.Fuzz(testAclCompileSourceHolds)
}
