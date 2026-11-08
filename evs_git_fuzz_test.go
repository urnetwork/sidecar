//go:build !js

// What the git codec's tests need a file system for, off the sidecar_http leg, whose Worker has none:
// §22.6's targets, over the checks and seeds in evs_git_test.go, which read go test's corpus
// directory, and the read of the codec's own source.

package sidecar

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The codec links on every leg, mobile and wasm among them, so it takes nothing but the standard
// library, and it never runs git.
func TestEvsGitCodecNeedsOnlyTheStandardLibrary(t *testing.T) {
	for _, goFile := range []string{"evs_git_object.go", "evs_git_delta.go", "evs_git_pktline.go"} {
		for _, importSpec := range parseGoFile(t, goFile).Imports {
			importPath, err := strconv.Unquote(importSpec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(importPath, ".") || slices.Contains([]string{"os", "os/exec", "syscall", "net", "unsafe"}, importPath) {
				t.Errorf("%s imports %s", goFile, importPath)
			}
		}
	}
}

func FuzzEvsPktLine(f *testing.F) {
	for _, seed := range evsGitPktLineSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, stream []byte) {
		checkEvsPktLineStream(t, stream)
	})
}

func FuzzEvsGitDeltaApply(f *testing.F) {
	for _, seed := range evsGitDeltaApplySeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		checkEvsGitDeltaApply(t, input)
	})
}

func FuzzEvsGitDeltaRoundTrip(f *testing.F) {
	for _, seed := range evsGitDeltaRoundTripSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		checkEvsGitDeltaRoundTrip(t, input)
	})
}

func FuzzEvsGitTreeDecode(f *testing.F) {
	for _, seed := range evsGitTreeSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		checkEvsGitTreeDecode(t, encoded)
	})
}

func FuzzEvsGitCommitDecode(f *testing.F) {
	for _, seed := range evsGitCommitSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		checkEvsGitCommitDecode(t, encoded)
	})
}

func FuzzEvsGitIdentDecode(f *testing.F) {
	for _, seed := range evsGitIdentSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		checkEvsGitIdentDecode(t, encoded)
	})
}
