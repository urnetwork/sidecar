//go:build !js

// §22.6's targets for the git codec, each over the checks and seeds in evs_git_test.go. Off the
// sidecar_http leg, whose Worker has no file system for go test's corpus directory.

package sidecar

import (
	"testing"
)

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
