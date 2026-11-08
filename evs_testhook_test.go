//go:build sidecar_testhooks

// Under the tag, every key §11.6's format derives, draws or unwraps reaches the privacy harness's hook, by value and
// under its name, so §22.7's capture scan can look for each.

package sidecar

import (
	"testing"
)

func TestEvsHookSeesEveryFormatDerivation(t *testing.T) {
	recorder := mlsRecordHooks(t)
	repoKey := evsTestRepoKey(evsTestId("repo"), 2)
	pathKey, err := NewEvsPathKey(repoKey)
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "K_path", pathKey.key)
	refKey, err := NewEvsRefKey(repoKey)
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "K_ref", refKey.key)
	manifestKey, err := NewEvsManifestKey(repoKey)
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "K_manifest", manifestKey.key)
	fekKey, err := NewEvsFekKey(repoKey)
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "K_fek", fekKey.key)
}
