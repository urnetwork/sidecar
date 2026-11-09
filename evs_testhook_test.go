//go:build sidecar_testhooks

// Under the tag, every key §11.6's format derives, draws or unwraps reaches the privacy harness's hook, by value and
// under its name, so §22.7's capture scan can look for each.

package sidecar

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
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

// §22.5's count per creation and unwrap: a segment's builder hooks its one object key as it draws it, a reader hooks
// it again as it unwraps the block, and records keyed by it hook nothing more; a deposit's reader hooks the key it
// opens from its slot and the K_dep it derives.
func TestEvsHookCountsObjectKeysPerCreationAndUnwrap(t *testing.T) {
	recorder := mlsRecordHooks(t)
	repoId := evsTestId("repo")
	keys := evsTestKeys(t, repoId, 2)
	objectKeyCount := func() int {
		return len(recorder.kindSecrets["object_key"])
	}
	out := &bytes.Buffer{}
	builder, err := NewEvsSegmentBuilder(out, keys.manifest, keys.fek)
	if err != nil {
		t.Fatal(err)
	}
	if objectKeyCount() != 1 {
		t.Fatalf("%d object keys hooked at the builder's draw", objectKeyCount())
	}
	recorder.require(t, "object_key", builder.ObjectKey().key)
	for i := range 3 {
		record, err := builder.BeginRecord(Id{}, evsTestHeader(fmt.Sprint(i), protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, 10))
		if err != nil {
			t.Fatal(err)
		}
		record.Write(evsTestBody(10))
		record.Close()
	}
	summary, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if objectKeyCount() != 1 {
		t.Errorf("%d object keys hooked after three records", objectKeyCount())
	}
	reader, err := NewEvsSegmentReader(bytes.NewReader(out.Bytes()), summary.PaddedSize, keys.fek)
	if err != nil {
		t.Fatal(err)
	}
	if objectKeyCount() != 2 {
		t.Errorf("%d object keys hooked after the unwrap", objectKeyCount())
	}
	for _, place := range summary.Places {
		if _, body, err := reader.OpenRecord(keys.manifest, place, Id{}, nil); err != nil {
			t.Fatal(err)
		} else {
			io.ReadAll(body)
		}
	}
	if objectKeyCount() != 2 {
		t.Errorf("%d object keys hooked after reading the records", objectKeyCount())
	}

	dropPrivateKey, err := evsTestRepoKey(repoId, 2).DropKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	depositKey := NewEvsObjectKey()
	wrapped, err := EvsWrapDepositKey(dropPrivateKey.PublicKey(), repoId, 2, depositKey)
	if err != nil {
		t.Fatal(err)
	}
	before := objectKeyCount()
	opened, err := EvsUnwrapDepositKey(dropPrivateKey, repoId, 2, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if objectKeyCount() != before+1 {
		t.Error("a deposit key's unwrap did not hook it")
	}
	depositManifest, err := NewEvsDepositManifestKey(repoId, 2, opened)
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "K_dep", depositManifest.key)
	inline, chainKey, err := EvsSealInlineRecord(keys.manifest, keys.fek, nil, Id{}, evsTestHeader("inline", protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, 0), evsTestBody(20))
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "object_key", chainKey.key)
	before = objectKeyCount()
	if _, _, _, err := EvsOpenInlineRecord(keys.manifest, keys.fek, nil, Id{}, inline); err != nil {
		t.Fatal(err)
	}
	if objectKeyCount() != before+1 {
		t.Error("an inline chain's unwrap did not hook its key")
	}
}
