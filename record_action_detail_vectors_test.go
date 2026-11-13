//go:build !js && !ios_extension

// Section 20's detail vectors (testdata/record/hashes.json; QD-771) opened as an approver opens them: each stored
// action's sealed_detail opens, under the context its own stored bytes derive in the vector's network, with the
// vector's config key, to the vector's detail, and in another network to nothing. record_hash_test.go recomputes the
// vectors' derived values by hand. The js leg opens no files, so this stays off it, as it does the ios_extension legs,
// which open no detail.

package sidecar

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Each detail vector opens to its detail beside its own stored bytes, and fails in another network.
func TestCanonicalActionDetailVectorsOpen(t *testing.T) {
	encoded, err := os.ReadFile(testRecordVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	vectors := &testRecordVectors{}
	if err := json.Unmarshal(encoded, vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.DetailSeal) == 0 {
		t.Fatal("no detail vectors")
	}
	for _, vector := range vectors.DetailSeal {
		stored, err := parseStoredCanonicalAction(testRecordHex(t, vector.Stored), testRecordVersionsKnown(1, 3, 4))
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		repoKey := &EvsRepoKey{
			repoId: Id(testRecordHex(t, vector.RepoId)), generation: vector.Generation, repoKey: testRecordHex(t, vector.RepoKey),
		}
		repoKeyAt := testConfigSealKeyAt(repoKey)
		want := &protocol.CanonicalActionDetail{}
		if err := proto.Unmarshal(testRecordHex(t, vector.Detail), want); err != nil {
			t.Fatal(err)
		}
		detail, err := OpenCanonicalActionDetail(stored, Id(testRecordHex(t, vector.NetworkId)), repoKeyAt)
		if err != nil || !proto.Equal(detail, want) {
			t.Errorf("%s: opened %+v, %v", vector.Name, detail, err)
		}
		if _, err := OpenCanonicalActionDetail(stored, testConfigId("another network"), repoKeyAt); !errors.Is(err, ErrConfigSealInvalid) {
			t.Errorf("%s in another network: %v", vector.Name, err)
		}
	}
}
