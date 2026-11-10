// RECORD.md section 20's log vectors, testdata/record/log.json: leaves, roots, an inclusion path, a consistency path
// and the checkpoint's text, each computed here and held to the file, and each proof verified and then refused with
// one byte, the index or a size changed.

package sidecar_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
)

type testLogVectors struct {
	Leaves []struct {
		SignedBodyText string `json:"signed_body_text"`
		Leaf           string `json:"leaf"`
	} `json:"leaves"`
	Roots []struct {
		Size uint64 `json:"size"`
		Root string `json:"root"`
	} `json:"roots"`
	Inclusion []struct {
		Index uint64   `json:"index"`
		Size  uint64   `json:"size"`
		Path  []string `json:"path"`
	} `json:"inclusion"`
	Consistency []struct {
		First  uint64   `json:"first"`
		Second uint64   `json:"second"`
		Path   []string `json:"path"`
	} `json:"consistency"`
	Note struct {
		LogId string `json:"log_id"`
		Size  uint64 `json:"size"`
		Body  string `json:"body"`
	} `json:"note"`
}

// The vectors, and their leaves as the tree takes them.
func readTestLogVectors(t *testing.T) (*testLogVectors, [][sha256.Size]byte) {
	t.Helper()
	content, err := os.ReadFile("testdata/record/log.json")
	if err != nil {
		t.Fatal(err)
	}
	vectors := &testLogVectors{}
	if err := json.Unmarshal(content, vectors); err != nil {
		t.Fatal(err)
	}
	leaves := [][sha256.Size]byte{}
	for _, vector := range vectors.Leaves {
		leaf := sidecar.RecordLeafHash([]byte(vector.SignedBodyText))
		if hex.EncodeToString(leaf[:]) != vector.Leaf {
			t.Fatalf("leaf(%q) = %x, want %s", vector.SignedBodyText, leaf, vector.Leaf)
		}
		leaves = append(leaves, leaf)
	}
	return vectors, leaves
}

func testHexPath(path [][]byte) []string {
	texts := []string{}
	for _, hash := range path {
		texts = append(texts, hex.EncodeToString(hash))
	}
	return texts
}

func TestRecordLogVectorsRoots(t *testing.T) {
	vectors, leaves := readTestLogVectors(t)
	if len(vectors.Roots) == 0 {
		t.Fatal("no root vectors")
	}
	for _, vector := range vectors.Roots {
		root := sidecar.RecordLogRoot(leaves[:vector.Size])
		if hex.EncodeToString(root[:]) != vector.Root {
			t.Errorf("root at size %d = %x, want %s", vector.Size, root, vector.Root)
		}
	}
	empty := sidecar.RecordLogRoot(nil)
	if empty != sha256.Sum256(nil) {
		t.Errorf("the empty tree's root is %x", empty)
	}
}

func TestRecordLogVectorsInclusion(t *testing.T) {
	vectors, leaves := readTestLogVectors(t)
	if len(vectors.Inclusion) == 0 {
		t.Fatal("no inclusion vectors")
	}
	for _, vector := range vectors.Inclusion {
		path, err := sidecar.RecordLogInclusionPath(vector.Index, leaves[:vector.Size])
		if err != nil {
			t.Fatal(err)
		}
		if got := testHexPath(path); !slices.Equal(got, vector.Path) {
			t.Fatalf("inclusion path of %d at %d = %v, want %v", vector.Index, vector.Size, got, vector.Path)
		}
		root := sidecar.RecordLogRoot(leaves[:vector.Size])
		if !sidecar.RecordLogVerifyInclusion(leaves[vector.Index], vector.Index, vector.Size, path, root) {
			t.Errorf("the path of %d at %d does not verify", vector.Index, vector.Size)
		}
		if sidecar.RecordLogVerifyInclusion(leaves[vector.Index], vector.Index+1, vector.Size, path, root) {
			t.Errorf("the path verifies at another index")
		}
		if sidecar.RecordLogVerifyInclusion(leaves[0], vector.Index, vector.Size, path, root) {
			t.Errorf("the path verifies for another leaf")
		}
		altered := [][]byte{}
		for _, hash := range path {
			altered = append(altered, bytes.Clone(hash))
		}
		altered[0][0] ^= 1
		if sidecar.RecordLogVerifyInclusion(leaves[vector.Index], vector.Index, vector.Size, altered, root) {
			t.Errorf("an altered path verifies")
		}
		if sidecar.RecordLogVerifyInclusion(leaves[vector.Index], vector.Index, vector.Size, path[:len(path)-1], root) {
			t.Errorf("a cut path verifies")
		}
	}
}

func TestRecordLogVectorsConsistency(t *testing.T) {
	vectors, leaves := readTestLogVectors(t)
	if len(vectors.Consistency) == 0 {
		t.Fatal("no consistency vectors")
	}
	for _, vector := range vectors.Consistency {
		path, err := sidecar.RecordLogConsistencyPath(vector.First, leaves[:vector.Second])
		if err != nil {
			t.Fatal(err)
		}
		if got := testHexPath(path); !slices.Equal(got, vector.Path) {
			t.Fatalf("consistency path %d to %d = %v, want %v", vector.First, vector.Second, got, vector.Path)
		}
		firstRoot := sidecar.RecordLogRoot(leaves[:vector.First])
		secondRoot := sidecar.RecordLogRoot(leaves[:vector.Second])
		if !sidecar.RecordLogVerifyConsistency(vector.First, vector.Second, firstRoot, secondRoot, path) {
			t.Errorf("the path %d to %d does not verify", vector.First, vector.Second)
		}
		otherRoot := secondRoot
		otherRoot[0] ^= 1
		if sidecar.RecordLogVerifyConsistency(vector.First, vector.Second, firstRoot, otherRoot, path) {
			t.Errorf("the path verifies to another root")
		}
		if sidecar.RecordLogVerifyConsistency(vector.First, vector.Second, otherRoot, secondRoot, path) {
			t.Errorf("the path verifies from another root")
		}
	}
}

// Every pair of sizes up to 33 leaves: each inclusion and consistency path the tree gives verifies, and a tree that
// replaced one early leaf has no consistency path from the old root.
func TestRecordLogProofsVerifyAtEverySize(t *testing.T) {
	leaves := [][sha256.Size]byte{}
	for i := 0; i < 33; i += 1 {
		leaves = append(leaves, sidecar.RecordLeafHash([]byte{byte(i)}))
	}
	for size := uint64(1); size <= uint64(len(leaves)); size += 1 {
		root := sidecar.RecordLogRoot(leaves[:size])
		for index := uint64(0); index < size; index += 1 {
			path, err := sidecar.RecordLogInclusionPath(index, leaves[:size])
			if err != nil {
				t.Fatal(err)
			}
			if !sidecar.RecordLogVerifyInclusion(leaves[index], index, size, path, root) {
				t.Fatalf("inclusion of %d at %d does not verify", index, size)
			}
		}
		for first := uint64(0); first <= size; first += 1 {
			path, err := sidecar.RecordLogConsistencyPath(first, leaves[:size])
			if err != nil {
				t.Fatal(err)
			}
			firstRoot := sidecar.RecordLogRoot(leaves[:first])
			if !sidecar.RecordLogVerifyConsistency(first, size, firstRoot, root, path) {
				t.Fatalf("consistency %d to %d does not verify", first, size)
			}
			if 0 < first && first < size {
				rewritten := append([][sha256.Size]byte{}, leaves[:first]...)
				rewritten[0][0] ^= 1
				if sidecar.RecordLogVerifyConsistency(first, size, sidecar.RecordLogRoot(rewritten), root, path) {
					t.Fatalf("a rewritten tree of %d is consistent with size %d", first, size)
				}
			}
		}
	}
}

func TestRecordLogVectorsNoteText(t *testing.T) {
	vectors, leaves := readTestLogVectors(t)
	logId, err := hex.DecodeString(vectors.Note.LogId)
	if err != nil {
		t.Fatal(err)
	}
	root := sidecar.RecordLogRoot(leaves[:vectors.Note.Size])
	body := sidecar.RecordLogNoteBody(sidecar.RecordLogOrigin(sidecar.Id(logId)), vectors.Note.Size, root)
	if string(body) != vectors.Note.Body {
		t.Fatalf("note body %q, want %q", body, vectors.Note.Body)
	}
}
