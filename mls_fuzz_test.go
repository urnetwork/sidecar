//go:build !js

// Fuzz targets for everything mls_* decodes (§22.6). Native Go fuzzing, whose seeds run as ordinary
// tests under go test, and crashers land in testdata/fuzz/ as more seeds (owner decision 101). Not on
// js: testing.F reads its corpus directory before it runs a seed, and js has no directory to open.
//
// Each target holds decoding to what §22.6 asks of it: total, memory-bounded, and canonical, so that
// what decodes re-encodes to the same bytes. These targets check mls_* alone. The differential half of
// §22.6's row, against mls-go and tmc/mls, waits for mlsinterop/.

package sidecar

import (
	"bytes"
	"testing"
)

// Every input either fails or re-encodes to itself.
func mlsFuzzRoundTrip(t *testing.T, input []byte, value mlsDecodableEncodable) {
	t.Helper()
	if err := mlsUnmarshal(input, value); err != nil {
		return
	}
	encoded, err := mlsMarshal(value)
	if err != nil {
		t.Fatalf("decoded but cannot encode: %v", err)
	}
	if !bytes.Equal(encoded, input) {
		t.Fatalf("%x re-encoded as %x", input, encoded)
	}
}

// Every input either fails or re-encodes to the bytes it used: nothing decodes that a canonical
// encoder would not have produced, and no input panics.
func FuzzMlsCodecIsCanonical(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte{0x03, 0x01, 0x02, 0x03})
	f.Add([]byte{0x40, 0x40})
	f.Add([]byte{0x40, 0x3f})
	f.Add([]byte{0x80, 0x00, 0x40, 0x00})
	f.Add([]byte{0xc0})
	f.Add([]byte{0x02, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, input []byte) {
		decoder := &mlsDecoder{remaining: input}
		length := decoder.readLength()
		if decoder.err != nil {
			return
		}
		used := input[:len(input)-len(decoder.remaining)]
		encoder := &mlsEncoder{}
		encoder.writeLength(length)
		encoded, err := encoder.finish()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, used) {
			t.Fatalf("header %x decoded as %d, which encodes as %x", used, length, encoded)
		}

		var elements [][]byte
		vectors := &mlsDecoder{remaining: input}
		vectors.readVectorOf(func(element *mlsDecoder) {
			elements = append(elements, element.readVector())
		})
		if vectors.err != nil {
			return
		}
		used = input[:len(input)-len(vectors.remaining)]
		encoder = &mlsEncoder{}
		encoder.writeVectorOf(func(writer *mlsEncoder) {
			for _, element := range elements {
				writer.writeVector(element)
			}
		})
		encoded, err = encoder.finish()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, used) {
			t.Fatalf("vector %x re-encoded as %x", used, encoded)
		}
	})
}

// Seeds from the mlswg's trees, cut down to the suite this package runs.
func mlsFuzzSeedTrees(f *testing.F) [][]byte {
	f.Helper()
	var vectors []struct {
		CipherSuite uint16      `json:"cipher_suite"`
		Tree        mlsHexBytes `json:"tree"`
	}
	mlsLoadVectors(f, "tree-validation", &vectors)
	var seeds [][]byte
	for _, vector := range vectors {
		if vector.CipherSuite == mlsCipherSuiteX25519 {
			seeds = append(seeds, vector.Tree)
		}
	}
	return seeds
}

// A tree off the wire, through everything that may touch it before validate refuses it.
func FuzzMlsRatchetTree(f *testing.F) {
	for _, seed := range mlsFuzzSeedTrees(f) {
		f.Add(seed)
	}
	f.Add([]byte{0})
	f.Add([]byte{1, 0})
	f.Add([]byte{2, 1, 3})
	f.Add(mlsTestTreeListingALeafOutside(f))
	settings := mlsVectorTreeSettings()
	settings.MaximumLeafCount = 64
	validation := mlsTestLeafValidation([]byte("group"))
	f.Fuzz(func(t *testing.T, input []byte) {
		suite := mlsTestSuiteX25519
		tree, err := decodeMlsRatchetTree(suite, settings, input)
		if err != nil {
			return
		}
		encoded, err := mlsMarshal(tree)
		if err != nil {
			t.Fatalf("decoded but cannot encode: %v", err)
		}
		if !bytes.Equal(encoded, input) {
			t.Fatalf("%x re-encoded as %x", input, encoded)
		}

		// nothing a peer's tree holds may panic before validation has refused it
		if _, err := tree.treeHash(); err != nil {
			t.Fatal(err)
		}
		for index := range tree.nodes {
			tree.resolution(mlsNodeIndex(index))
			if !mlsNodeIndex(index).isLeaf() && tree.nodes[index].parent != nil {
				tree.validateUnmergedLeaves(mlsNodeIndex(index))
			}
		}
		for index := range tree.leafCount() {
			tree.filteredDirectPath(mlsLeafIndex(index))
		}
		tree.verifyParentHashes()
		tree.validate(validation)
		clone := tree.clone()
		if leaf := clone.leafNode(0); leaf != nil {
			clone.removeLeaf(0)
		}
	})
}

// A leaf alone, as a KeyPackage or an UpdatePath delivers it.
func FuzzMlsLeafNode(f *testing.F) {
	for _, seed := range mlsFuzzSeedTrees(f) {
		// a tree's first entry is a vector header, a presence octet, a node type and a leaf
		f.Add(seed[min(len(seed), 3):])
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		mlsFuzzRoundTrip(t, input, &mlsLeafNode{})
	})
}

// A KeyPackage, public by design, so anyone can feed one in.
func FuzzMlsKeyPackage(f *testing.F) {
	var vectors []struct {
		AddProposal mlsHexBytes `json:"add_proposal"`
	}
	mlsLoadVectors(f, "messages", &vectors)
	for _, vector := range vectors[:min(len(vectors), 8)] {
		f.Add([]byte(vector.AddProposal))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		mlsFuzzRoundTrip(t, input, &mlsKeyPackage{})
	})
}

// The subset's proposals, and the refusal of the rest.
func FuzzMlsProposal(f *testing.F) {
	f.Add([]byte{0, 3, 0, 0, 0, 1})
	f.Add([]byte{0, 6, 2, 1, 2})
	f.Add([]byte{0, 7, 0})
	f.Add([]byte{0, 2})
	f.Fuzz(func(t *testing.T, input []byte) {
		mlsFuzzRoundTrip(t, input, &mlsProposal{})
	})
}

// A commit's path.
func FuzzMlsUpdatePath(f *testing.F) {
	var vectors []struct {
		CipherSuite uint16 `json:"cipher_suite"`
		UpdatePaths []struct {
			UpdatePath mlsHexBytes `json:"update_path"`
		} `json:"update_paths"`
	}
	mlsLoadVectors(f, "treekem", &vectors)
	for _, vector := range vectors {
		if vector.CipherSuite == mlsCipherSuiteX25519 {
			f.Add([]byte(vector.UpdatePaths[0].UpdatePath))
		}
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		mlsFuzzRoundTrip(t, input, &mlsUpdatePath{})
	})
}

// The GroupContext a GroupInfo carries.
func FuzzMlsGroupContext(f *testing.F) {
	var vectors []struct {
		CipherSuite uint16 `json:"cipher_suite"`
		Epochs      []struct {
			GroupContext mlsHexBytes `json:"group_context"`
		} `json:"epochs"`
	}
	mlsLoadVectors(f, "key-schedule", &vectors)
	for _, vector := range vectors {
		if vector.CipherSuite == mlsCipherSuiteX25519 {
			f.Add([]byte(vector.Epochs[0].GroupContext))
		}
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		mlsFuzzRoundTrip(t, input, &mlsGroupContext{})
	})
}

// Capabilities, whose lists may hold anything.
func FuzzMlsCapabilities(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0})
	f.Add([]byte{2, 0, 1, 2, 0, 16, 0, 0, 2, 0, 1})
	f.Fuzz(func(t *testing.T, input []byte) {
		mlsFuzzRoundTrip(t, input, &mlsCapabilities{})
	})
}

// Credentials, where one wrong type must not desynchronize a parse.
func FuzzMlsCredential(f *testing.F) {
	f.Add([]byte{0, 1, 2, 'i', 'd'})
	f.Add([]byte{0xf5, 0x52, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		mlsFuzzRoundTrip(t, input, &mlsCredential{})
	})
}
