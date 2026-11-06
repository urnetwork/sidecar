// The secret tree against the mlswg's secret-tree vectors under 0x0001, then §9.2's deletion schedule
// and the ratchets' refusals under both suites.

package sidecar

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestMlsSecretTreeVectors(t *testing.T) {
	var vectors []struct {
		CipherSuite uint16 `json:"cipher_suite"`
		SenderData  struct {
			SenderDataSecret mlsHexBytes `json:"sender_data_secret"`
			Ciphertext       mlsHexBytes `json:"ciphertext"`
			Key              mlsHexBytes `json:"key"`
			Nonce            mlsHexBytes `json:"nonce"`
		} `json:"sender_data"`
		EncryptionSecret mlsHexBytes `json:"encryption_secret"`
		Leaves           [][]struct {
			Generation       uint32      `json:"generation"`
			HandshakeKey     mlsHexBytes `json:"handshake_key"`
			HandshakeNonce   mlsHexBytes `json:"handshake_nonce"`
			ApplicationKey   mlsHexBytes `json:"application_key"`
			ApplicationNonce mlsHexBytes `json:"application_nonce"`
		} `json:"leaves"`
	}
	mlsLoadVectors(t, "secret-tree", &vectors)

	suite := mlsTestSuiteX25519
	settings := defaultMlsSecretTreeSettings()
	ran := 0
	for _, vector := range vectors {
		if vector.CipherSuite != suite.value {
			continue
		}
		ran++

		key, nonce, err := suite.deriveSenderDataKey(vector.SenderData.SenderDataSecret, vector.SenderData.Ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(key, vector.SenderData.Key) {
			t.Errorf("sender data key %x, want %x", key, vector.SenderData.Key)
		}
		if !bytes.Equal(nonce, vector.SenderData.Nonce) {
			t.Errorf("sender data nonce %x, want %x", nonce, vector.SenderData.Nonce)
		}

		tree, err := newMlsSecretTree(suite, settings, vector.EncryptionSecret, uint32(len(vector.Leaves)))
		if err != nil {
			t.Fatal(err)
		}
		for leaf, generations := range vector.Leaves {
			ratchets, err := tree.ratchets(mlsLeafIndex(leaf))
			if err != nil {
				t.Fatal(err)
			}
			for _, generation := range generations {
				handshake, err := ratchets.handshake.stepTo(generation.Generation)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(handshake.key, generation.HandshakeKey) {
					t.Errorf("leaf %d generation %d: handshake key %x", leaf, generation.Generation, handshake.key)
				}
				if !bytes.Equal(handshake.nonce, generation.HandshakeNonce) {
					t.Errorf("leaf %d generation %d: handshake nonce %x", leaf, generation.Generation, handshake.nonce)
				}
				handshake.consume()

				application, err := ratchets.application.stepTo(generation.Generation)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(application.key, generation.ApplicationKey) {
					t.Errorf("leaf %d generation %d: application key %x", leaf, generation.Generation, application.key)
				}
				if !bytes.Equal(application.nonce, generation.ApplicationNonce) {
					t.Errorf("leaf %d generation %d: application nonce %x", leaf, generation.Generation, application.nonce)
				}
				application.consume()
			}
		}
	}
	if ran == 0 {
		t.Fatal("no vector for suite 0x0001")
	}
}

// A tree of eight leaves on a fixed secret, for the tests below.
func mlsNewTestSecretTree(t *testing.T, suite *mlsCipherSuite) *mlsSecretTree {
	t.Helper()
	tree, err := newMlsSecretTree(suite, defaultMlsSecretTreeSettings(), bytes.Repeat([]byte{0x5a}, suite.hashLength), 8)
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func mlsTestHandshakeRatchet(t *testing.T, tree *mlsSecretTree, leaf mlsLeafIndex) *mlsSenderRatchet {
	t.Helper()
	ratchets, err := tree.ratchets(leaf)
	if err != nil {
		t.Fatal(err)
	}
	return ratchets.handshake
}

// A sender and every receiver reach one key per generation from the same epoch secret, each in its
// own tree, the way two members do.
func TestMlsSecretTreeSenderAndReceiverAgree(t *testing.T) {
	for _, suite := range mlsTestSuites {
		sender := mlsTestHandshakeRatchet(t, mlsNewTestSecretTree(t, suite), 3)
		receiver := mlsTestHandshakeRatchet(t, mlsNewTestSecretTree(t, suite), 3)
		for expected := uint32(0); expected < 5; expected++ {
			generation, key, nonce, err := sender.next()
			if err != nil {
				t.Fatal(err)
			}
			if generation != expected {
				t.Fatalf("generation %d, want %d", generation, expected)
			}
			if len(key) != suite.aeadKeyLength || len(nonce) != suite.aeadNonceLength {
				t.Fatalf("key of %d bytes, nonce of %d", len(key), len(nonce))
			}
			step, err := receiver.stepTo(generation)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(step.key, key) || !bytes.Equal(step.nonce, nonce) {
				t.Fatalf("generation %d: the sides disagree", generation)
			}
			step.consume()
		}
	}
}

func TestMlsLeavesAndRatchetsHaveDifferentKeys(t *testing.T) {
	tree := mlsNewTestSecretTree(t, mlsSuite)
	seenKeys := map[string]bool{}
	for leaf := mlsLeafIndex(0); leaf < 8; leaf++ {
		ratchets, err := tree.ratchets(leaf)
		if err != nil {
			t.Fatal(err)
		}
		for _, ratchet := range []*mlsSenderRatchet{ratchets.handshake, ratchets.application} {
			for range 3 {
				_, key, _, err := ratchet.next()
				if err != nil {
					t.Fatal(err)
				}
				if seenKeys[string(key)] {
					t.Fatalf("leaf %d repeated a key", leaf)
				}
				seenKeys[string(key)] = true
			}
		}
	}
}

// Nothing a sender does can reuse a generation: the ratchet moved before the key came back.
func TestMlsSenderNeverReusesAGeneration(t *testing.T) {
	ratchet := mlsTestHandshakeRatchet(t, mlsNewTestSecretTree(t, mlsSuite), 0)
	first, _, _, err := ratchet.next()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ratchet.stepTo(first); !errors.Is(err, errMlsGeneration) {
		t.Fatalf("the sender's used generation is still reachable: %v", err)
	}
	second, _, _, err := ratchet.next()
	if err != nil {
		t.Fatal(err)
	}
	if second != first+1 {
		t.Fatalf("generation %d after %d", second, first)
	}
}

func TestMlsConsumedGenerationIsRefused(t *testing.T) {
	ratchet := mlsTestHandshakeRatchet(t, mlsNewTestSecretTree(t, mlsSuite), 1)
	step, err := ratchet.stepTo(4)
	if err != nil {
		t.Fatal(err)
	}
	step.consume()
	for _, generation := range []uint32{0, 3, 4} {
		if _, err := ratchet.stepTo(generation); !errors.Is(err, errMlsGeneration) {
			t.Errorf("generation %d: %v", generation, err)
		}
	}
	if _, err := ratchet.stepTo(5); err != nil {
		t.Errorf("the next generation: %v", err)
	}
}

// A forged message names a generation and fails its AEAD: the real one must still open.
func TestMlsDiscardedStepLeavesTheRatchetAlone(t *testing.T) {
	ratchet := mlsTestHandshakeRatchet(t, mlsNewTestSecretTree(t, mlsSuite), 1)
	forged, err := ratchet.stepTo(7)
	if err != nil {
		t.Fatal(err)
	}
	wantKey := bytes.Clone(forged.key)
	forged.discard()

	if ratchet.generation != 0 {
		t.Fatalf("generation %d", ratchet.generation)
	}
	real, err := ratchet.stepTo(0)
	if err != nil {
		t.Fatal(err)
	}
	real.consume()
	again, err := ratchet.stepTo(7)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.key, wantKey) {
		t.Fatal("a discarded step changed later keys")
	}
}

func TestMlsForwardDistanceIsBounded(t *testing.T) {
	settings := &mlsSecretTreeSettings{MaximumForwardDistance: 5}
	tree, err := newMlsSecretTree(mlsSuite, settings, make([]byte, mlsSuite.hashLength), 1)
	if err != nil {
		t.Fatal(err)
	}
	ratchet := mlsTestHandshakeRatchet(t, tree, 0)
	if _, err := ratchet.stepTo(6); !errors.Is(err, errMlsGeneration) {
		t.Fatalf("distance 6: %v", err)
	}
	if _, err := ratchet.stepTo(math.MaxUint32); !errors.Is(err, errMlsGeneration) {
		t.Fatalf("the last generation: %v", err)
	}
	if ratchet.generation != 0 {
		t.Fatalf("a refusal moved the ratchet to %d", ratchet.generation)
	}
	step, err := ratchet.stepTo(5)
	if err != nil {
		t.Fatal(err)
	}
	step.consume()
	// the distance runs from the next unused generation, now 6
	if _, err := ratchet.stepTo(12); !errors.Is(err, errMlsGeneration) {
		t.Fatalf("distance 6: %v", err)
	}
	if _, err := ratchet.stepTo(11); err != nil {
		t.Fatalf("distance 5: %v", err)
	}
}

func TestMlsZeroForwardDistanceTakesOnlyTheNextGeneration(t *testing.T) {
	settings := &mlsSecretTreeSettings{MaximumForwardDistance: 0}
	tree, err := newMlsSecretTree(mlsSuite, settings, make([]byte, mlsSuite.hashLength), 1)
	if err != nil {
		t.Fatal(err)
	}
	ratchet := mlsTestHandshakeRatchet(t, tree, 0)
	if _, err := ratchet.stepTo(1); !errors.Is(err, errMlsGeneration) {
		t.Fatal(err)
	}
	if _, err := ratchet.stepTo(0); err != nil {
		t.Fatal(err)
	}
}

// Past uint32 a ratchet would wrap to a generation it already used.
func TestMlsGenerationDoesNotWrap(t *testing.T) {
	ratchet := mlsTestHandshakeRatchet(t, mlsNewTestSecretTree(t, mlsSuite), 0)
	ratchet.generation = math.MaxUint32 - 1
	generation, _, _, err := ratchet.next()
	if err != nil {
		t.Fatal(err)
	}
	if generation != math.MaxUint32-1 {
		t.Fatalf("generation %d", generation)
	}
	if _, _, _, err := ratchet.next(); !errors.Is(err, errMlsGeneration) {
		t.Fatal(err)
	}
	if ratchet.generation != math.MaxUint32 {
		t.Fatalf("generation %d", ratchet.generation)
	}
}

// Two steps taken apart: consuming the later one first must not let the earlier one rewind.
func TestMlsStaleStepCannotMoveTheRatchetBack(t *testing.T) {
	ratchet := mlsTestHandshakeRatchet(t, mlsNewTestSecretTree(t, mlsSuite), 0)
	early, err := ratchet.stepTo(2)
	if err != nil {
		t.Fatal(err)
	}
	late, err := ratchet.stepTo(5)
	if err != nil {
		t.Fatal(err)
	}
	late.consume()
	early.consume()
	if ratchet.generation != 6 {
		t.Fatalf("generation %d", ratchet.generation)
	}
	if !bytes.Equal(early.key, make([]byte, len(early.key))) {
		t.Fatal("the stale step kept its key")
	}
}

// §9.2: consuming a generation overwrites the secrets behind it.
func TestMlsRatchetOverwritesConsumedSecrets(t *testing.T) {
	ratchet := mlsTestHandshakeRatchet(t, mlsNewTestSecretTree(t, mlsSuite), 0)
	before := ratchet.secret
	step, err := ratchet.stepTo(0)
	if err != nil {
		t.Fatal(err)
	}
	key := step.key
	nonce := step.nonce
	if bytes.Equal(before, make([]byte, len(before))) {
		t.Fatal("the secret went before the step was consumed")
	}
	step.consume()
	zero := make([]byte, mlsSuite.hashLength)
	if !bytes.Equal(before, zero) {
		t.Errorf("old ratchet secret survived: %x", before)
	}
	if !bytes.Equal(key, zero[:len(key)]) || !bytes.Equal(nonce, zero[:len(nonce)]) {
		t.Error("the consumed key or nonce survived")
	}
	if bytes.Equal(ratchet.secret, zero) {
		t.Error("the ratchet lost its next secret")
	}
}

// §9.2's example, on an eight-leaf tree: deriving leaf 3's ratchets consumes the root and everything
// on leaf 3's path, and leaves exactly its copath.
func TestMlsTreeSecretsFollowTheDeletionSchedule(t *testing.T) {
	suite := mlsSuite
	tree := mlsNewTestSecretTree(t, suite)
	root := mlsTreeRoot(8)
	rootSecret := tree.nodeIndexSecrets[root]

	if _, err := tree.ratchets(3); err != nil {
		t.Fatal(err)
	}

	zero := make([]byte, suite.hashLength)
	if !bytes.Equal(rootSecret, zero) {
		t.Error("the root secret survived")
	}
	if _, ok := tree.nodeIndexSecrets[root]; ok {
		t.Error("the root is still in the frontier")
	}
	leafNode := mlsLeafIndex(3).node()
	for _, node := range append(leafNode.directPath(8), leafNode) {
		if _, ok := tree.nodeIndexSecrets[node]; ok {
			t.Errorf("node %d on the path is still in the frontier", node)
		}
	}
	copath := leafNode.copath(8)
	if len(tree.nodeIndexSecrets) != len(copath) {
		t.Errorf("frontier of %d nodes, want the copath's %d", len(tree.nodeIndexSecrets), len(copath))
	}
	for _, node := range copath {
		if _, ok := tree.nodeIndexSecrets[node]; !ok {
			t.Errorf("copath node %d is missing", node)
		}
	}
}

// Consuming one leaf's path must not cost any other leaf its secret.
func TestMlsEveryLeafStaysReachable(t *testing.T) {
	suite := mlsSuite
	tree := mlsNewTestSecretTree(t, suite)
	order := []mlsLeafIndex{5, 0, 7, 2, 3, 1, 6, 4}
	keys := map[mlsLeafIndex][]byte{}
	for _, leaf := range order {
		_, key, _, err := mlsTestHandshakeRatchet(t, tree, leaf).next()
		if err != nil {
			t.Fatal(err)
		}
		keys[leaf] = key
	}
	if len(tree.nodeIndexSecrets) != 0 {
		t.Errorf("%d secrets left in the frontier", len(tree.nodeIndexSecrets))
	}

	inOrder := mlsNewTestSecretTree(t, suite)
	for leaf := mlsLeafIndex(0); leaf < 8; leaf++ {
		_, key, _, err := mlsTestHandshakeRatchet(t, inOrder, leaf).next()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(key, keys[leaf]) {
			t.Errorf("leaf %d's key depends on the order of use", leaf)
		}
	}
}

func TestMlsRatchetsAreDerivedOnce(t *testing.T) {
	tree := mlsNewTestSecretTree(t, mlsSuite)
	first, err := tree.ratchets(2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := tree.ratchets(2)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("a second call restarted the ratchets")
	}
}

func TestMlsSecretTreeRefusesLeavesOutsideIt(t *testing.T) {
	tree := mlsNewTestSecretTree(t, mlsSuite)
	for _, leaf := range []mlsLeafIndex{8, 9, math.MaxUint32} {
		if _, err := tree.ratchets(leaf); err == nil {
			t.Errorf("leaf %d in a tree of 8", leaf)
		}
	}
}

func TestMlsSecretTreeRefusesBadLeafCounts(t *testing.T) {
	settings := defaultMlsSecretTreeSettings()
	secret := make([]byte, mlsSuite.hashLength)
	for _, leafCount := range []uint32{0, 3, 1000} {
		if _, err := newMlsSecretTree(mlsSuite, settings, secret, leafCount); err == nil {
			t.Errorf("a tree of %d leaves", leafCount)
		}
	}
}

func TestMlsSecretTreeCopiesItsInput(t *testing.T) {
	settings := defaultMlsSecretTreeSettings()
	secret := bytes.Repeat([]byte{1}, mlsSuite.hashLength)
	tree, err := newMlsSecretTree(mlsSuite, settings, secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	clear(secret)
	if bytes.Equal(tree.nodeIndexSecrets[0], secret) {
		t.Fatal("the tree shares the caller's buffer")
	}
}

func TestMlsEraseClearsTheTree(t *testing.T) {
	tree := mlsNewTestSecretTree(t, mlsSuite)
	ratchets, err := tree.ratchets(0)
	if err != nil {
		t.Fatal(err)
	}
	ratchetSecret := ratchets.handshake.secret
	frontierSecret := tree.nodeIndexSecrets[mlsLeafIndex(1).node()]
	tree.erase()
	zero := make([]byte, mlsSuite.hashLength)
	if !bytes.Equal(ratchetSecret, zero) || !bytes.Equal(frontierSecret, zero) {
		t.Fatal("a secret survived")
	}
	if len(tree.nodeIndexSecrets) != 0 || len(tree.leafIndexRatchets) != 0 {
		t.Fatal("the tree still lists secrets")
	}
	if _, err := tree.ratchets(0); err == nil {
		t.Fatal("an erased tree gave ratchets")
	}
}

// Only the first KDF.Nh bytes of the ciphertext are sampled, and a shorter ciphertext is taken whole.
func TestMlsSenderDataKeySample(t *testing.T) {
	for _, suite := range mlsTestSuites {
		secret := bytes.Repeat([]byte{8}, suite.hashLength)
		sample := bytes.Repeat([]byte{9}, suite.hashLength)
		short, shortNonce, err := suite.deriveSenderDataKey(secret, sample)
		if err != nil {
			t.Fatal(err)
		}
		long, longNonce, err := suite.deriveSenderDataKey(secret, append(bytes.Clone(sample), 1, 2, 3))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(short, long) || !bytes.Equal(shortNonce, longNonce) {
			t.Errorf("suite %#x: bytes past the sample moved the key", suite.value)
		}
		shorter, _, err := suite.deriveSenderDataKey(secret, sample[:4])
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(short, shorter) {
			t.Errorf("suite %#x: a short ciphertext reused the key", suite.value)
		}
		if len(short) != suite.aeadKeyLength || len(shortNonce) != suite.aeadNonceLength {
			t.Errorf("suite %#x: key of %d bytes, nonce of %d", suite.value, len(short), len(shortNonce))
		}
	}
}
