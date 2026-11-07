// Fixed inputs and the exact bytes they give, on every leg (§22.5), so a build whose encoding or
// derivation moves fails here, wasm's included. A format change regenerates the file:
//
//	go test -run TestKeychainVectors . -args -update-keychain-vectors
//
// which is a format change, and is read as one in review. The Worker has no file system, so the vectors
// are embedded.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"
)

//go:embed testdata/keychain/vectors.json
var keychainVectorsJson []byte

var updateKeychainVectors = flag.Bool("update-keychain-vectors", false, "rewrite testdata/keychain/vectors.json")

// A hex string, so the file stays readable by another implementation.
type hexBytes []byte

// As a hex string.
func (self hexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(self))
}

// From a hex string.
func (self *hexBytes) UnmarshalJSON(src []byte) error {
	var encoded string
	if err := json.Unmarshal(src, &encoded); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return err
	}
	*self = decoded
	return nil
}

// One file class's key.
type localKeyVector struct {
	Secret hexBytes `json:"secret"`
	Class  string   `json:"class"`
	Key    hexBytes `json:"key"`
}

// One sealed file. Sealed holds a short file whole. A long one is sealTestPlaintext of
// PlaintextByteCount, and SealedSha256 pins it.
type sealedFileVector struct {
	Key                hexBytes `json:"key"`
	Class              string   `json:"class"`
	Path               string   `json:"path"`
	Generation         uint64   `json:"generation"`
	NoncePrefix        hexBytes `json:"nonce_prefix"`
	Plaintext          hexBytes `json:"plaintext,omitempty"`
	PlaintextByteCount int      `json:"plaintext_byte_count,omitempty"`
	Sealed             hexBytes `json:"sealed,omitempty"`
	SealedSha256       hexBytes `json:"sealed_sha256,omitempty"`
}

// keychain.ur's plaintext.
type recordsVector struct {
	NameValues map[string]hexBytes `json:"name_values"`
	Encoded    hexBytes            `json:"encoded"`
}

// One unlock.wrap, made from the keys here with Random as its only draw.
type unlockWrapVector struct {
	UnlockKey       hexBytes `json:"unlock_key"`
	PreviousKey     hexBytes `json:"previous_key"`
	StoreKey        hexBytes `json:"store_key"`
	Pass            string   `json:"pass"`
	Generation      uint64   `json:"generation"`
	StoreGeneration uint64   `json:"store_generation"`
	MemoryKibiCount uint32   `json:"memory_kibi_count"`
	IterationCount  uint32   `json:"iteration_count"`
	ThreadCount     uint8    `json:"thread_count"`
	Random          hexBytes `json:"random"`
	Encoded         hexBytes `json:"encoded"`
}

// One keychain.wrap, with two roots, as in a rotation.
type keychainWrapVector struct {
	NetworkId        hexBytes `json:"network_id"`
	UnlockKey        hexBytes `json:"unlock_key"`
	UnlockGeneration uint64   `json:"unlock_generation"`
	Root             hexBytes `json:"root"`
	OlderRoot        hexBytes `json:"older_root"`
	Random           hexBytes `json:"random"`
	Encoded          hexBytes `json:"encoded"`
}

// The file.
type keychainVectors struct {
	LocalKeys    []localKeyVector   `json:"local_keys"`
	SealedFiles  []sealedFileVector `json:"sealed_files"`
	Records      recordsVector      `json:"records"`
	UnlockWrap   unlockWrapVector   `json:"unlock_wrap"`
	KeychainWrap keychainWrapVector `json:"keychain_wrap"`
}

// A key of one repeated byte, to read at a glance in the file.
func vectorKey(fill byte) hexBytes {
	return bytes.Repeat([]byte{fill}, localKeyByteCount)
}

// Seals a vector's file from its inputs.
func sealVector(t *testing.T, vector *sealedFileVector) []byte {
	t.Helper()
	header := &sealHeader{generation: vector.Generation, class: vector.Class}
	copy(header.noncePrefix[:], vector.NoncePrefix)
	plaintext := []byte(vector.Plaintext)
	if vector.PlaintextByteCount != 0 {
		plaintext = sealTestPlaintext(vector.PlaintextByteCount)
	}
	return sealTestFile(t, header, vector.Key, vector.Path, plaintext)
}

// Builds a vector's unlock.wrap from its inputs, taking every draw from its fixed Random.
func unlockWrapOfVector(t *testing.T, vector *unlockWrapVector) []byte {
	t.Helper()
	random := bytes.NewReader(vector.Random)
	store := &unlockStoreWrap{generation: vector.StoreGeneration}
	storeWrapped, err := sealWrappedKey(vector.StoreKey, vector.UnlockKey, store.additionalData(vector.Generation), random)
	if err != nil {
		t.Fatal(err)
	}
	store.wrapped = *storeWrapped

	settings := &SidecarKeychainSettings{
		PassMemoryByteCount: int64(vector.MemoryKibiCount) * 1024,
		PassIterationCount:  int(vector.IterationCount),
		PassThreadCount:     int(vector.ThreadCount),
	}
	pass, err := newUnlockPassWrap(vector.UnlockKey, vector.Generation, []byte(vector.Pass), settings, random)
	if err != nil {
		t.Fatal(err)
	}

	chainKey, err := deriveLocalKey(vector.UnlockKey, unlockPreviousClass)
	if err != nil {
		t.Fatal(err)
	}
	previousGeneration := vector.Generation - 1
	previousWrapped, err := sealWrappedKey(
		chainKey,
		vector.PreviousKey,
		unlockPreviousAdditionalData(vector.Generation, previousGeneration),
		random,
	)
	if err != nil {
		t.Fatal(err)
	}
	wrap := &unlockWrap{
		generation: vector.Generation,
		store:      store,
		pass:       pass,
		previous:   []unlockPreviousKey{{generation: previousGeneration, wrapped: *previousWrapped}},
	}
	return wrap.encode()
}

// Builds a vector's keychain.wrap from its inputs.
func keychainWrapOfVector(t *testing.T, vector *keychainWrapVector) []byte {
	t.Helper()
	networkId := Id(vector.NetworkId)
	random := bytes.NewReader(vector.Random)
	root, err := wrapKeychainRoot(networkId, 2, vector.Root, vector.UnlockGeneration, vector.UnlockKey, random)
	if err != nil {
		t.Fatal(err)
	}
	olderRoot, err := wrapKeychainRoot(networkId, 1, vector.OlderRoot, vector.UnlockGeneration, vector.UnlockKey, random)
	if err != nil {
		t.Fatal(err)
	}
	wrap := &keychainWrap{networkId: networkId, roots: []keychainRoot{*root, *olderRoot}}
	return wrap.encode()
}

// The vectors with their answers computed, from fixed inputs only.
func computeKeychainVectors(t *testing.T) *keychainVectors {
	t.Helper()
	root := vectorKey(0x11)
	localKeys := []localKeyVector{}
	for _, class := range []string{keychainRecordsClass, "search", "evs", "smtp-dkim"} {
		key, err := deriveLocalKey(root, class)
		if err != nil {
			t.Fatal(err)
		}
		localKeys = append(localKeys, localKeyVector{Secret: root, Class: class, Key: key})
	}

	records := recordsVector{NameValues: map[string]hexBytes{
		"evs/key":       []byte("synthetic evs key"),
		"identity/seed": vectorKey(0x22),
		"zero/empty":    {},
	}}
	nameValues := map[string][]byte{}
	for name, value := range records.NameValues {
		nameValues[name] = value
	}
	records.Encoded = encodeKeychainRecords(nameValues)

	sealedFiles := []sealedFileVector{
		{
			Key:         localKeys[0].Key,
			Class:       keychainRecordsClass,
			Path:        keychainRecordsName,
			Generation:  1,
			NoncePrefix: bytes.Repeat([]byte{0x33}, sealNoncePrefixByteCount),
			Plaintext:   records.Encoded,
		},
		{
			Key:         localKeys[2].Key,
			Class:       "evs",
			Path:        "evs/empty",
			Generation:  3,
			NoncePrefix: bytes.Repeat([]byte{0x44}, sealNoncePrefixByteCount),
			Plaintext:   []byte{},
		},
		{
			Key:                localKeys[2].Key,
			Class:              "evs",
			Path:               "evs/a/long",
			Generation:         3,
			NoncePrefix:        bytes.Repeat([]byte{0x55}, sealNoncePrefixByteCount),
			PlaintextByteCount: 2*sealChunkByteCount + 1,
		},
	}
	for i := range sealedFiles {
		sealed := sealVector(t, &sealedFiles[i])
		if sealedFiles[i].PlaintextByteCount != 0 {
			hash := sha256.Sum256(sealed)
			sealedFiles[i].SealedSha256 = hash[:]
		} else {
			sealedFiles[i].Sealed = sealed
		}
	}

	unlock := unlockWrapVector{
		UnlockKey:       vectorKey(0x66),
		PreviousKey:     vectorKey(0x77),
		StoreKey:        vectorKey(0x88),
		Pass:            "synthetic vector pass",
		Generation:      4,
		StoreGeneration: 3,
		MemoryKibiCount: 256,
		IterationCount:  2,
		ThreadCount:     2,
		Random:          bytes.Repeat([]byte{0x99, 0xaa, 0xbb}, 40),
	}
	unlock.Encoded = unlockWrapOfVector(t, &unlock)

	wrapVector := keychainWrapVector{
		NetworkId:        bytes.Repeat([]byte{0xcc}, 16),
		UnlockKey:        vectorKey(0xdd),
		UnlockGeneration: 2,
		Root:             vectorKey(0xee),
		OlderRoot:        vectorKey(0xef),
		Random:           bytes.Repeat([]byte{0xf1, 0xf2}, 24),
	}
	wrapVector.Encoded = keychainWrapOfVector(t, &wrapVector)

	return &keychainVectors{
		LocalKeys:    localKeys,
		SealedFiles:  sealedFiles,
		Records:      records,
		UnlockWrap:   unlock,
		KeychainWrap: wrapVector,
	}
}

// The file as checked in, with what this leg computes from the same inputs beside it.
func TestKeychainVectorsAreByteEqual(t *testing.T) {
	computed := computeKeychainVectors(t)
	encoded, err := json.MarshalIndent(computed, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if *updateKeychainVectors {
		if err := os.WriteFile("testdata/keychain/vectors.json", encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if !bytes.Equal(encoded, keychainVectorsJson) {
		t.Error("a vector moved: this leg computes other bytes than testdata/keychain/vectors.json holds")
	}
}

// Each vector also opens, so the file cannot pin bytes nothing can read.
func TestKeychainVectorsOpen(t *testing.T) {
	vectors := &keychainVectors{}
	if err := json.Unmarshal(keychainVectorsJson, vectors); err != nil {
		t.Fatal(err)
	}

	for _, vector := range vectors.SealedFiles {
		sealed := []byte(vector.Sealed)
		if vector.PlaintextByteCount != 0 {
			sealed = sealVector(t, &vector)
		}
		plaintext, err := openTestFile(sealed, vector.Key, vector.Path)
		if err != nil {
			t.Fatalf("%s: %v", vector.Path, err)
		}
		want := []byte(vector.Plaintext)
		if vector.PlaintextByteCount != 0 {
			want = sealTestPlaintext(vector.PlaintextByteCount)
		}
		if !bytes.Equal(plaintext, want) {
			t.Errorf("%s: the plaintext changed", vector.Path)
		}
	}

	nameValues, err := decodeKeychainRecords(vectors.Records.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(nameValues) != len(vectors.Records.NameValues) {
		t.Errorf("%d records", len(nameValues))
	}

	wrap, err := decodeUnlockWrap(vectors.UnlockWrap.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	unlockKey, err := wrap.pass.open([]byte(vectors.UnlockWrap.Pass), wrap.generation)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unlockKey, vectors.UnlockWrap.UnlockKey) {
		t.Error("the pass opened another U")
	}
	opened, err := wrap.store.wrapped.open(vectors.UnlockWrap.StoreKey, wrap.store.additionalData(wrap.generation))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, vectors.UnlockWrap.UnlockKey) {
		t.Error("W opened another U")
	}

	rootWrap, err := decodeKeychainWrap(vectors.KeychainWrap.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	root, err := rootWrap.roots[0].open(rootWrap.networkId, vectors.KeychainWrap.UnlockKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root, vectors.KeychainWrap.Root) {
		t.Error("U opened another root")
	}
}
