// The sealed fields of config records (config_seal.go; plan-TEAM-sealed-field-format). Pure, on every leg.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// RK_g of a test repo.
func testConfigSealKey(generation uint64) *EvsRepoKey {
	return &EvsRepoKey{repoId: testConfigId("config repo"), generation: generation, repoKey: bytes.Repeat([]byte{byte(generation)}, gkmRepoKeyByteCount)}
}

func testConfigSealContext() *ConfigSealContext {
	return &ConfigSealContext{
		SignedType: bridge.SignedType_SIGNED_INDEXER_SET,
		NetworkId:  testConfigId("network").Bytes(),
		Nonce:      bytes.Repeat([]byte{0x5a}, configNonceByteCount),
	}
}

func testConfigSealKeyAt(keys ...*EvsRepoKey) func(generation uint64) *EvsRepoKey {
	return func(generation uint64) *EvsRepoKey {
		for _, key := range keys {
			if key.Generation() == generation {
				return key
			}
		}
		return nil
	}
}

// A sealed body opens to the same message under its generation's key, its generation readable without one, padded
// to a multiple of 256 bytes.
func TestSealConfigBodyRoundTrip(t *testing.T) {
	body := &protocol.IndexerServices{Services: []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_MAIL, protocol.IndexerService_INDEXER_SERVICE_SEARCH}}
	sealed, err := SealConfigBody(testConfigSealKey(3), testConfigSealContext(), body, nil)
	if err != nil {
		t.Fatal(err)
	}
	if (len(sealed)-configSealGenerationByteCount-24-16)%configSealPadByteCount != 0 {
		t.Fatalf("%d bytes is no padded seal", len(sealed))
	}
	generation, err := ConfigSealedGeneration(sealed)
	if err != nil || generation != 3 {
		t.Fatalf("generation %d, err %v", generation, err)
	}
	opened := &protocol.IndexerServices{}
	generation, err = OpenConfigBody(sealed, testConfigSealContext(), testConfigSealKeyAt(testConfigSealKey(2), testConfigSealKey(3)), opened)
	if err != nil || generation != 3 || !proto.Equal(opened, body) {
		t.Fatalf("opened %v at %d, err %v", opened, generation, err)
	}

	// two seals of one body differ, by their nonces
	again, err := SealConfigBody(testConfigSealKey(3), testConfigSealContext(), body, nil)
	if err != nil || bytes.Equal(again, sealed) {
		t.Fatalf("a second seal is the first: %v", err)
	}
}

// A reader without the generation keeps the entry pending; anything changed in the seal, or in the record it is
// bound to, voids it.
func TestOpenConfigBodyRefusesWhatWasNotSealedSo(t *testing.T) {
	body := &protocol.IndexerServices{Services: []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_MIRROR}}
	sealed, err := SealConfigBody(testConfigSealKey(3), testConfigSealContext(), body, nil)
	if err != nil {
		t.Fatal(err)
	}
	open := func(sealed []byte, context *ConfigSealContext, keyAt func(uint64) *EvsRepoKey) error {
		_, err := OpenConfigBody(sealed, context, keyAt, &protocol.IndexerServices{})
		return err
	}

	if err := open(sealed, testConfigSealContext(), testConfigSealKeyAt(testConfigSealKey(2))); !errors.Is(err, ErrConfigSealGenerationMissing) {
		t.Fatalf("a missing generation: %v", err)
	}
	if err := open(sealed, testConfigSealContext(), func(uint64) *EvsRepoKey { return testConfigSealKey(2) }); !errors.Is(err, ErrConfigSealInvalid) {
		t.Fatalf("another generation's key: %v", err)
	}
	keyless := &EvsRepoKey{repoId: testConfigId("config repo"), generation: 3}
	if err := open(sealed, testConfigSealContext(), testConfigSealKeyAt(keyless)); !errors.Is(err, ErrConfigSealGenerationMissing) {
		t.Fatalf("a key that holds no RK_g: %v", err)
	}
	otherRepo := &EvsRepoKey{repoId: testConfigId("another repo"), generation: 3, repoKey: testConfigSealKey(3).repoKey}
	if err := open(sealed, testConfigSealContext(), testConfigSealKeyAt(otherRepo)); !errors.Is(err, ErrConfigSealInvalid) {
		t.Fatalf("another repo's key: %v", err)
	}

	for name, edit := range map[string]func(context *ConfigSealContext){
		"another type":    func(context *ConfigSealContext) { context.SignedType = bridge.SignedType_SIGNED_RECOVERY_BIND },
		"another network": func(context *ConfigSealContext) { context.NetworkId = testConfigId("other").Bytes() },
		"another nonce":   func(context *ConfigSealContext) { context.Nonce[0] ^= 1 },
	} {
		context := testConfigSealContext()
		edit(context)
		if err := open(sealed, context, testConfigSealKeyAt(testConfigSealKey(3))); !errors.Is(err, ErrConfigSealInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for i := configSealGenerationByteCount; i < len(sealed); i += 37 {
		tampered := bytes.Clone(sealed)
		tampered[i] ^= 1
		if err := open(tampered, testConfigSealContext(), testConfigSealKeyAt(testConfigSealKey(3))); !errors.Is(err, ErrConfigSealInvalid) {
			t.Fatalf("a flip at %d: %v", i, err)
		}
	}
	if err := open(sealed[:20], testConfigSealContext(), testConfigSealKeyAt(testConfigSealKey(3))); !errors.Is(err, ErrConfigSealInvalid) {
		t.Fatalf("a short seal: %v", err)
	}
	if err := open(sealed, &ConfigSealContext{SignedType: bridge.SignedType_SIGNED_INDEXER_SET}, testConfigSealKeyAt(testConfigSealKey(3))); !errors.Is(err, ErrConfigSealInvalid) {
		t.Fatalf("no header: %v", err)
	}
}

// The format's bytes, fixed: RK_3 of all 0x03, the repo, the context above, a nonce of 24 0x11 bytes.
func TestSealConfigBodyVector(t *testing.T) {
	body := &protocol.IndexerServices{Services: []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_SEARCH}}
	sealed, err := SealConfigBody(testConfigSealKey(3), testConfigSealContext(), body, bytes.NewReader(bytes.Repeat([]byte{0x11}, 24)))
	if err != nil {
		t.Fatal(err)
	}
	const want = "0000000000000003111111111111111111111111111111111111111111111111"
	if hex.EncodeToString(sealed[:32]) != want {
		t.Fatalf("prefix %x", sealed[:32])
	}
	if got := hex.EncodeToString(sealed); got != testConfigSealVector {
		t.Fatalf("sealed %s", got)
	}
}

// TestSealConfigBodyVector's bytes.
const testConfigSealVector = "0000000000000003111111111111111111111111111111111111111111111111ea526bfb0bb036d4230ee80b8b92e13c77ee04708709833b23129912a0d24abc19310a3f7323aa52812129406ba7cfb849c350110992956b2f6fc7a07471d3908adffef45a31ca7d2700912adf31cd60933007a032bd381fca3afca2f3cdfe74be6be13c3f9673cc5b4641ca3b6871b7a7332d8da4ea0f0cc405790bf1d7b04223d5c4a8c4816fb4f03fbabda6d805a969d7256e69382c117a7342b44a8a4843bf12bc241f5594357c79f4124542bf6d0743fdd3af9beffda99b6b5e3256bb40ba494ee9e343658f13d93b4164f46849ded6983d0260db8a9614ad9a78746bf22b23af2f0081988a2ea3aaca855999375a15c1f9f12ae483b82f71162032fa4f94c80d8515fc8de1b3a46b3850b173cf"
