//go:build !ios_extension

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A holder's world: the filer world's net and heads as the accepting network's config, a keyring, and a config
// generation and write gate a test moves.
type testBridgeShareHolder struct {
	t       *testing.T
	world   *testBridgeFileWorld
	keys    *testBridgeShareKeys
	renewer *BridgeShareSignerRenewer
	shareId Id

	stateLock sync.Mutex
	// the config's generation as the holder reads it, and the least generation evs takes a head sealed at
	generation uint64
	covers     uint64
	// run inside a SaveHead before the gate judges it: where a removal's rotation lands
	beforeWrite func()
	// the generation each SaveHead was sealed at, and the files it refused
	refused [][]byte
}

// The write gate: a head sealed at the holder's generation lands only when that generation covers the config's
// holders_shrunk_at.
type testBridgeShareHolderWriter struct {
	holder *testBridgeShareHolder
}

func (self testBridgeShareHolderWriter) SaveHead(ctx context.Context, edit func(head *ConfigHead) (*ConfigHead, error)) (*bridge.AuthPin, error) {
	holder := self.holder
	holder.stateLock.Lock()
	sealedAt := holder.generation
	beforeWrite := holder.beforeWrite
	holder.beforeWrite = nil
	holder.stateLock.Unlock()
	if beforeWrite != nil {
		beforeWrite()
	}
	holder.stateLock.Lock()
	covers := holder.covers
	holder.stateLock.Unlock()
	if sealedAt < covers {
		// what the refused head would have held, so a test sees its seed never lands
		base := holder.world.net.log.State().Base()
		head, err := holder.world.heads.ReadConfigHead(ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
		if err == nil {
			if next, err := edit(head); err == nil {
				holder.stateLock.Lock()
				holder.refused = append(holder.refused, next.File(ConfigHeadBridgeSharePath(holder.shareId)))
				holder.stateLock.Unlock()
			}
		}
		return nil, fmt.Errorf("evs: a head sealed at generation %d, which no longer covers the repo's holders", sealedAt)
	}
	return holder.world.heads.SaveHead(ctx, edit)
}

func newTestBridgeShareHolder(t *testing.T) *testBridgeShareHolder {
	t.Helper()
	world := newTestBridgeFileWorld(t, true)
	keys := newTestBridgeShareKeys(t)
	keys.clock = world.clock
	keyStore, _ := NewBridgeShareKeyLocalStore(keys.store)
	keyring, err := NewBridgeShareKeyring(&BridgeShareKeyringArgs{Store: keyStore, Clock: world.clock})
	if err != nil {
		t.Fatal(err)
	}
	keys.keyring = keyring
	holder := &testBridgeShareHolder{t: t, world: world, keys: keys, shareId: testConfigId("holder share"), generation: 7, covers: 7}
	if _, err := keyring.Create(context.Background(), holder.shareId); err != nil {
		t.Fatal(err)
	}
	holder.renewer, err = NewBridgeShareSignerRenewer(&BridgeShareSignerRenewerArgs{
		Keyring: keyring, Config: testBridgeFileConfig{net: world.net}, Heads: world.heads,
		HeadWriter: func() BridgeHeadWriter { return testBridgeShareHolderWriter{holder: holder} },
		Generation: func(ctx context.Context) (uint64, error) {
			holder.stateLock.Lock()
			defer holder.stateLock.Unlock()
			return holder.generation, nil
		},
		Clock: world.clock, Log: NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return holder
}

// The network rotates its config to generation, for a removal when shrunk: evs then takes no head sealed below it.
func (self *testBridgeShareHolder) rotate(generation uint64, shrunk bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.generation = generation
	if shrunk {
		self.covers = generation
	}
}

// The share's file in the head saved last, nil for none.
func (self *testBridgeShareHolder) file() *bridge.BridgeShareSigner {
	self.t.Helper()
	head, _ := self.world.heads.savedHead()
	if head == nil {
		return nil
	}
	fileBytes := head.File(ConfigHeadBridgeSharePath(self.shareId))
	if fileBytes == nil {
		return nil
	}
	file := &bridge.BridgeShareSigner{}
	if err := proto.Unmarshal(fileBytes, file); err != nil {
		self.t.Fatal(err)
	}
	return file
}

func (self *testBridgeShareHolder) renew(want bool) {
	self.t.Helper()
	landed, err := self.renewer.Renew(context.Background(), self.shareId)
	if err != nil || landed != want {
		self.t.Fatalf("a renewal landed %t, expected %t: %v", landed, want, err)
	}
}

// §17.9's renew row: a holder writes a signer when the share has no file, when the config's generation passed the
// file's, and when the file's cert has under 3 days left, each with a new seed; a pass that finds none of them writes
// nothing.
func TestRenewalIsDueOnlyWhenItsRowSays(t *testing.T) {
	holder := newTestBridgeShareHolder(t)
	holder.renew(true)
	first := holder.file()
	if first == nil || first.GetConfigGeneration() != 7 {
		t.Fatalf("the first signer: %v", first.GetConfigGeneration())
	}
	_, saves := holder.world.heads.savedHead()
	holder.renew(false)
	holder.world.clock.advance(95 * time.Hour)
	holder.renew(false)
	if _, again := holder.world.heads.savedHead(); again != saves {
		t.Fatalf("a pass that was not due saved %d heads", again-saves)
	}
	// under 3 days left: renewed at its generation
	holder.world.clock.advance(2 * time.Hour)
	holder.renew(true)
	second := holder.file()
	if second.GetConfigGeneration() != 7 || bytes.Equal(second.GetSignerSeed(), first.GetSignerSeed()) {
		t.Fatal("the renewal at its generation reused a seed or moved the generation")
	}
	// a new generation: renewed at once
	holder.rotate(8, false)
	holder.renew(true)
	third := holder.file()
	if third.GetConfigGeneration() != 8 || bytes.Equal(third.GetSignerSeed(), second.GetSignerSeed()) {
		t.Fatal("the renewal at a new generation")
	}
	holder.renew(false)
	// a device with no config writer renews nothing
	renewer, err := NewBridgeShareSignerRenewer(&BridgeShareSignerRenewerArgs{
		Keyring: holder.keys.keyring, Config: testBridgeFileConfig{net: holder.world.net}, Heads: holder.world.heads,
		Generation: func(ctx context.Context) (uint64, error) { return 9, nil }, Clock: holder.world.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := renewer.Renew(context.Background(), holder.shareId); !errors.Is(err, ErrBridgeShareSignerRenew) {
		t.Errorf("no config writer: %v", err)
	}
	// every share held is passed over, and one whose key is not held is not renewed
	if renewed, err := holder.renewer.RenewAll(context.Background()); err != nil || len(renewed) != 0 {
		t.Errorf("a pass over every share: %v, %v", renewed, err)
	}
	if _, err := holder.renewer.Renew(context.Background(), testConfigId("holder share not held")); !errors.Is(err, ErrBridgeShareSignerRenew) {
		t.Errorf("a share whose key is not held: %v", err)
	}
}

// FS-38's stale holder (§17.9's renew row; §10.6's write gate): a holder that read generation 7 and certified it writes
// after the network rotated to 8 for a removal. evs refuses the head sealed at 7, the signer it carried is dropped,
// and the holder starts over at 8 with a new seed, so the removed sidecar, which holds 7's key, reads no seed of a new
// cert.
func TestAStaleHoldersRenewalIsRefusedAndRemade(t *testing.T) {
	holder := newTestBridgeShareHolder(t)
	holder.renew(true)
	before := holder.file()
	// the rotation lands between the holder's read of the generation and its write
	holder.world.clock.advance(100 * time.Hour)
	holder.stateLock.Lock()
	holder.beforeWrite = func() { holder.rotate(8, true) }
	holder.stateLock.Unlock()
	holder.renew(true)
	after := holder.file()
	if after.GetConfigGeneration() != 8 {
		t.Fatalf("the signer that landed is of generation %d", after.GetConfigGeneration())
	}
	if len(holder.refused) != 1 {
		t.Fatalf("the gate refused %d heads", len(holder.refused))
	}
	dropped := &bridge.BridgeShareSigner{}
	if err := proto.Unmarshal(holder.refused[0], dropped); err != nil {
		t.Fatal(err)
	}
	if dropped.GetConfigGeneration() != 7 || bytes.Equal(dropped.GetSignerSeed(), before.GetSignerSeed()) {
		t.Fatal("the refused head did not carry a new signer of the stale generation")
	}
	if bytes.Equal(dropped.GetSignerSeed(), after.GetSignerSeed()) {
		t.Fatal("the seed the gate refused landed at the next generation")
	}
	// a refusal with the generation unmoved is not retried: the next pass tries again
	holder.world.clock.advance(100 * time.Hour)
	holder.stateLock.Lock()
	holder.covers = 9
	holder.stateLock.Unlock()
	if _, err := holder.renewer.Renew(context.Background(), holder.shareId); !errors.Is(err, ErrBridgeShareSignerRenew) {
		t.Fatalf("a refused renewal: %v", err)
	}
	if len(holder.refused) != 2 || !bytes.Equal(holder.file().GetSignerSeed(), after.GetSignerSeed()) {
		t.Fatalf("the gate refused %d heads, or the file changed", len(holder.refused))
	}
}

// §17.9's use row: a sidecar signs with a share's file only when it is its path's share, its cert is a ShareCert of
// that share at the file's generation certifying the seed, the cert is unexpired, and its generation is no lower than
// the newest this sidecar used.
func TestASignerIsUsedOnlyAsItsFileCertifies(t *testing.T) {
	keys := newTestBridgeShareKeys(t)
	net := newTestConfigNet(t)
	ctx := context.Background()
	shareId, otherId := testConfigId("use share"), testConfigId("use other share")
	sharePublicKey, err := keys.keyring.Create(ctx, shareId)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.keyring.Create(ctx, otherId); err != nil {
		t.Fatal(err)
	}
	headOf := func(path string, file *bridge.BridgeShareSigner) *ConfigHead {
		fileBytes, err := proto.Marshal(file)
		if err != nil {
			t.Fatal(err)
		}
		head, err := NewConfigHead(map[string][]byte{ConfigHeadGenesisPath: net.signedGenesis, path: fileBytes})
		if err != nil {
			t.Fatal(err)
		}
		return head
	}
	file, err := keys.keyring.Certify(ctx, shareId, 7)
	if err != nil {
		t.Fatal(err)
	}
	nowMs := keys.clock.Now().UnixMilli()
	use, err := ReadBridgeShareSigner(headOf(ConfigHeadBridgeSharePath(shareId), file), shareId)
	if err != nil || use.Generation != 7 || use.NotAfterMs != nowMs+(168*time.Hour).Milliseconds() {
		t.Fatalf("the use: %v, %v", use, err)
	}
	if err := BridgeShareSignerUsable(use, 7, nowMs); err != nil {
		t.Fatal(err)
	}
	// what it signs verifies at a host under the pinned ShareKey
	windowPublicKey := bytes.Repeat([]byte{0x77}, 32)
	delegation := &bridge.WindowDelegation{
		NetworkId: testConfigId("use network").Bytes(), SubjectSidecarId: testConfigId("use subject").Bytes(),
		WindowClientId: testConfigId("use window").Bytes(), WindowClientPublicKey: windowPublicKey,
		TargetSidecarId: testConfigId("use target").Bytes(), NotAfterMs: nowMs + 1000,
		ShareId: shareId.Bytes(), ShareCert: use.CertSigned,
	}
	signed, err := bridge.WindowDelegationSigned(delegation, use.sign, nil)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := bridge.VerifyWindowDelegationAdmission(signed, &bridge.WindowDelegationCheck{
		NetworkId: delegation.NetworkId, WindowClientId: delegation.WindowClientId, WindowClientPublicKey: windowPublicKey,
		TargetSidecarId: delegation.TargetSidecarId, NowMs: nowMs,
		IdentityKey: func(sidecarId []byte) ([]byte, bool) { return nil, false },
		Share: func(got []byte) (*bridge.WindowDelegationShare, bool) {
			return &bridge.WindowDelegationShare{SharePublicKey: sharePublicKey, Generation: 7}, bytes.Equal(got, shareId.Bytes())
		},
	})
	if err != nil || admission.ShareCert.GetConfigGeneration() != 7 {
		t.Fatalf("a host's admission of what the signer signed: %v", err)
	}
	if _, err := use.sign(bridge.SignedPurposeWindowDelegation, bridge.SignedType_SIGNED_SHARE_CERT, []byte("x")); !errors.Is(err, ErrBridgeShareSignerRefused) {
		t.Errorf("a signer asked to sign another type: %v", err)
	}

	otherFile, err := keys.keyring.Certify(ctx, otherId, 7)
	if err != nil {
		t.Fatal(err)
	}
	otherGeneration := proto.Clone(file).(*bridge.BridgeShareSigner)
	otherGeneration.ConfigGeneration = 8
	otherSeed := proto.Clone(file).(*bridge.BridgeShareSigner)
	otherSeed.SignerSeed = bytes.Repeat([]byte{0x42}, 32)
	shortSeed := proto.Clone(file).(*bridge.BridgeShareSigner)
	shortSeed.SignerSeed = shortSeed.SignerSeed[:16]
	noCert := proto.Clone(file).(*bridge.BridgeShareSigner)
	noCert.ShareCert = []byte("no certificate")
	renamed := proto.Clone(otherFile).(*bridge.BridgeShareSigner)
	renamed.ShareId = shareId.Bytes()
	for name, refused := range map[string]*bridge.BridgeShareSigner{
		"another share's file under the path":       otherFile,
		"another share's cert under the share's id": renamed,
		"a cert of another generation":              otherGeneration,
		"a seed the cert does not certify":          otherSeed,
		"a short seed":                              shortSeed,
		"no certificate":                            noCert,
	} {
		if _, err := ReadBridgeShareSigner(headOf(ConfigHeadBridgeSharePath(shareId), refused), shareId); !errors.Is(err, ErrBridgeShareSignerRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if use, err := ReadBridgeShareSigner(headOf(ConfigHeadBridgeSharePath(otherId), otherFile), shareId); use != nil || err != nil {
		t.Errorf("a head with no file for the share: %v, %v", use, err)
	}
	if err := BridgeShareSignerUsable(use, 8, nowMs); !errors.Is(err, ErrBridgeShareSignerRefused) {
		t.Errorf("below the floor: %v", err)
	}
	if err := BridgeShareSignerUsable(use, 7, use.NotAfterMs); !errors.Is(err, ErrBridgeShareSignerRefused) {
		t.Errorf("an expired cert: %v", err)
	}
	if err := BridgeShareSignerUsable(nil, 0, nowMs); !errors.Is(err, ErrBridgeShareSignerRefused) {
		t.Errorf("no signer: %v", err)
	}
	// an unexpired signer of an older generation than the config's goes on until the holder's renewal lands
	if err := BridgeShareSignerUsable(use, 6, use.NotAfterMs-1); err != nil {
		t.Errorf("an unexpired signer above the floor: %v", err)
	}
}

// A seed is in no rendering of a signer's use (I-7): not its prints, not its JSON.
func TestSeedsNeverLeaveTheSigner(t *testing.T) {
	keys := newTestBridgeShareKeys(t)
	ctx := context.Background()
	shareId := testConfigId("seed share")
	if _, err := keys.keyring.Create(ctx, shareId); err != nil {
		t.Fatal(err)
	}
	file, err := keys.keyring.Certify(ctx, shareId, 3)
	if err != nil {
		t.Fatal(err)
	}
	fileBytes, _ := proto.Marshal(file)
	head, err := NewConfigHead(map[string][]byte{ConfigHeadGenesisPath: newTestConfigNet(t).signedGenesis, ConfigHeadBridgeSharePath(shareId): fileBytes})
	if err != nil {
		t.Fatal(err)
	}
	use, err := ReadBridgeShareSigner(head, shareId)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(use)
	if err != nil {
		t.Fatal(err)
	}
	valueEncoded, _ := json.Marshal(*use)
	seed := file.GetSignerSeed()
	for name, rendering := range map[string]string{
		"%v": fmt.Sprintf("%v", use), "%+v": fmt.Sprintf("%+v", use), "%#v": fmt.Sprintf("%#v", use),
		"value %v": fmt.Sprintf("%v", *use), "value %+v": fmt.Sprintf("%+v", *use), "value %#v": fmt.Sprintf("%#v", *use),
		"%s": fmt.Sprintf("%s", use), "json": string(encoded), "value json": string(valueEncoded),
	} {
		for _, form := range []string{fmt.Sprintf("%x", seed), fmt.Sprintf("%v", seed), fmt.Sprintf("%d", seed[:4]), string(seed)} {
			if bytes.Contains([]byte(rendering), []byte(form[:min(len(form), 12)])) {
				t.Errorf("%s holds the seed", name)
			}
		}
	}
}

// The floor of the use row: the newest generation a sidecar signed with is saved before it signs with it, never
// falls, and a restart starts from what was saved.
func TestASignersFloorIsSavedBeforeItIsUsed(t *testing.T) {
	shareId := testConfigId("floor share")
	saved := map[Id]uint64{}
	saveErr := error(nil)
	floors := NewBridgeShareSignerFloors(nil, func(floors map[Id]uint64) error {
		if saveErr != nil {
			return saveErr
		}
		saved = floors
		return nil
	})
	if err := floors.Use(shareId, 7); err != nil || floors.Floor(shareId) != 7 || saved[shareId] != 7 {
		t.Fatalf("a first use: %v", err)
	}
	if err := floors.Use(shareId, 6); err != nil || floors.Floor(shareId) != 7 {
		t.Fatalf("a lower use moved the floor: %v", err)
	}
	saveErr = errors.New("the store is full")
	if err := floors.Use(shareId, 9); err == nil || floors.Floor(shareId) != 7 {
		t.Fatalf("a floor that was not saved rose: %v", err)
	}
	restarted := NewBridgeShareSignerFloors(saved, nil)
	if restarted.Floor(shareId) != 7 || restarted.Floor(testConfigId("floor other")) != 0 {
		t.Fatal("a restart lost the floor")
	}
}
