//go:build !ios_extension

// A share's ShareKey on the accepting admin's device (BRIDGE-M6-04; §17.9's share signers, D-BRIDGE-17; DESIGN-DETAILS
// 12.2.8; I-1, I-4): the Ed25519 key that certifies one ShareSigner a generation of the accepting network's config,
// and signs nothing else.
//
//	Create(share_id)      a seed of 32 random bytes, kept as bridge/share-key/<share_id hex> in the keyring's store,
//	                      created only where none is kept, so two accepts of one share hold one key; never in the config
//	Certify(share_id, g)  a new ShareSigner seed for every cert, and its ShareCert{share_id, g, the signer's public
//	                      key, not_after_ms := now + CertLifetime} signed by the ShareKey: the BridgeShareSigner file a
//	                      config head carries at g
//
// A cert is never renewed in place: every Certify makes a new seed, so one seed rides one file, in a head sealed at the
// generation its cert names, and "who holds this seed" is "who reads a head sealed at that generation".
//
// The store is the custody §17.9 names: an owner-bound `secret` of the accepting admin (§11.12), so the key reaches
// only §8.5's readers of that secret. BridgeShareKeyStore is its seam. NewBridgeShareKeyLocalStore keeps the key in
// this device's own sealed store instead, which is narrower: only the device that accepted can certify, and its loss
// lapses the share after its last cert's 7 days, until the admin's secret repo backs the store.
//
// testHookSecret runs where a ShareKey's or a ShareSigner's seed is made or read. Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// The store keeps a ShareKey under the name already: Create answers the one kept.
	ErrBridgeShareKeyExists = errors.New("bridge share key exists")
	// The store keeps no ShareKey under the name: this device does not hold the share's key.
	ErrBridgeShareKeyAbsent = errors.New("bridge share key absent")
)

// The names a keyring keeps its seeds under. A format value.
const bridgeShareKeyPrefix = "bridge/share-key/"

// Where a keyring keeps ShareKey seeds (the file's comment).
type BridgeShareKeyStore interface {
	// Keeps seed under name where nothing is kept, as an If-None-Match create: ErrBridgeShareKeyExists where
	// something is, with nothing changed.
	CreateShareKey(ctx context.Context, name string, seed []byte) error
	// The seed kept under name, ErrBridgeShareKeyAbsent for none.
	ReadShareKey(ctx context.Context, name string) ([]byte, error)
	// The names kept under prefix, sorted.
	ListShareKeys(ctx context.Context, prefix string) ([]string, error)
}

// A key store over a device's own sealed store (the file's comment).
type bridgeShareKeyLocalStore struct {
	store SidecarStore
}

// A key store over store, a directory of this device's sealed store.
func NewBridgeShareKeyLocalStore(store SidecarStore) (BridgeShareKeyStore, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: a share key store needs a store", errInvalidSettings)
	}
	return &bridgeShareKeyLocalStore{store: store}, nil
}

// Keeps seed under name where the store holds nothing there.
func (self *bridgeShareKeyLocalStore) CreateShareKey(ctx context.Context, name string, seed []byte) error {
	if reader, err := self.store.Open(name); err == nil {
		reader.Close()
		return ErrBridgeShareKeyExists
	} else if !errors.Is(err, ErrSidecarStoreAbsent) {
		return err
	}
	writer, err := self.store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(seed); err != nil {
		return err
	}
	return writer.Commit()
}

// The seed kept under name.
func (self *bridgeShareKeyLocalStore) ReadShareKey(ctx context.Context, name string) ([]byte, error) {
	reader, err := self.store.Open(name)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, ErrBridgeShareKeyAbsent
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(io.LimitReader(reader, 2*ed25519.SeedSize))
}

// The names kept under prefix, in the store's order.
func (self *bridgeShareKeyLocalStore) ListShareKeys(ctx context.Context, prefix string) ([]string, error) {
	entries, err := self.store.List(prefix)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	return names, nil
}

// Tunables of a keyring.
type BridgeShareKeySettings struct {
	// How long a cert runs from its signing: 168 h, §17.9's 7 days and the most a host admits (DESIGN-DETAILS
	// 12.2.2's ShareCertLifetime). Non-positive is the default.
	CertLifetime time.Duration
	// The cert's format limits; nil is the format's defaults.
	Cert *bridge.ShareCertSettings
}

// §17.9's values.
func DefaultBridgeShareKeySettings() *BridgeShareKeySettings {
	return &BridgeShareKeySettings{
		CertLifetime: 168 * time.Hour,
	}
}

// What a keyring is built over.
type BridgeShareKeyringArgs struct {
	Store BridgeShareKeyStore
	// crypto/rand's reader when nil.
	Random   io.Reader
	Clock    Clock
	Settings *BridgeShareKeySettings
}

// The ShareKeys this device holds (the file's comment).
type BridgeShareKeyring struct {
	store    BridgeShareKeyStore
	random   io.Reader
	clock    Clock
	settings *BridgeShareKeySettings
}

// A keyring over args, whose Store is required.
func NewBridgeShareKeyring(args *BridgeShareKeyringArgs) (*BridgeShareKeyring, error) {
	if args == nil || args.Store == nil {
		return nil, fmt.Errorf("%w: a share keyring needs its store", errInvalidSettings)
	}
	settings := DefaultBridgeShareKeySettings()
	if args.Settings != nil {
		if 0 < args.Settings.CertLifetime {
			settings.CertLifetime = args.Settings.CertLifetime
		}
		settings.Cert = args.Settings.Cert
	}
	random := args.Random
	if random == nil {
		random = rand.Reader
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	return &BridgeShareKeyring{store: args.Store, random: random, clock: clock, settings: settings}, nil
}

// bridge/share-key/<share_id hex>.
func bridgeShareKeyName(shareId Id) string {
	return bridgeShareKeyPrefix + hex.EncodeToString(shareId.Bytes())
}

// The ShareKey's seed as kept. ErrBridgeShareKeyAbsent for a share whose key this device does not hold.
func (self *BridgeShareKeyring) seed(ctx context.Context, shareId Id) ([]byte, error) {
	seed, err := self.store.ReadShareKey(ctx, bridgeShareKeyName(shareId))
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("the share key kept is %d bytes, no Ed25519 seed", len(seed))
	}
	testHookSecret("bridge-share-key", seed)
	return seed, nil
}

// Creates the share's ShareKey where this device holds none and answers its public key; where it holds one, a
// second accept or a resumed one, answers that key's.
func (self *BridgeShareKeyring) Create(ctx context.Context, shareId Id) (ed25519.PublicKey, error) {
	if shareId == (Id{}) {
		return nil, fmt.Errorf("%w: no share", ErrBridgeFileRefused)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(self.random, seed); err != nil {
		return nil, err
	}
	testHookSecret("bridge-share-key", seed)
	testHookBarrier("bridge_share_key.create.before", shareId.String())
	err := self.store.CreateShareKey(ctx, bridgeShareKeyName(shareId), seed)
	testHookBarrier("bridge_share_key.create.after", shareId.String())
	switch {
	case err == nil:
		return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), nil
	case errors.Is(err, ErrBridgeShareKeyExists):
		return self.PublicKey(ctx, shareId)
	}
	return nil, err
}

// The public half of a share's ShareKey. ErrBridgeShareKeyAbsent where this device does not hold it.
func (self *BridgeShareKeyring) PublicKey(ctx context.Context, shareId Id) (ed25519.PublicKey, error) {
	seed, err := self.seed(ctx, shareId)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), nil
}

// The shares whose ShareKey this device holds, in id order.
func (self *BridgeShareKeyring) Shares(ctx context.Context) ([]Id, error) {
	names, err := self.store.ListShareKeys(ctx, bridgeShareKeyPrefix)
	if err != nil {
		return nil, err
	}
	shareIds := []Id{}
	for _, name := range names {
		encoded, ok := strings.CutPrefix(name, bridgeShareKeyPrefix)
		if !ok {
			continue
		}
		decoded, err := hex.DecodeString(encoded)
		if err != nil {
			continue
		}
		if shareId, err := IdFromBytes(decoded); err == nil {
			shareIds = append(shareIds, shareId)
		}
	}
	return shareIds, nil
}

// Certifies a new ShareSigner of generation g for the share (the file's Certify row): the BridgeShareSigner file,
// its seed new, never one a cert rode before.
func (self *BridgeShareKeyring) Certify(ctx context.Context, shareId Id, generation uint64) (*bridge.BridgeShareSigner, error) {
	if generation == 0 {
		return nil, fmt.Errorf("%w: no generation to certify", ErrBridgeFileRefused)
	}
	shareSeed, err := self.seed(ctx, shareId)
	if err != nil {
		return nil, err
	}
	signerSeed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(self.random, signerSeed); err != nil {
		return nil, err
	}
	testHookSecret("bridge-share-signer", signerSeed)
	cert := &bridge.ShareCert{
		ShareId:          shareId.Bytes(),
		ConfigGeneration: generation,
		SignerPublicKey:  ed25519.NewKeyFromSeed(signerSeed).Public().(ed25519.PublicKey),
		NotAfterMs:       self.clock.Now().Add(self.settings.CertLifetime).UnixMilli(),
	}
	signedCert, err := bridge.ShareCertSigned(cert, shareSeed, self.settings.Cert)
	if err != nil {
		return nil, err
	}
	return &bridge.BridgeShareSigner{ShareId: shareId.Bytes(), ConfigGeneration: generation, SignerSeed: signerSeed, ShareCert: signedCert}, nil
}
