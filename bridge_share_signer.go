//go:build !ios_extension

// A share's ShareSigners in the accepting network (BRIDGE-M6-04; §17.9's share signers, D-BRIDGE-17; DESIGN-DETAILS
// 12.2.8; I-1, I-4, FS-38): the config file a ShareKey's holder writes, the rule a sidecar signs by, and the
// re-signing a new signer asks.
//
//	file    bridge/share/<share_id hex>, a BridgeShareSigner{share_id, g, a seed, its Signed ShareCert}: a config file,
//	        not a statement, so only config writers' heads change it and their signatures cover it
//	renew   on a device that holds the ShareKey and writes the config, each ShareRenewInterval and at each new
//	        generation: g := the config's generation as this device holds it; due := no file, or the file's generation
//	        below g, or its cert with less than ShareRenewBelow left; due -> SaveHead replaces the file with
//	        Certify(share_id, g), the head sealed at g. evs refuses a head sealed at g once g no longer covers the
//	        config's holders_shrunk_at (§10.6's write gate): the signer that did not land is dropped, the device reads
//	        the generation again, and starts over with a new seed. Not due is nothing: a second pass at g is a no-op
//	use     a sidecar signs with a share's file only when its share_id is the path's, its cert parses as a ShareCert
//	        of that share whose generation is the file's and whose signer key is the seed's public key, its cert is
//	        unexpired, and its generation is at least the newest this sidecar has used for the share (the floor), so
//	        it never signs below a generation it already used, and goes on with an unexpired signer of an older
//	        generation until the holder's renewal lands
//	resign  a new signer -> the host re-signs each live window client of that share's links, whose next contracts
//	        carry it (BridgeComponent.ResignShares)
//
// The write gate is the fence against a stale holder: a holder that read generation 7, certified it and writes after
// the network rotated to 8 for a removal cannot land the file in a head sealed at 7, so the removed sidecar, which
// holds 7's key, reads no seed whose cert outlives its removal by more than a cert's lifetime. The holder's own view
// cannot be that fence, since its view is what is stale.
//
// A seed never leaves the sidecar role: a BridgeShareSignerUse is not in BridgeState, crosses no device RPC and prints
// as its ids alone. testHookSecret runs where a seed is read from a file. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// A bridge/share file a sidecar does not sign with: not its path's share, a cert that is no ShareCert of the share
	// at the file's generation, a seed the cert does not certify, an expired cert, or a generation below one this
	// sidecar already used.
	ErrBridgeShareSignerRefused = errors.New("bridge share signer refused")
	// The renewal did not land: no config writer runs here, this device holds no ShareKey of the share, or the write
	// was refused. A signer that did not land is dropped, never written again.
	ErrBridgeShareSignerRenew = errors.New("bridge share signer renewal did not land")
)

// bridge/share/<share_id hex>, the path of a share's BridgeShareSigner in the accepting network's head.
func ConfigHeadBridgeSharePath(shareId Id) string {
	return ConfigHeadBridgeSharePrefix + hex.EncodeToString(shareId.Bytes())
}

// A share's signer as a sidecar role may sign with it (the file's use row). Its seed stays inside: nothing prints
// or exports it.
type BridgeShareSignerUse struct {
	ShareId Id
	// g, the config generation the cert names.
	Generation uint64
	// When the cert stops admitting: a delegation it signs is admitted until the earlier of this and its own.
	NotAfterMs int64
	// The Signed ShareCert as the file carries it, which every delegation the signer signs carries too.
	CertSigned []byte

	seed []byte
}

// The use's ids alone: never the seed (I-7).
func (self BridgeShareSignerUse) String() string {
	return fmt.Sprintf("BridgeShareSignerUse(share %s, generation %d)", self.ShareId, self.Generation)
}

// As String, so %#v prints no seed either.
func (self BridgeShareSignerUse) GoString() string {
	return self.String()
}

// The ids alone, as String: the seed is in no encoding of a use.
func (self BridgeShareSignerUse) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{"share_id": self.ShareId.String(), "generation": self.Generation, "not_after_ms": self.NotAfterMs})
}

// Signs body as the share's signer (bridge.ShareSignerSign), for WindowDelegationSigned.
func (self *BridgeShareSignerUse) sign(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
	if purpose != bridge.SignedPurposeWindowDelegation || signedType != bridge.SignedType_SIGNED_WINDOW_DELEGATION {
		return nil, fmt.Errorf("%w: a share signer signs only share-link window delegations", ErrBridgeShareSignerRefused)
	}
	return bridge.ShareSignerSign(self.ShareId.Bytes(), self.seed, body)
}

// Reads a share's signer file from a head as the use row holds it, but the floor and the cert's expiry, which
// BridgeShareSignerUsable judges at a time. Nil and no error for a head with no file for the share.
func ReadBridgeShareSigner(head *ConfigHead, shareId Id) (*BridgeShareSignerUse, error) {
	if head == nil || shareId == (Id{}) {
		return nil, nil
	}
	fileBytes := head.File(ConfigHeadBridgeSharePath(shareId))
	if fileBytes == nil {
		return nil, nil
	}
	file := &bridge.BridgeShareSigner{}
	if err := proto.Unmarshal(fileBytes, file); err != nil || bridgeLedgerUnknownFields(file) {
		return nil, fmt.Errorf("%w: the file is no BridgeShareSigner", ErrBridgeShareSignerRefused)
	}
	if !bytes.Equal(file.GetShareId(), shareId.Bytes()) {
		return nil, fmt.Errorf("%w: a file of another share than its path's", ErrBridgeShareSignerRefused)
	}
	if len(file.GetSignerSeed()) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: a seed of %d bytes", ErrBridgeShareSignerRefused, len(file.GetSignerSeed()))
	}
	// the cert's signature is the host's to verify, under a ShareKey this network's sidecars do not pin: here it is
	// held to the file
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(file.GetShareCert(), signed); err != nil || signed.GetType() != uint32(bridge.SignedType_SIGNED_SHARE_CERT) {
		return nil, fmt.Errorf("%w: a cert that is no Signed ShareCert", ErrBridgeShareSignerRefused)
	}
	cert := &bridge.ShareCert{}
	if err := proto.Unmarshal(signed.GetBody(), cert); err != nil || 0 < len(cert.ProtoReflect().GetUnknown()) {
		return nil, fmt.Errorf("%w: a cert that does not decode", ErrBridgeShareSignerRefused)
	}
	seed := bytes.Clone(file.GetSignerSeed())
	testHookSecret("bridge-share-signer", seed)
	switch {
	case !bytes.Equal(cert.GetShareId(), shareId.Bytes()) || !bytes.Equal(signed.GetSignerId(), shareId.Bytes()):
		return nil, fmt.Errorf("%w: a cert of another share", ErrBridgeShareSignerRefused)
	case cert.GetConfigGeneration() != file.GetConfigGeneration() || cert.GetConfigGeneration() == 0:
		return nil, fmt.Errorf("%w: a cert of another generation than the file's", ErrBridgeShareSignerRefused)
	case !bytes.Equal(cert.GetSignerPublicKey(), ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)):
		return nil, fmt.Errorf("%w: a seed the cert does not certify", ErrBridgeShareSignerRefused)
	}
	return &BridgeShareSignerUse{
		ShareId: shareId, Generation: cert.GetConfigGeneration(), NotAfterMs: cert.GetNotAfterMs(),
		CertSigned: bytes.Clone(file.GetShareCert()), seed: seed,
	}, nil
}

// Whether a sidecar signs with use at nowMs given the newest generation it already used for the share (the file's
// use row): its cert unexpired and its generation no lower than the floor.
func BridgeShareSignerUsable(use *BridgeShareSignerUse, floor uint64, nowMs int64) error {
	switch {
	case use == nil:
		return fmt.Errorf("%w: no signer", ErrBridgeShareSignerRefused)
	case use.NotAfterMs <= nowMs:
		return fmt.Errorf("%w: its cert expired: the share lapsed until its holder renews", ErrBridgeShareSignerRefused)
	case use.Generation < floor:
		return fmt.Errorf("%w: a generation below one this sidecar already used", ErrBridgeShareSignerRefused)
	}
	return nil
}

// The newest generation a sidecar has signed with, a share: the floor of the use row, kept across restarts in the
// store it is given so a restart never signs below it. Safe for concurrent use.
type BridgeShareSignerFloors struct {
	stateLock sync.Mutex
	floors    map[Id]uint64
	// nil keeps the floors in memory alone
	save func(floors map[Id]uint64) error
}

// Floors starting from loaded, saved through save at each rise; a nil save keeps them in memory alone.
func NewBridgeShareSignerFloors(loaded map[Id]uint64, save func(floors map[Id]uint64) error) *BridgeShareSignerFloors {
	floors := map[Id]uint64{}
	for shareId, generation := range loaded {
		floors[shareId] = generation
	}
	return &BridgeShareSignerFloors{floors: floors, save: save}
}

// The newest generation used for a share, 0 for none.
func (self *BridgeShareSignerFloors) Floor(shareId Id) uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.floors[shareId]
}

// Notes that a signer of generation is about to sign for the share: the floor rises to it, saved before the caller
// signs, so a kill after the signature leaves the floor at least there. An error leaves the floor as it was.
func (self *BridgeShareSignerFloors) Use(shareId Id, generation uint64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if generation <= self.floors[shareId] {
		return nil
	}
	if self.save != nil {
		next := map[Id]uint64{}
		for held, floor := range self.floors {
			next[held] = floor
		}
		next[shareId] = generation
		if err := self.save(next); err != nil {
			return err
		}
	}
	self.floors[shareId] = generation
	return nil
}

// Tunables of the renewal.
type BridgeShareSignerSettings struct {
	// How often a holder looks at each share it holds the ShareKey of: 1 h (DESIGN-DETAILS 12.2.2's
	// ShareRenewInterval).
	RenewInterval time.Duration
	// A cert with less than this left is renewed at its generation: 72 h, §17.9's 3 days (ShareRenewBelow).
	RenewBelow time.Duration
	// How many times one renewal starts over after the write gate refused its head and the generation moved: 3.
	// Each start makes a new seed. Non-positive tries once.
	RenewAttemptCount int
}

// DESIGN-DETAILS 12.2.2's values.
func DefaultBridgeShareSignerSettings() *BridgeShareSignerSettings {
	return &BridgeShareSignerSettings{
		RenewInterval:     time.Hour,
		RenewBelow:        72 * time.Hour,
		RenewAttemptCount: 3,
	}
}

// What a renewer is built over.
type BridgeShareSignerRenewerArgs struct {
	// The ShareKeys this device holds.
	Keyring *BridgeShareKeyring
	// The accepting network's verified config, and the reader of the head its base names.
	Config BridgeFilerConfig
	Heads  ConfigHeadReader
	// This device's config writer; nil, or a nil answer, where none runs: nothing is renewed.
	HeadWriter func() BridgeHeadWriter
	// The config repo's generation as this device holds it (GkmClient.CurrentRepoKey's).
	Generation func(ctx context.Context) (uint64, error)
	Clock      Clock
	Log        Logger
	Settings   *BridgeShareSignerSettings
}

// The renew loop of a ShareKey's holder (the file's renew row).
type BridgeShareSignerRenewer struct {
	args     *BridgeShareSignerRenewerArgs
	settings *BridgeShareSignerSettings
	clock    Clock
	log      Logger
}

// A renewer over args, whose Keyring, Config and Generation are required.
func NewBridgeShareSignerRenewer(args *BridgeShareSignerRenewerArgs) (*BridgeShareSignerRenewer, error) {
	if args == nil || args.Keyring == nil || args.Config == nil || args.Generation == nil {
		return nil, fmt.Errorf("%w: a share signer renewer needs its keyring, config and generation", errInvalidSettings)
	}
	settings := DefaultBridgeShareSignerSettings()
	if args.Settings != nil {
		if 0 < args.Settings.RenewInterval {
			settings.RenewInterval = args.Settings.RenewInterval
		}
		if 0 < args.Settings.RenewBelow {
			settings.RenewBelow = args.Settings.RenewBelow
		}
		settings.RenewAttemptCount = args.Settings.RenewAttemptCount
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	return &BridgeShareSignerRenewer{args: args, settings: settings, clock: clock, log: loggerOrDefault(args.Log)}, nil
}

// The share's signer file in the newest verified head, nil for none or one no sidecar signs with, which is due.
func (self *BridgeShareSignerRenewer) current(ctx context.Context, shareId Id) (*BridgeShareSignerUse, error) {
	state := self.args.Config.State()
	if state == nil {
		return nil, fmt.Errorf("%w: no verified state", ErrBridgeShareSignerRenew)
	}
	base := state.Base()
	if base == nil || self.args.Heads == nil {
		return nil, nil
	}
	head, err := self.args.Heads.ReadConfigHead(ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
	if err != nil {
		return nil, fmt.Errorf("%w: the head: %w", ErrBridgeShareSignerRenew, err)
	}
	use, err := ReadBridgeShareSigner(head, shareId)
	if err != nil {
		// a file no sidecar signs with is replaced
		return nil, nil
	}
	return use, nil
}

// One pass for one share (the file's renew row): true when a new signer landed, false when none was due.
// ErrBridgeShareSignerRenew when one was due and did not land; the signer it made is dropped.
func (self *BridgeShareSignerRenewer) Renew(ctx context.Context, shareId Id) (bool, error) {
	var writer BridgeHeadWriter
	if self.args.HeadWriter != nil {
		writer = self.args.HeadWriter()
	}
	if writer == nil {
		return false, fmt.Errorf("%w: no config writer runs for this network on this device", ErrBridgeShareSignerRenew)
	}
	var failed error
	for range max(1, self.settings.RenewAttemptCount) {
		generation, err := self.args.Generation(ctx)
		if err != nil || generation == 0 {
			return false, fmt.Errorf("%w: the config's generation: %w", ErrBridgeShareSignerRenew, errors.Join(err, failed))
		}
		current, err := self.current(ctx, shareId)
		if err != nil {
			return false, err
		}
		nowMs := self.clock.Now().UnixMilli()
		due := current == nil || current.Generation < generation || current.NotAfterMs-nowMs < self.settings.RenewBelow.Milliseconds()
		if !due {
			return false, nil
		}
		// every start certifies a new seed: one that did not land is never written again
		file, err := self.args.Keyring.Certify(ctx, shareId, generation)
		if err != nil {
			return false, fmt.Errorf("%w: %w", ErrBridgeShareSignerRenew, err)
		}
		fileBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(file)
		if err != nil {
			return false, fmt.Errorf("%w: %w", ErrBridgeShareSignerRenew, err)
		}
		barrierKey := shareId.String()
		// between the holder's read of the generation and its write: where a removal's rotation races it
		testHookBarrier("bridge_share_signer.renew.write.before", barrierKey)
		_, err = writer.SaveHead(ctx, func(head *ConfigHead) (*ConfigHead, error) {
			return head.WithFile(ConfigHeadBridgeSharePath(shareId), fileBytes)
		})
		testHookBarrier("bridge_share_signer.renew.write.after", barrierKey)
		if err == nil {
			return true, nil
		}
		failed = errors.Join(failed, err)
		// the write was refused: start over only where the generation moved, which is what the write gate refuses
		// a stale one for; anything else waits for the next pass
		next, generationErr := self.args.Generation(ctx)
		if generationErr != nil || next == generation {
			break
		}
	}
	return false, fmt.Errorf("%w: %w", ErrBridgeShareSignerRenew, failed)
}

// One pass over every share this device holds the ShareKey of. Answers the shares renewed, and the passes that failed
// joined.
func (self *BridgeShareSignerRenewer) RenewAll(ctx context.Context) ([]Id, error) {
	shareIds, err := self.args.Keyring.Shares(ctx)
	if err != nil {
		return nil, err
	}
	renewed := []Id{}
	var failed error
	for _, shareId := range shareIds {
		landed, err := self.Renew(ctx, shareId)
		if err != nil {
			failed = errors.Join(failed, err)
			continue
		}
		if landed {
			renewed = append(renewed, shareId)
		}
	}
	return renewed, failed
}

// Runs passes each RenewInterval, and at once at each signal of wake, a new generation's, until ctx ends. A failed
// pass is logged by its shares' ids and tried again at the next.
func (self *BridgeShareSignerRenewer) Run(ctx context.Context, wake <-chan struct{}) {
	for {
		if _, err := self.RenewAll(ctx); err != nil && ctx.Err() == nil {
			self.log.Warningf("bridge share signers: a renewal did not land: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-self.clock.After(self.settings.RenewInterval):
		}
	}
}

// Whether a share's holder is still one (the file's comment; §17.9's bound row): the device that filed the share's
// aliases stands, and its member is still an admin. A holder device revoked, or a holder member gone from the
// AdminSet, can certify until the sharing network revokes the share, so the accepting network's devices raise
// bridge_alarm share_holder_removed naming it, and the sharing network re-invites. removed names the device where it
// was revoked, and the member's first device otherwise; the zero id for a holder that stands.
func BridgeShareHolderRemoved(state *ConfigState, aliasSigner Id) (removed Id, gone bool) {
	if state == nil || aliasSigner == (Id{}) {
		return Id{}, false
	}
	row := state.SidecarRow(aliasSigner)
	if row == nil || row.GetRevokedAt() != 0 {
		return aliasSigner, true
	}
	statement := &configStatement{signers: []ConfigSigner{{Kind: ConfigSignerSidecar, SidecarId: aliasSigner}}, timeMs: state.TimeMs()}
	if !bridgeSignerAdmin(state, statement) {
		return aliasSigner, true
	}
	return Id{}, false
}

// A sink that signs a share's links again: the device role, in process or over §18.6's ResignShares.
type BridgeShareResigner interface {
	// The shares whose signer changed. Each live window client of their links is signed again, for its later
	// contracts.
	ResignShares(shareIds []Id) error
}

// The share signers a component signs with (the file's use and resign rows): the ones its newest compiled head
// carries, and the floors. Safe for concurrent use.
type bridgeComponentShares struct {
	stateLock sync.Mutex
	// by share, the signer the newest compiled head carries; a file no sidecar signs with is absent
	signers map[Id]*BridgeShareSignerUse
	// nil until the first use: floors kept in memory alone
	floors *BridgeShareSignerFloors
}

// Takes the head a compile read: every bridge/share/<share_id hex> file a sidecar would sign with. Answers the shares
// whose signer is new or changed, in id order; a share whose file left the head stops signing and is not answered.
func (self *bridgeComponentShares) setHead(head *ConfigHead) []Id {
	signers := map[Id]*BridgeShareSignerUse{}
	if head != nil {
		for _, path := range head.Paths() {
			encoded, ok := strings.CutPrefix(path, ConfigHeadBridgeSharePrefix)
			if !ok {
				continue
			}
			decoded, err := hex.DecodeString(encoded)
			if err != nil {
				continue
			}
			shareId, err := IdFromBytes(decoded)
			if err != nil || ConfigHeadBridgeSharePath(shareId) != path {
				continue
			}
			if use, err := ReadBridgeShareSigner(head, shareId); err == nil && use != nil {
				signers[shareId] = use
			}
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	changed := []Id{}
	for shareId, use := range signers {
		if held := self.signers[shareId]; held == nil || !bytes.Equal(held.CertSigned, use.CertSigned) {
			changed = append(changed, shareId)
		}
	}
	self.signers = signers
	slices.SortFunc(changed, func(a Id, b Id) int { return bytes.Compare(a.Bytes(), b.Bytes()) })
	return changed
}

// Sets where the floors are kept, before the first use: loaded now, and saved at each rise.
func (self *bridgeComponentShares) setFloors(floors *BridgeShareSignerFloors) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.floors = floors
}

// The share's signer for a signature at now, its floor raised first (the file's use row).
// ErrBridgeShareSignerRefused where the head carries none this sidecar signs with.
func (self *bridgeComponentShares) use(shareId Id, now time.Time) (*BridgeShareSignerUse, error) {
	use, floors := func() (*BridgeShareSignerUse, *BridgeShareSignerFloors) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.floors == nil {
			self.floors = NewBridgeShareSignerFloors(nil, nil)
		}
		return self.signers[shareId], self.floors
	}()
	if err := BridgeShareSignerUsable(use, floors.Floor(shareId), now.UnixMilli()); err != nil {
		return nil, err
	}
	// saved before the signature, so a kill after it leaves the floor at least here
	if err := floors.Use(shareId, use.Generation); err != nil {
		return nil, fmt.Errorf("%w: its generation was not kept: %w", ErrBridgeShareSignerRefused, err)
	}
	return use, nil
}

// Has the device role sign the shares' links again (the file's resign row): a share's new signer reaches its live
// window clients' later contracts. A sink that signs no share's links takes nothing.
func (self *BridgeComponent) ResignShares(shareIds []Id) {
	sink := self.currentSink()
	resigner, ok := sink.(BridgeShareResigner)
	if !ok || len(shareIds) == 0 {
		return
	}
	if err := resigner.ResignShares(shareIds); err != nil {
		self.log.Warningf("[bridge]%s the device role did not re-sign %d shares: %v", self.args.NetworkId, len(shareIds), err)
	}
}
