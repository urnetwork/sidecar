//go:build !ios_extension && !sidecar_http

// Forwarding's setup in the sidecar role (BRIDGE-M8-06; D-SDK-32, D-TEAM-33, D-CORE-13, I-6, I-7, I-8, owner decision
// 197, DESIGN-DETAILS 4.2.6): the one act a sidecar S runs for its app's VPN component in its network, after which the
// component's forwarding role needs nothing of S. The component generates its keys and gives S their public halves
// (bridge.ForwardingKeys); S answers a bridge.ForwardingHandOff. Six steps, each idempotent, with the record
// forward/setup in S's network store written before step 1 and after each step:
//
//	1 sign      S's forwarding Delegation {pubkey, reader_xwing_public_key, forward: S, and where S's client is the
//	            device client's child, that client and its key}, through sidecarAct as S's own confirmed act; its
//	            Signed bytes recorded, which the act keeps pending until they land
//	2 file      the act posts them, and the log is followed to their entry; a repeat finds the Delegation's row by its
//	            id or posts the same bytes again, and a refusal at a moved tip (409) signs anew at the new pin
//	3 key       the reader key's object at gkm (UploadDelegationKey), which gkm takes once its state holds the row
//	4 wrap      the late DelegationWrap of the config's current generation to that key (DeliverDelegationWraps)
//	5 mint      F, forward_only, a child of S's client under S's own token and DPoP proof, with the component's
//	            client public key: api answers a repeat for the same key with F again, so a resume mints no second F
//	6 hand off  Pending, the key set, F's id, token and strict_exp, the config repo and group, the Signed Delegation
//	            and the position that carried it
//
// A repeat with the record's key_set_id resumes after the steps done, and always mints and hands off again, since the
// record keeps no token; one with another key set starts over, and its Delegation supersedes the earlier one where it
// lands (§7.9's forwarding row). One setup runs at a time on a sidecar.
//
// When it is due (ForwardingSetupDue): while no forwarding Delegation of S is live, at each new client generation of S
// (enrollment, re-enrollment, pairing), and at any run RotationInterval (90 days) or more after the last; after a
// DelegationRevoke of S's Delegation by any signer but S, only once S's person confirms in the app's UI
// (ConfirmForwardingSetup), never through MCP. A revocation whose entry this device no longer keeps reads as another's,
// so the person decides where the device cannot tell.
//
// The hand-off carries no key of S: the component's keys stay in the component and S's in S (DESIGN-DETAILS 4.3's
// KeysStayPut). F's token is in it for the component alone: nothing logs it, the record never holds it, and no caller
// but the setup's gets it (I-7). The setup is reached by the app's own sidecar role in process and, for a paired
// remote-mode app, by the daemon's control methods (daemon_bridge.go); MCP has no path to it.
//
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// No setup is installed on this sidecar, the network is not its own, or it holds no identity, config state or
	// config key: nothing was signed.
	ErrForwardingSetupUnavailable = errors.New("forwarding setup unavailable")
	// The keys are not a set a setup takes, or another set was recorded under their key_set_id: nothing was signed.
	ErrForwardingSetupRefused = errors.New("forwarding setup refused")
	// A step did not finish: the record keeps the steps done, and a repeat with the same keys resumes after them.
	ErrForwardingSetupIncomplete = errors.New("forwarding setup incomplete")
	// Another signer revoked this sidecar's forwarding Delegation: a setup waits for its person's confirmation in the app.
	ErrForwardingSetupNeedsConfirm = errors.New("forwarding setup waits for the person's confirmation after another's revocation")
)

// Why a sidecar's forwarding setup is due (DESIGN-DETAILS 4.2.6's when row).
type ForwardingSetupReason string

const (
	// Not due.
	ForwardingSetupNotDue ForwardingSetupReason = ""
	// S runs a client generation newer than the last setup's: an enrollment, a re-enrollment or a pairing.
	ForwardingSetupNewClientGeneration ForwardingSetupReason = "new_client_generation"
	// The last setup is RotationInterval old.
	ForwardingSetupNinetyDays ForwardingSetupReason = "ninety_days"
	// No forwarding Delegation of S is live.
	ForwardingSetupNoneLive ForwardingSetupReason = "none_live"
	// Another signer revoked S's forwarding Delegation, and S's person has not confirmed setting it up again.
	ForwardingSetupForeignRevocation ForwardingSetupReason = "foreign_revocation"
)

// The store directory, its class and the record's name: format values of the setup's own state.
const (
	forwardingSetupDirectory     = "forward"
	forwardingSetupClass         = "forward"
	forwardingSetupRecordName    = "setup"
	forwardingSetupRecordVersion = 1
)

// The forwarding client's name and spec as api lists it to the network's admins.
const (
	forwardingClientDescription = "forwarding"
	forwardingClientDeviceSpec  = "sidecar forwarding"
)

// Tunables of forwarding's setup.
type ForwardingSetupSettings struct {
	// How long a setup waits for its Delegation's entry to apply before it answers incomplete: 60 s, a follow's round
	// trips with room. Non-positive waits not at all, so a setup resumes at its next call unless the entry applied.
	LandTimeout time.Duration
	// How long after a setup an app's run sets it up again: 90 days (DESIGN-DETAILS 4.2.6's when row), which bounds
	// how long one forwarding key serves. Non-positive makes every run's setup due.
	RotationInterval time.Duration
	// How many Delegations a setup signs when api refuses one at a tip that moved past its pin: 3, since each refusal
	// means another entry landed first. Non-positive signs one.
	FileAttemptCount int
}

// DESIGN-DETAILS 4.2.6's values.
func DefaultForwardingSetupSettings() *ForwardingSetupSettings {
	return &ForwardingSetupSettings{
		LandTimeout:      60 * time.Second,
		RotationInterval: 90 * 24 * time.Hour,
		FileAttemptCount: 3,
	}
}

// What the setup reads of the network's config: TEAM-M2-10's ConfigClient is one.
type ForwardingSetupConfig interface {
	// The newest verified state, nil before one.
	State() *ConfigState
	// The state at or past n, once the follow reaches it.
	WaitFor(ctx context.Context, n uint64) (*ConfigState, error)
	// The entries the log keeps in [from, through], read safely beside the follower.
	BridgeEntries(from uint64, through uint64) []*BridgeConfigEntry
}

var _ ForwardingSetupConfig = (*ConfigClient)(nil)

// What a host gives the setup beyond the sidecar itself.
type ForwardingSetupSources struct {
	// The network's verified config.
	Config ForwardingSetupConfig
	// PUT /gkm/delegation-keys/<delegation_id>: GkmApi.UploadDelegationKey.
	UploadDelegationKey func(ctx context.Context, delegationId []byte, readerKey []byte) error
	// The late DelegationWraps of the config's current generation: GkmGroupClient.DeliverDelegationWraps.
	DeliverDelegationWraps func(ctx context.Context, delegationId []byte) error
	// Where the record lives; nil is this sidecar's network store's forward/ directory.
	Store SidecarStore
	// Nil is the defaults.
	Settings *ForwardingSetupSettings
}

// The installed setup: its sources, and one setup at a time.
type sidecarForwardingSetup struct {
	sources  *ForwardingSetupSources
	settings *ForwardingSetupSettings
	runLock  sync.Mutex
}

// What a setup keeps between its steps. JSON in the sealed store, its byte fields in base64.
type forwardingSetupRecord struct {
	Version int `json:"version"`
	// The key set the steps are for, and its public halves as given, deterministically encoded.
	KeySetId []byte `json:"key_set_id"`
	Keys     []byte `json:"keys"`
	// The last step done, 0 to 6.
	Step int `json:"step"`
	// Step 1's Signed Delegation and its delegation_id.
	SignedDelegation []byte `json:"signed_delegation,omitempty"`
	DelegationId     []byte `json:"delegation_id,omitempty"`
	// Step 2's entry.
	DelegationAtN     uint64 `json:"delegation_at_n,omitempty"`
	DelegationAtChain []byte `json:"delegation_at_chain,omitempty"`
	// Step 5's forwarding client.
	ForwardClientId *Id `json:"forward_client_id,omitempty"`
	// The client generation and the time of the last setup that handed off.
	Generation  int64 `json:"generation,omitempty"`
	CompletedMs int64 `json:"completed_ms,omitempty"`
	// The position of another signer's DelegationRevoke the person confirmed setting up past.
	ConfirmedRevocationAt uint64 `json:"confirmed_revocation_at,omitempty"`
}

// Installs forwarding's setup over sources, replacing any before; the answer removes it, if it is still installed.
// With none installed every setup is refused.
func (self *Sidecar) InstallForwardingSetup(sources *ForwardingSetupSources) func() {
	setup := &sidecarForwardingSetup{sources: sources, settings: DefaultForwardingSetupSettings()}
	if sources != nil && sources.Settings != nil {
		setup.settings = sources.Settings
	}
	self.forwardingSetup.Store(setup)
	var once sync.Once
	return func() {
		once.Do(func() {
			self.forwardingSetup.CompareAndSwap(setup, &sidecarForwardingSetup{})
		})
	}
}

// The installed setup for networkId, with this sidecar's identity. ErrForwardingSetupUnavailable with none, for another
// network, or before an identity.
func (self *Sidecar) forwardingSetupFor(networkId Id) (*sidecarForwardingSetup, *SidecarIdentity, error) {
	setup, _ := self.forwardingSetup.Load().(*sidecarForwardingSetup)
	if setup == nil || setup.sources == nil || setup.sources.Config == nil {
		return nil, nil, fmt.Errorf("%w: no setup is installed", ErrForwardingSetupUnavailable)
	}
	identity := self.currentIdentity()
	if identity == nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrForwardingSetupUnavailable, ErrSidecarNoIdentity)
	}
	if identity.NetworkId != networkId {
		return nil, nil, fmt.Errorf("%w: another network's", ErrForwardingSetupUnavailable)
	}
	return setup, identity, nil
}

// The store the record lives in.
func (self *Sidecar) forwardingSetupStore(setup *sidecarForwardingSetup) (SidecarStore, error) {
	if setup.sources.Store != nil {
		return setup.sources.Store, nil
	}
	return self.LocalStore().Directory(forwardingSetupDirectory, forwardingSetupClass)
}

// The record, nil for none.
func (self *Sidecar) loadForwardingSetupRecord(setup *sidecarForwardingSetup) (*forwardingSetupRecord, error) {
	store, err := self.forwardingSetupStore(setup)
	if err != nil {
		return nil, err
	}
	reader, err := store.Open(forwardingSetupRecordName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	record := &forwardingSetupRecord{}
	if err := json.NewDecoder(reader).Decode(record); err != nil {
		return nil, fmt.Errorf("the forwarding setup record does not read: %w", err)
	}
	if record.Version != forwardingSetupRecordVersion {
		return nil, fmt.Errorf("the forwarding setup record is version %d", record.Version)
	}
	return record, nil
}

// Replaces the record, whole, at once.
func (self *Sidecar) saveForwardingSetupRecord(setup *sidecarForwardingSetup, record *forwardingSetupRecord) error {
	store, err := self.forwardingSetupStore(setup)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	writer, err := store.Create(forwardingSetupRecordName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(encoded); err != nil {
		return err
	}
	return writer.Commit()
}

// Holds the keys to the forms §7.9's forwarding row takes and a setup hands off: a 16-byte key_set_id, an Ed25519
// forwarding key, a 1,216-byte X-Wing reader key, F's Ed25519 ClientKey, and a host client both named or neither, which
// only a child of a device client names. The keys deterministically encoded, as the record keeps them.
func (self *Sidecar) checkForwardingKeys(keys *bridge.ForwardingKeys) ([]byte, error) {
	if keys == nil {
		return nil, fmt.Errorf("%w: no keys", ErrForwardingSetupRefused)
	}
	hostIdSize, hostKeySize := len(keys.GetHostClientId()), len(keys.GetHostClientPublicKey())
	switch {
	case len(keys.GetKeySetId()) != len(Id{}):
		return nil, fmt.Errorf("%w: a key_set_id of %d bytes", ErrForwardingSetupRefused, len(keys.GetKeySetId()))
	case len(keys.GetForwardPublicKey()) != ed25519.PublicKeySize:
		return nil, fmt.Errorf("%w: a forwarding key of %d bytes", ErrForwardingSetupRefused, len(keys.GetForwardPublicKey()))
	case len(keys.GetReaderXwingPublicKey()) != configXwingPublicKeyByteCount:
		return nil, fmt.Errorf("%w: a reader key of %d bytes", ErrForwardingSetupRefused, len(keys.GetReaderXwingPublicKey()))
	case len(keys.GetClientPublicKey()) != ed25519.PublicKeySize:
		return nil, fmt.Errorf("%w: a client key of %d bytes", ErrForwardingSetupRefused, len(keys.GetClientPublicKey()))
	case hostIdSize == 0 && hostKeySize == 0:
	case hostIdSize != len(Id{}) || hostKeySize != configHostClientPublicKeyByteCount:
		return nil, fmt.Errorf("%w: a host client of %d bytes and its key of %d", ErrForwardingSetupRefused, hostIdSize, hostKeySize)
	case !self.Paired():
		// only a child of a device client forwards for that device in its network; api checks which client it is
		return nil, fmt.Errorf("%w: a host client named by a sidecar that is no device client's child", ErrForwardingSetupRefused)
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(keys)
}

// Whether the entry at n that ended delegationId is a DelegationRevoke of it that this sidecar signed itself: false
// for another signer, for an end of any other kind, and for an entry the log no longer keeps.
func forwardingEndedBySelf(config ForwardingSetupConfig, n uint64, sidecarId Id, delegationId []byte) bool {
	entries := config.BridgeEntries(n, n)
	if len(entries) != 1 || entries[0].N != n {
		return false
	}
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(entries[0].EntryBytes, entry); err != nil || entry.GetKind() != bridge.AuthEntryKindStatement {
		return false
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(entry.GetBody(), signed); err != nil || bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_DELEGATION_REVOKE {
		return false
	}
	revoke := &protocol.DelegationRevoke{}
	if err := proto.Unmarshal(signed.GetBody(), revoke); err != nil || !bytes.Equal(revoke.GetDelegationId(), delegationId) {
		return false
	}
	return bytes.Equal(signed.GetSignerId(), sidecarId.Bytes()) && len(signed.GetKeyId()) == 0
}

// Why a setup is due at state for the record (the file's when row), in that order. A record's generation and time are
// its last setup that handed off, which a new key set's record keeps, so a setup started and not finished is due only
// as the one before it would be; a sidecar with no record reads as generation 0, set up never. An end of the record's
// Delegation while this sidecar is itself revoked is no revocation to confirm: nothing of it can set up again.
func (self *Sidecar) forwardingDue(setup *sidecarForwardingSetup, state *ConfigState, record *forwardingSetupRecord, identity *SidecarIdentity) ForwardingSetupReason {
	if record == nil {
		record = &forwardingSetupRecord{}
	}
	if len(record.DelegationId) != 0 {
		row := state.Delegation(record.DelegationId)
		admission := state.Sidecar(identity.SidecarId)
		if row != nil && row.GetEndedAt() != 0 && record.ConfirmedRevocationAt != row.GetEndedAt() &&
			admission != nil && admission.Row.GetRevokedAt() == 0 &&
			!forwardingEndedBySelf(setup.sources.Config, row.GetEndedAt(), identity.SidecarId, record.DelegationId) {
			return ForwardingSetupForeignRevocation
		}
	}
	switch {
	case state.ForwardingDelegation(identity.SidecarId) == nil:
		return ForwardingSetupNoneLive
	case record.Generation < identity.Generation:
		return ForwardingSetupNewClientGeneration
	case setup.settings.RotationInterval <= self.clock.Now().Sub(time.UnixMilli(record.CompletedMs)):
		return ForwardingSetupNinetyDays
	}
	return ForwardingSetupNotDue
}

// Why a setup is due in networkId (the file's when row), ForwardingSetupNotDue when it is not; an error where no setup
// is installed or no state is verified yet.
func (self *Sidecar) ForwardingSetupDue(networkId Id) (ForwardingSetupReason, error) {
	setup, identity, err := self.forwardingSetupFor(networkId)
	if err != nil {
		return ForwardingSetupNotDue, err
	}
	state := setup.sources.Config.State()
	if state == nil {
		return ForwardingSetupNotDue, fmt.Errorf("%w: no verified state", ErrForwardingSetupUnavailable)
	}
	record, err := self.loadForwardingSetupRecord(setup)
	if err != nil {
		return ForwardingSetupNotDue, err
	}
	return self.forwardingDue(setup, state, record, identity), nil
}

// The person's confirmation in the app that the setup may run again after another signer revoked this sidecar's
// forwarding Delegation (the file's when row): it holds for that revocation alone. Nothing where none waits. An app's UI
// calls it, and a paired remote-mode app's confirmed control call; MCP has no path to it.
func (self *Sidecar) ConfirmForwardingSetup(networkId Id) error {
	setup, identity, err := self.forwardingSetupFor(networkId)
	if err != nil {
		return err
	}
	setup.runLock.Lock()
	defer setup.runLock.Unlock()
	state := setup.sources.Config.State()
	if state == nil {
		return fmt.Errorf("%w: no verified state", ErrForwardingSetupUnavailable)
	}
	record, err := self.loadForwardingSetupRecord(setup)
	if err != nil || record == nil || self.forwardingDue(setup, state, record, identity) != ForwardingSetupForeignRevocation {
		return err
	}
	record.ConfirmedRevocationAt = state.Delegation(record.DelegationId).GetEndedAt()
	return self.saveForwardingSetupRecord(setup, record)
}

// Runs forwarding's setup in networkId for the VPN component's keys and answers its hand-off (the file's six steps).
// ErrForwardingSetupIncomplete where a step did not finish, which a repeat with the same keys resumes;
// ErrForwardingSetupNeedsConfirm after another signer's revocation the person has not confirmed.
func (self *Sidecar) SetUpForwarding(ctx context.Context, networkId Id, keys *bridge.ForwardingKeys) (*bridge.ForwardingHandOff, error) {
	setup, identity, err := self.forwardingSetupFor(networkId)
	if err != nil {
		return nil, err
	}
	keysBytes, err := self.checkForwardingKeys(keys)
	if err != nil {
		return nil, err
	}
	if self.sidecarApi == nil {
		return nil, fmt.Errorf("%w: no api client to mint the forwarding client", ErrForwardingSetupUnavailable)
	}
	configKeys := self.configKeys()
	if configKeys == nil {
		return nil, fmt.Errorf("%w: no config key", ErrForwardingSetupUnavailable)
	}
	repoKey, err := configKeys.CurrentConfigKey(ctx)
	if err != nil || repoKey == nil {
		return nil, fmt.Errorf("%w: no current config key: %w", ErrForwardingSetupUnavailable, errors.Join(err, ErrConfigSealGenerationMissing))
	}
	setup.runLock.Lock()
	defer setup.runLock.Unlock()
	config := setup.sources.Config
	state := config.State()
	if state == nil {
		return nil, fmt.Errorf("%w: no verified state", ErrForwardingSetupUnavailable)
	}
	record, err := self.loadForwardingSetupRecord(setup)
	if err != nil {
		return nil, err
	}
	if self.forwardingDue(setup, state, record, identity) == ForwardingSetupForeignRevocation {
		return nil, ErrForwardingSetupNeedsConfirm
	}
	switch {
	case record == nil || !bytes.Equal(record.KeySetId, keys.GetKeySetId()):
		// a new key set starts over; its Delegation supersedes the one before
		fresh := &forwardingSetupRecord{Version: forwardingSetupRecordVersion, KeySetId: bytes.Clone(keys.GetKeySetId()), Keys: keysBytes}
		if record != nil {
			fresh.Generation, fresh.CompletedMs, fresh.ConfirmedRevocationAt = record.Generation, record.CompletedMs, record.ConfirmedRevocationAt
		}
		record = fresh
		if err := self.saveForwardingSetupRecord(setup, record); err != nil {
			return nil, err
		}
	case !bytes.Equal(record.Keys, keysBytes):
		return nil, fmt.Errorf("%w: another key set was recorded under its key_set_id", ErrForwardingSetupRefused)
	}

	// 1 and 2: the Delegation, signed and filed, and its entry applied
	if record.Step < 2 {
		if err := self.fileForwardingDelegation(ctx, setup, record, keys, identity); err != nil {
			return nil, err
		}
	}
	// 3: the reader key's object at gkm
	if record.Step < 3 {
		if setup.sources.UploadDelegationKey == nil {
			return nil, fmt.Errorf("%w: no gkm to hold the reader key", ErrForwardingSetupIncomplete)
		}
		if err := setup.sources.UploadDelegationKey(ctx, record.DelegationId, keys.GetReaderXwingPublicKey()); err != nil {
			return nil, fmt.Errorf("%w: the reader key: %w", ErrForwardingSetupIncomplete, err)
		}
		if err := self.advanceForwardingSetup(setup, record, 3); err != nil {
			return nil, err
		}
	}
	// 4: the late DelegationWrap of the config's current generation
	if record.Step < 4 {
		if setup.sources.DeliverDelegationWraps == nil {
			return nil, fmt.Errorf("%w: no gkm to deliver the config's key", ErrForwardingSetupIncomplete)
		}
		if err := setup.sources.DeliverDelegationWraps(ctx, record.DelegationId); err != nil {
			return nil, fmt.Errorf("%w: the config's DelegationWrap: %w", ErrForwardingSetupIncomplete, err)
		}
		if err := self.advanceForwardingSetup(setup, record, 4); err != nil {
			return nil, err
		}
	}
	// 5: F, again on every hand-off, since the record keeps no token and api answers the same key with the same F
	minted, err := self.sidecarApi.AuthClient(ctx, &SidecarAuthClientArgs{
		SourceClientId:   &identity.ClientId,
		Description:      forwardingClientDescription,
		DeviceSpec:       forwardingClientDeviceSpec,
		DeclaresNoEgress: true,
		ForwardOnly:      true,
		ClientPublicKey:  bytes.Clone(keys.GetClientPublicKey()),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: the forwarding client: %w", ErrForwardingSetupIncomplete, err)
	}
	strictExp := sidecarJwtExpiration(minted.ByClientJwt)
	if !minted.AdminRefused || !minted.StrictExp || minted.ClientId == (Id{}) || strictExp.IsZero() {
		// a client whose answer does not confirm its marks is kept nowhere (§5.6)
		return nil, fmt.Errorf("%w: api's forwarding client does not confirm admin_refused and strict_exp", ErrForwardingSetupIncomplete)
	}
	if record.ForwardClientId != nil && *record.ForwardClientId != minted.ClientId && record.Step < 6 {
		self.log.Warningf("[bridge]%s a resumed setup's forwarding client is not the one minted before", networkId)
	}
	forwardClientId := minted.ClientId
	record.ForwardClientId = &forwardClientId
	if err := self.advanceForwardingSetup(setup, record, 5); err != nil {
		return nil, err
	}
	// 6: the hand-off, with no key of S's
	pending := CompileBridgePending(state, identity)
	pending.ForwardDelegationId = bytes.Clone(record.DelegationId)
	handOff := &bridge.ForwardingHandOff{
		Pending:          pending,
		KeySetId:         bytes.Clone(record.KeySetId),
		ForwardClientId:  minted.ClientId.Bytes(),
		ForwardClientJwt: minted.ByClientJwt,
		StrictExpMs:      strictExp.UnixMilli(),
		ConfigRepoId:     bytes.Clone(state.Genesis().GetConfigRepoId()),
		ConfigGroupId:    repoKey.GroupId().Bytes(),
		SignedDelegation: bytes.Clone(record.SignedDelegation),
		DelegationAt:     &bridge.AuthPin{Version: record.DelegationAtN, Chain: bytes.Clone(record.DelegationAtChain)},
	}
	record.Generation, record.CompletedMs = identity.Generation, self.clock.Now().UnixMilli()
	if err := self.advanceForwardingSetup(setup, record, 6); err != nil {
		return nil, err
	}
	if self.log.V(1).Enabled() {
		self.log.Infof("[bridge]%s set up forwarding at %d", networkId, record.DelegationAtN)
	}
	return handOff, nil
}

// Records a step done.
func (self *Sidecar) advanceForwardingSetup(setup *sidecarForwardingSetup, record *forwardingSetupRecord, step int) error {
	record.Step = step
	testHookBarrier("bridge_forward_setup.step.before", fmt.Sprint(step))
	err := self.saveForwardingSetupRecord(setup, record)
	testHookBarrier("bridge_forward_setup.step.after", fmt.Sprint(step))
	return err
}

// Steps 1 and 2: signs the Delegation where the record holds none, through sidecarAct, which keeps its bytes pending
// until they land, and records them with the position api answered; then follows the log to that position. A repeat
// finds the Delegation's row, or the position recorded, or posts its pending bytes once more for theirs; bytes that are
// neither in the log nor pending were refused or passed their not_after, so it signs anew. A refusal at a moved tip
// signs anew, up to FileAttemptCount; any other drops the bytes, so a repeat signs anew. Where the bytes landed while
// their answer was lost and the follow has not applied them, a resume signs a second Delegation, which supersedes the
// first: no reach is lost, and the record names the one handed off.
func (self *Sidecar) fileForwardingDelegation(ctx context.Context, setup *sidecarForwardingSetup, record *forwardingSetupRecord,
	keys *bridge.ForwardingKeys, identity *SidecarIdentity) error {
	config := setup.sources.Config
	// drops the recorded bytes, which never land, so the next pass signs anew
	drop := func() error {
		record.SignedDelegation, record.DelegationId, record.DelegationAtN = nil, nil, 0
		return self.advanceForwardingSetup(setup, record, 0)
	}
	// a refusal at a tip that moved past the bytes' pin signs anew while attempts remain
	refused := func(err error, attempt int) (bool, error) {
		if dropErr := drop(); dropErr != nil {
			return false, dropErr
		}
		apiErr := &SidecarApiError{}
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusConflict && attempt+1 < max(1, setup.settings.FileAttemptCount) {
			return true, nil
		}
		return false, fmt.Errorf("%w: the forwarding Delegation: %w", ErrForwardingSetupRefused, err)
	}
	for attempt := 0; ; attempt += 1 {
		if record.Step < 1 {
			delegation := &protocol.Delegation{
				Pubkey:               bytes.Clone(keys.GetForwardPublicKey()),
				ReaderXwingPublicKey: bytes.Clone(keys.GetReaderXwingPublicKey()),
				Forward: &bridge.ForwardScope{
					ForwardSidecarId:    identity.SidecarId.Bytes(),
					HostClientId:        bytes.Clone(keys.GetHostClientId()),
					HostClientPublicKey: bytes.Clone(keys.GetHostClientPublicKey()),
				},
			}
			act, err := self.newAct(SidecarActConfirmed)
			if err != nil {
				return fmt.Errorf("%w: %w", ErrForwardingSetupUnavailable, err)
			}
			if err := act.Add(bridge.SignedType_SIGNED_DELEGATION, delegation); err != nil {
				return err
			}
			pins, runErr := act.Run(ctx, nil)
			if signed := act.Signed(); len(signed) == 1 {
				delegationId, err := DelegationId(signed[0])
				if err != nil {
					return err
				}
				record.SignedDelegation, record.DelegationId = signed[0], delegationId[:]
				if runErr == nil && len(pins) == 1 && pins[0] != nil {
					record.DelegationAtN = pins[0].GetVersion()
				}
				if err := self.advanceForwardingSetup(setup, record, 1); err != nil {
					return err
				}
			}
			switch {
			case errors.Is(runErr, ErrSidecarActRefused):
				// dropped from the pending records: the bytes never land, so they are no step done
				again, err := refused(runErr, attempt)
				if again {
					continue
				}
				return err
			case runErr != nil:
				// pending where it signed and its answer was lost, else nothing signed, which a repeat signs anew
				return fmt.Errorf("%w: the forwarding Delegation has not landed: %w", ErrForwardingSetupIncomplete, runErr)
			}
		}
		if row := config.State().Delegation(record.DelegationId); row != nil {
			record.DelegationAtN = row.GetAt()
		}
		if record.DelegationAtN == 0 {
			// a repeat whose answer was lost: its pending bytes once more, for their position
			pending, err := self.pendingStatement(record.SignedDelegation)
			if err != nil {
				return fmt.Errorf("%w: %w", ErrForwardingSetupIncomplete, err)
			}
			if pending == nil {
				if err := drop(); err != nil {
					return err
				}
				continue
			}
			pin, err := self.postPendingInOrder(ctx, pending)
			switch {
			case errors.Is(err, ErrSidecarActRefused):
				again, err := refused(err, attempt)
				if again {
					continue
				}
				return err
			case err != nil:
				return fmt.Errorf("%w: the forwarding Delegation is pending: %w", ErrForwardingSetupIncomplete, err)
			case pin == nil:
				return fmt.Errorf("%w: the forwarding Delegation's post answered no entry", ErrForwardingSetupIncomplete)
			}
			record.DelegationAtN = pin.GetVersion()
			if err := self.advanceForwardingSetup(setup, record, 1); err != nil {
				return err
			}
		}
		waitCtx, cancel := context.WithTimeout(ctx, setup.settings.LandTimeout)
		state, err := config.WaitFor(waitCtx, record.DelegationAtN)
		cancel()
		if err != nil {
			return fmt.Errorf("%w: the forwarding Delegation's entry has not applied: %w", ErrForwardingSetupIncomplete, err)
		}
		row := state.Delegation(record.DelegationId)
		if row == nil {
			// sequenced and refused by the rule, which every reader holds alike
			if err := drop(); err != nil {
				return err
			}
			return fmt.Errorf("%w: the log refused the forwarding Delegation", ErrForwardingSetupRefused)
		}
		chain, _ := state.chainAt(row.GetAt())
		record.DelegationAtN, record.DelegationAtChain = row.GetAt(), bytes.Clone(chain[:])
		return self.advanceForwardingSetup(setup, record, 2)
	}
}

// The pending statement whose Signed bytes are signed, nil where none is pending: it landed, was refused, or passed
// its not_after.
func (self *Sidecar) pendingStatement(signed []byte) (*sidecarPendingStatement, error) {
	pendings, err := self.pendingStatements()
	if err != nil {
		return nil, err
	}
	for _, pending := range pendings {
		if bytes.Equal(pending.signed, signed) {
			return pending, nil
		}
	}
	return nil, nil
}

// What a sidecar role's witness hint carries to its VPN component (§18.6's witness row): the newest pin it verified,
// §6.4's witnessed pin where one stands, and whether its full reading found a fork, which holds the component pending
// until a later witness clears it (DESIGN-DETAILS 4.2.5).
type ForwardingWitness struct {
	Pin *bridge.AuthPin
	// Whether Pin is §6.4's witnessed pin, not only this sidecar's verified one.
	Witnessed bool
	Fork      bool
	// Why a setup is due, which an app's run reads beside the hint.
	SetupDue ForwardingSetupReason
}

// The witness hint for networkId's VPN component (§18.6's witness row).
func (self *Sidecar) ForwardingWitness(networkId Id) (*ForwardingWitness, error) {
	setup, identity, err := self.forwardingSetupFor(networkId)
	if err != nil {
		return nil, err
	}
	state := setup.sources.Config.State()
	if state == nil {
		return nil, fmt.Errorf("%w: no verified state", ErrForwardingSetupUnavailable)
	}
	witness := &ForwardingWitness{Pin: proto.Clone(state.Pin()).(*bridge.AuthPin)}
	self.headCheckStatuses.stateLock.Lock()
	headCheck := self.headCheckStatuses.status
	self.headCheckStatuses.stateLock.Unlock()
	if witnessed, ok := headCheck.(interface{ WitnessedPin() *bridge.AuthPin }); ok {
		if pin := witnessed.WitnessedPin(); pin != nil && pin.GetVersion() <= state.Pin().GetVersion() {
			witness.Pin, witness.Witnessed = pin, true
		}
	}
	if forks, ok := setup.sources.Config.(interface{ Fork() *ConfigForkError }); ok && forks.Fork() != nil {
		witness.Fork = true
	}
	record, err := self.loadForwardingSetupRecord(setup)
	if err != nil {
		return nil, err
	}
	witness.SetupDue = self.forwardingDue(setup, state, record, identity)
	return witness, nil
}
