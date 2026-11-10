// keychain.wrap's HPKE copy of R_n, and the sealer that keeps it on the member's current recovery binding (§5.9,
// D-CORE-10, D-CORE-14, R-CORE-15, I-1; owner decisions 23, 62).
//
// The copy is keychain.wrap's recovery field (keys_root.go), sealed to the X-Wing key of the member's current binding
// in this network only, so one membership's code opens one network's roots and nothing of any other network's, even
// with the whole state directory in hand:
//
//	version 1 | key_sha256, 32 B | xwing public key, 1,216 B | sealed length, uint16 | sealed
//	sealed    HPKE base mode (X-Wing, HKDF-SHA256, ChaCha20-Poly1305), enc || ct, with
//	          info "urnetwork-sidecar-v1/local/keychain-recovery" and aad version || network id || key_sha256
//	plaintext root count, uint8 | root ...; root: root generation, uint64 | R_n, 32 B; newest first
//
// key_sha256 is the binding's name, SHA-256 of its Ed25519 key. The copy holds every root keychain.wrap holds, so it
// opens what U opens there, mid-rotation included, and it carries the public key it was sealed to, so a rotation
// re-seals it to the same binding with no other state (keys_rotate.go). The public key is a public key: the log seals
// it from api (plan-TEAM-sealed-field-format), and this file never leaves the device.
//
// recoverySealer is the Sidecar's half. As this device applies each entry of the log it compares the binding the copy
// is sealed to with its member's current one and re-seals on any difference: a RecoveryBind or RecoveryRebind, §7.9's
// cascade voiding one, or a signer outside P signing a restored one again. No copy is kept while none is current: with
// no binding, under a binding a void restored (which takes no wrap until signed again, §5.9), or while this device
// does not hold the current binding's X-Wing key. That key rides sealed in the binding's record, so this device learns
// it by signing the binding itself (identity_recovery_bind.go) or by opening the record's sealed body with the config
// repo's key (SidecarConfigKeys). Each seal and each end is recorded with the AuthPin this device stood at, in the core
// namespace's recovery_seal record, and those spans are what recovery_rebind's Evidence names at a void (§5.6's alarm
// row, §5.9's backup rule): a backup taken inside a span holds a sealing to that binding, which no re-seal reaches.
//
// The file is written before the record, so a kill between the two leaves a copy the next comparison finds and seals
// again. testHookSecret sees each root the copy opens; testHookBarrier brackets each re-seal. On every leg.

package sidecar

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The copy's format values.
const (
	keychainRecoveryVersion = 1
	keychainRecoveryInfo    = localKeyInfoPrefix + "keychain-recovery"
	// an X-Wing public key's bytes (gkm_keys.go's gkmXWingPublicKeyByteCount, the same key type)
	recoveryXwingPublicKeyByteCount = gkmXWingPublicKeyByteCount
)

// The sealer's record in the core namespace, and how many spans it keeps: a format bound, the oldest going first.
const (
	recoverySealRecordName    = "recovery_seal"
	recoverySealRecordVersion = 1
	recoverySealSpanMaxCount  = 256
)

var (
	errKeychainRecoveryFormat = fmt.Errorf("%w: keychain.wrap's recovery copy does not decode", ErrSidecarStoreFailed)
	// keychain.wrap holds no HPKE copy: no binding was current when it was last sealed.
	ErrRecoveryCopyAbsent = errors.New("keychain.wrap holds no recovery copy")
	// The copy does not open under these keys: another membership's code, another network's, or a retired binding's.
	ErrRecoveryCopyKey = errors.New("the recovery code does not open this network's keychain")
)

// keychain.wrap's recovery field, decoded.
type keychainRecoveryCopy struct {
	keySha256      []byte
	xwingPublicKey []byte
	// enc || ct
	sealed []byte
}

// The field's bytes.
func (self *keychainRecoveryCopy) encode() []byte {
	encoded := make([]byte, 0, 1+len(self.keySha256)+len(self.xwingPublicKey)+2+len(self.sealed))
	encoded = append(encoded, keychainRecoveryVersion)
	encoded = append(encoded, self.keySha256...)
	encoded = append(encoded, self.xwingPublicKey...)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(self.sealed)))
	return append(encoded, self.sealed...)
}

// A recovery field's content, or ErrSidecarStoreFailed. Total, bounded by its input.
func decodeKeychainRecoveryCopy(encoded []byte) (*keychainRecoveryCopy, error) {
	cursor := &wrapCursor{remaining: encoded}
	if cursor.takeUint8() != keychainRecoveryVersion {
		return nil, errKeychainRecoveryFormat
	}
	recoveryCopy := &keychainRecoveryCopy{
		keySha256:      bytes.Clone(cursor.take(sha256.Size)),
		xwingPublicKey: bytes.Clone(cursor.take(recoveryXwingPublicKeyByteCount)),
	}
	recoveryCopy.sealed = bytes.Clone(cursor.take(int(cursor.takeUint16())))
	if cursor.failed || !cursor.finished() || len(recoveryCopy.sealed) == 0 {
		return nil, errKeychainRecoveryFormat
	}
	return recoveryCopy, nil
}

// The copy's additional data.
func keychainRecoveryAdditionalData(networkId Id, keySha256 []byte) []byte {
	additionalData := make([]byte, 0, 1+len(networkId)+len(keySha256))
	additionalData = append(additionalData, keychainRecoveryVersion)
	additionalData = append(additionalData, networkId[:]...)
	return append(additionalData, keySha256...)
}

// Seals wrap's roots, each opened in generationRoots, to a binding's X-Wing public key.
func sealKeychainRecoveryCopy(wrap *keychainWrap, generationRoots map[uint64][]byte, keySha256 []byte, xwingPublicKey []byte) (*keychainRecoveryCopy, error) {
	if len(keySha256) != sha256.Size || len(xwingPublicKey) != recoveryXwingPublicKeyByteCount {
		return nil, fmt.Errorf("%w: a binding of a %d-byte hash and a %d-byte key", ErrRecoveryKeys, len(keySha256), len(xwingPublicKey))
	}
	publicKey, err := hpke.MLKEM768X25519().NewPublicKey(xwingPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecoveryKeys, err)
	}
	plaintext := make([]byte, 0, 1+len(wrap.roots)*(8+localKeyByteCount))
	defer clear(plaintext)
	plaintext = append(plaintext, byte(len(wrap.roots)))
	for i := range wrap.roots {
		root := generationRoots[wrap.roots[i].generation]
		if len(root) != localKeyByteCount {
			return nil, fmt.Errorf("%w: a root to seal is not open", ErrSidecarStoreFailed)
		}
		plaintext = binary.BigEndian.AppendUint64(plaintext, wrap.roots[i].generation)
		plaintext = append(plaintext, root...)
	}
	encapsulation, sender, err := hpke.NewSender(publicKey, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(keychainRecoveryInfo))
	if err != nil {
		return nil, storeFault(err)
	}
	ciphertext, err := sender.Seal(keychainRecoveryAdditionalData(wrap.networkId, keySha256), plaintext)
	if err != nil {
		return nil, storeFault(err)
	}
	return &keychainRecoveryCopy{
		keySha256:      bytes.Clone(keySha256),
		xwingPublicKey: bytes.Clone(xwingPublicKey),
		sealed:         append(encapsulation, ciphertext...),
	}, nil
}

// Every root the copy holds, by generation, opened with a code's X-Wing key, and the newest generation.
// ErrRecoveryCopyKey when the key is not the one it was sealed to in this network.
func (self *keychainRecoveryCopy) open(networkId Id, privateKey hpke.PrivateKey) (map[uint64][]byte, uint64, error) {
	if privateKey == nil || privateKey.KEM().ID() != hpke.MLKEM768X25519().ID() || len(self.sealed) <= gkmXWingEncapsulationByteCount {
		return nil, 0, ErrRecoveryCopyKey
	}
	recipient, err := hpke.NewRecipient(self.sealed[:gkmXWingEncapsulationByteCount], privateKey, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(keychainRecoveryInfo))
	if err != nil {
		return nil, 0, ErrRecoveryCopyKey
	}
	plaintext, err := recipient.Open(keychainRecoveryAdditionalData(networkId, self.keySha256), self.sealed[gkmXWingEncapsulationByteCount:])
	if err != nil {
		return nil, 0, ErrRecoveryCopyKey
	}
	defer clear(plaintext)
	cursor := &wrapCursor{remaining: plaintext}
	rootCount := int(cursor.takeUint8())
	generationRoots := map[uint64][]byte{}
	fail := func() (map[uint64][]byte, uint64, error) {
		for _, root := range generationRoots {
			clear(root)
		}
		return nil, 0, errKeychainRecoveryFormat
	}
	if rootCount == 0 || keychainWrapMaxRootCount < rootCount {
		return fail()
	}
	newestGeneration := uint64(0)
	for i := 0; i < rootCount; i += 1 {
		generation := cursor.takeUint64()
		root := bytes.Clone(cursor.take(localKeyByteCount))
		if cursor.failed || generation == 0 || (i != 0 && newestGeneration <= generation) || generationRoots[generation] != nil {
			clear(root)
			return fail()
		}
		if i == 0 {
			newestGeneration = generation
		}
		testHookSecret("R_n", root)
		generationRoots[generation] = root
	}
	if !cursor.finished() {
		return fail()
	}
	return generationRoots, newestGeneration, nil
}

// Re-seals next's recovery copy, if it holds one, over next's roots, each opened in generationRoots, to the binding the
// copy names: what a rotation does as keychain.wrap's roots change, so the code opens what U opens.
func resealKeychainRecoveryCopy(next *keychainWrap, generationRoots map[uint64][]byte) error {
	if len(next.recovery) == 0 {
		return nil
	}
	recoveryCopy, err := decodeKeychainRecoveryCopy(next.recovery)
	if err != nil {
		return err
	}
	resealed, err := sealKeychainRecoveryCopy(next, generationRoots, recoveryCopy.keySha256, recoveryCopy.xwingPublicKey)
	if err != nil {
		return err
	}
	next.recovery = resealed.encode()
	return nil
}

// Seals network n's keychain.wrap copy to a binding, replacing any before, or with a nil key removes it. The network's
// keychain must open: a locked, failed or lost store changes nothing (D-CORE-15).
func (self *SidecarInstance) sealRecoveryCopy(networkId Id, keySha256 []byte, xwingPublicKey []byte) error {
	testHookBarrier("keys.recovery_seal.before", networkId.String())
	err := func() error {
		self.operationLock.Lock()
		defer self.operationLock.Unlock()
		if _, err := self.keychainWithLock(networkId); err != nil {
			return err
		}
		wrap, err := self.readKeychainWrap(networkId)
		if err != nil {
			return err
		}
		if xwingPublicKey == nil {
			if len(wrap.recovery) == 0 && self.wrapDurable(keychainWrapPath(networkId)) {
				return nil
			}
			wrap.recovery = nil
			return self.writeWrapWithLock(keychainWrapPath(networkId), wrap.encode())
		}
		generationRoots, err := self.openRoots(wrap)
		if err != nil {
			return err
		}
		defer func() {
			for _, root := range generationRoots {
				clear(root)
			}
		}()
		recoveryCopy, err := sealKeychainRecoveryCopy(wrap, generationRoots, keySha256, xwingPublicKey)
		if err != nil {
			return err
		}
		wrap.recovery = recoveryCopy.encode()
		return self.writeWrapWithLock(keychainWrapPath(networkId), wrap.encode())
	}()
	testHookBarrier("keys.recovery_seal.after", networkId.String())
	return err
}

// The binding network n's keychain.wrap copy is sealed to, its key hash; nil while it holds none.
func (self *SidecarInstance) recoveryCopyKeySha256(networkId Id) ([]byte, error) {
	wrap, err := self.readKeychainWrap(networkId)
	if err != nil {
		return nil, err
	}
	if len(wrap.recovery) == 0 {
		return nil, nil
	}
	recoveryCopy, err := decodeKeychainRecoveryCopy(wrap.recovery)
	if err != nil {
		return nil, err
	}
	return recoveryCopy.keySha256, nil
}

// Network n's roots as its recovery code opens them from keychain.wrap, by generation, with the newest generation:
// §5.9's "R_n by n's recovery code", for a device whose U is lost (CORE-M2-06's recovery adopts them under a new U).
// It reads only n's file, so it needs no unlock, and a code of any other network or membership answers
// ErrRecoveryCopyKey. The caller clears the roots.
func (self *SidecarInstance) openRecoveryRoots(networkId Id, keys *RecoveryKeys) (map[uint64][]byte, uint64, error) {
	wrap, err := self.readKeychainWrap(networkId)
	if err != nil {
		return nil, 0, err
	}
	if len(wrap.recovery) == 0 {
		return nil, 0, ErrRecoveryCopyAbsent
	}
	recoveryCopy, err := decodeKeychainRecoveryCopy(wrap.recovery)
	if err != nil {
		return nil, 0, err
	}
	privateKey, err := keys.XwingPrivateKey()
	if err != nil {
		return nil, 0, err
	}
	if !bytes.Equal(recoveryCopy.keySha256, keys.KeySha256()) {
		return nil, 0, ErrRecoveryCopyKey
	}
	return recoveryCopy.open(networkId, privateKey)
}

// The config repo's keys as recovery reads them: the GkmClient's CurrentRepoKey and RepoKey of the config repo, which
// KEYS installs. A binding's body rides sealed under them (plan-TEAM-sealed-field-format). Safe for concurrent use.
type SidecarConfigKeys interface {
	// The key of the config's current generation, which a new binding's body seals under.
	CurrentConfigKey(ctx context.Context) (*EvsRepoKey, error)
	// The key of generation, nil for one this device does not hold.
	ConfigKeyAt(generation uint64) *EvsRepoKey
}

// An authority that also says whether a member's binding in effect is one a cascade void restored, which takes no wrap
// until a signer outside P signs it again (§7.9, §5.9): ConfigState.BindingRestored. Optional beside SidecarAuthority:
// an authority without it holds no restored binding.
type SidecarRecoveryAuthority interface {
	BindingRestored(memberId Id) bool
}

// ConfigState's own answer.
func (self *ConfigAuthority) BindingRestored(memberId Id) bool {
	state := self.client.State()
	return state != nil && state.BindingRestored(memberId)
}

// One span keychain.wrap was sealed to a binding.
type recoverySealSpan struct {
	KeySha256 []byte `json:"key_sha256"`
	// the marshalled AuthPin this device stood at when it sealed, and when the copy was replaced or removed
	SealedAt []byte `json:"sealed_at"`
	EndedAt  []byte `json:"ended_at,omitempty"`
}

// The sealer's persisted record.
type recoverySealRecord struct {
	Version int `json:"version"`
	// the X-Wing public keys of this member's bindings this device learned, by key hash in hex
	PublicKeys map[string][]byte `json:"public_keys"`
	// every span, oldest first; the last is open while the copy stands
	Spans []*recoverySealSpan `json:"spans"`
}

// The open span, nil while no copy stands.
func (self *recoverySealRecord) openSpan() *recoverySealSpan {
	if len(self.Spans) == 0 || self.Spans[len(self.Spans)-1].EndedAt != nil {
		return nil
	}
	return self.Spans[len(self.Spans)-1]
}

// The sealer's state on a Sidecar, under its own lock, which is held across the record's and the file's writes and
// never under stateLock.
type recoverySealer struct {
	stateLock  sync.Mutex
	configKeys SidecarConfigKeys
	// the binding the copy was last seen sealed to, in hex, empty for none; unknown until the first comparison
	sealedTo      string
	sealedToKnown bool
}

// Installs keys as the config repo's keys, which a binding's sealed body opens and seals under, replacing any before;
// the answer removes them, if they are still the installed ones. With none installed this device signs no binding and
// learns no other device's.
func (self *Sidecar) InstallConfigKeys(keys SidecarConfigKeys) func() {
	func() {
		self.recovery.stateLock.Lock()
		defer self.recovery.stateLock.Unlock()
		self.recovery.configKeys = keys
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			self.recovery.stateLock.Lock()
			defer self.recovery.stateLock.Unlock()
			if self.recovery.configKeys == keys {
				self.recovery.configKeys = nil
			}
		})
	}
}

// The installed config keys, nil for none.
func (self *Sidecar) configKeys() SidecarConfigKeys {
	self.recovery.stateLock.Lock()
	defer self.recovery.stateLock.Unlock()
	return self.recovery.configKeys
}

// The record as persisted, or a fresh one.
func (self *Sidecar) loadRecoverySealRecord() (*recoverySealRecord, error) {
	secrets := self.currentCoreSecrets()
	if secrets == nil {
		return nil, ErrSidecarNoIdentity
	}
	encoded, err := secrets.Get(recoverySealRecordName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return &recoverySealRecord{Version: recoverySealRecordVersion, PublicKeys: map[string][]byte{}}, nil
	}
	if err != nil {
		return nil, err
	}
	record := &recoverySealRecord{}
	if err := json.Unmarshal(encoded, record); err != nil || record.Version != recoverySealRecordVersion {
		return nil, fmt.Errorf("%w: the recovery seal record", ErrSidecarStoreFailed)
	}
	if record.PublicKeys == nil {
		record.PublicKeys = map[string][]byte{}
	}
	return record, nil
}

// Persists the record, the oldest spans past the bound going first.
func (self *Sidecar) persistRecoverySealRecord(record *recoverySealRecord) error {
	secrets := self.currentCoreSecrets()
	if secrets == nil {
		return ErrSidecarNoIdentity
	}
	if recoverySealSpanMaxCount < len(record.Spans) {
		record.Spans = record.Spans[len(record.Spans)-recoverySealSpanMaxCount:]
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return secrets.Put(recoverySealRecordName, encoded)
}

// Keeps a binding's X-Wing public key, by its key hash, so the sealer can seal to it once it is current.
func (self *Sidecar) keepRecoveryPublicKey(keySha256 []byte, xwingPublicKey []byte) error {
	if len(keySha256) != sha256.Size || len(xwingPublicKey) != recoveryXwingPublicKeyByteCount {
		return ErrRecoveryKeys
	}
	self.recovery.stateLock.Lock()
	defer self.recovery.stateLock.Unlock()
	record, err := self.loadRecoverySealRecord()
	if err != nil {
		return err
	}
	name := hex.EncodeToString(keySha256)
	if bytes.Equal(record.PublicKeys[name], xwingPublicKey) {
		return nil
	}
	record.PublicKeys[name] = bytes.Clone(xwingPublicKey)
	return self.persistRecoverySealRecord(record)
}

// Opens a RecoveryBind's or RecoveryRebind's sealed body, as carried in a statement's bytes, and checks it against
// what the record shows in the clear: the Ed25519 key hashes to ed25519_public_key_sha256, the X-Wing key has its
// length, and genesis_sig verifies for this network's genesis where genesisSha256 is given. The member it binds and
// the binding's key hash come back with the body.
func openRecoveryBindBody(signedType bridge.SignedType, statementBytes []byte, configKeys SidecarConfigKeys, networkId Id, genesisSha256 []byte) (Id, []byte, *protocol.RecoveryBindBody, error) {
	var header *bridge.StatementHeader
	var memberBytes []byte
	var keySha256 []byte
	var sealedBody []byte
	switch signedType {
	case bridge.SignedType_SIGNED_RECOVERY_BIND:
		bind := &protocol.RecoveryBind{}
		if err := proto.Unmarshal(statementBytes, bind); err != nil {
			return Id{}, nil, nil, err
		}
		header, memberBytes, keySha256, sealedBody = bind.GetHeader(), bind.GetMemberId(), bind.GetEd25519PublicKeySha256(), bind.GetSealedBody()
	case bridge.SignedType_SIGNED_RECOVERY_REBIND:
		rebind := &protocol.RecoveryRebind{}
		if err := proto.Unmarshal(statementBytes, rebind); err != nil {
			return Id{}, nil, nil, err
		}
		header, memberBytes, keySha256, sealedBody = rebind.GetHeader(), rebind.GetMemberId(), rebind.GetEd25519PublicKeySha256(), rebind.GetSealedBody()
	default:
		return Id{}, nil, nil, fmt.Errorf("%w: type %#x is no recovery binding", ErrRecoveryKeys, int32(signedType))
	}
	memberId, err := IdFromBytes(memberBytes)
	if err != nil {
		return Id{}, nil, nil, err
	}
	if configKeys == nil {
		return memberId, keySha256, nil, ErrConfigSealGenerationMissing
	}
	body := &protocol.RecoveryBindBody{}
	if _, err := OpenConfigBody(sealedBody, NewConfigSealContext(signedType, header), configKeys.ConfigKeyAt, body); err != nil {
		return memberId, keySha256, nil, err
	}
	if !bytes.Equal(RecoveryKeySha256(body.GetEd25519PublicKey()), keySha256) || len(body.GetXwingPublicKey()) != recoveryXwingPublicKeyByteCount {
		return memberId, keySha256, nil, fmt.Errorf("%w: the sealed body is not the binding its record names", ErrRecoveryKeys)
	}
	if genesisSha256 != nil {
		if err := VerifyRecoveryGenesisSig(body.GetEd25519PublicKey(), networkId, genesisSha256, body.GetGenesisSig()); err != nil {
			return memberId, keySha256, nil, err
		}
	}
	return memberId, keySha256, body, nil
}

// Learns a binding of this device's member from its record, a RecoveryBind's or RecoveryRebind's statement bytes as
// the log or the config head carries them, keeping its X-Wing public key for the sealer: what a device that did not
// sign the binding runs for it, the sealer for each entry it applies and a reader of the config head for one filed
// before this device followed the log. A binding of another member is ignored. An error leaves the key unknown, and
// the sealer keeps no copy to a key it does not hold.
func (self *Sidecar) LearnRecoveryBinding(signedType bridge.SignedType, statementBytes []byte) error {
	identity := self.currentIdentity()
	if identity == nil {
		return ErrSidecarNoIdentity
	}
	authority := self.authority()
	if authority == nil {
		return ErrSidecarActNoAuthority
	}
	own := authority.Admission(identity.SidecarId)
	if own == nil || 0 < len(own.TagIds) {
		return nil
	}
	var genesisSha256 []byte
	if anchor, err := self.Anchor(); err == nil && anchor != nil {
		genesisSha256 = anchor.GenesisSha256
	}
	memberId, keySha256, body, err := openRecoveryBindBody(signedType, statementBytes, self.configKeys(), identity.NetworkId, genesisSha256)
	if err != nil {
		return err
	}
	if memberId != own.MemberId {
		return nil
	}
	return self.keepRecoveryPublicKey(keySha256, body.GetXwingPublicKey())
}

// The binding the copy should be sealed to at authority's newest state: the member's current binding's key hash and
// X-Wing key, or nil for no copy, with why. Runs under the sealer's lock.
func (self *Sidecar) recoverySealTargetWithLock(authority SidecarAuthority, identity *SidecarIdentity, record *recoverySealRecord) ([]byte, []byte, string) {
	own := authority.Admission(identity.SidecarId)
	if own == nil || own.Row == nil || 0 < len(own.TagIds) || own.Ephemeral {
		return nil, nil, "this device is no member's durable device"
	}
	binding := authority.CurrentBinding(own.MemberId)
	if binding == nil || len(binding.GetKeySha256()) != sha256.Size {
		return nil, nil, "its member has no current binding"
	}
	if restores, ok := authority.(SidecarRecoveryAuthority); ok && restores.BindingRestored(own.MemberId) {
		return nil, nil, "its member's binding is one a void restored"
	}
	xwingPublicKey := record.PublicKeys[hex.EncodeToString(binding.GetKeySha256())]
	if len(xwingPublicKey) != recoveryXwingPublicKeyByteCount {
		return nil, nil, "this device does not hold the current binding's key"
	}
	return binding.GetKeySha256(), xwingPublicKey, ""
}

// Brings keychain.wrap's copy to this device's member's current binding at authority's newest state, re-sealing only
// on a difference, and records the span that ends and the one that starts with pin, the position this device stands
// at. What the sealer runs as it applies each entry and once at each install of an authority.
func (self *Sidecar) syncRecoverySeal(authority SidecarAuthority, pin *bridge.AuthPin) error {
	identity := self.currentIdentity()
	if identity == nil || self.instance == nil {
		return nil
	}
	self.recovery.stateLock.Lock()
	defer self.recovery.stateLock.Unlock()
	record, err := self.loadRecoverySealRecord()
	if err != nil {
		return err
	}
	keySha256, xwingPublicKey, why := self.recoverySealTargetWithLock(authority, identity, record)
	want := hex.EncodeToString(keySha256)
	if !self.recovery.sealedToKnown {
		// the file says what it is sealed to, whatever the record last recorded
		sealedTo, err := self.instance.recoveryCopyKeySha256(identity.NetworkId)
		if err != nil {
			return err
		}
		self.recovery.sealedTo = hex.EncodeToString(sealedTo)
		self.recovery.sealedToKnown = true
	}
	openSpan := record.openSpan()
	recorded := ""
	if openSpan != nil {
		recorded = hex.EncodeToString(openSpan.KeySha256)
	}
	if self.recovery.sealedTo == want && recorded == want {
		return nil
	}
	if self.recovery.sealedTo != want {
		self.recovery.sealedToKnown = false
		if err := self.instance.sealRecoveryCopy(identity.NetworkId, keySha256, xwingPublicKey); err != nil {
			return err
		}
		self.recovery.sealedTo = want
		self.recovery.sealedToKnown = true
		if want == "" {
			self.log.Infof("[keys]keychain.wrap holds no recovery copy: %s", why)
		} else {
			self.log.Infof("[keys]keychain.wrap is sealed to the member's current recovery binding")
		}
	}
	pinBytes, err := proto.Marshal(pin)
	if err != nil {
		return err
	}
	if openSpan != nil {
		openSpan.EndedAt = pinBytes
	}
	if want != "" {
		record.Spans = append(record.Spans, &recoverySealSpan{KeySha256: bytes.Clone(keySha256), SealedAt: pinBytes})
	}
	return self.persistRecoverySealRecord(record)
}

// The sealer's step for one applied entry: learns each binding of this device's member the entry put into effect, then
// brings the copy to the member's current binding.
func (self *Sidecar) applyRecoverySealEntry(authority SidecarAuthority, entry *SidecarAuthorityEntry) {
	if entry == nil || entry.Pin == nil {
		return
	}
	for _, effect := range entry.Effects {
		if effect.Type != bridge.SignedType_SIGNED_RECOVERY_BIND && effect.Type != bridge.SignedType_SIGNED_RECOVERY_REBIND {
			continue
		}
		if err := self.LearnRecoveryBinding(effect.Type, effect.Body); err != nil && self.log.V(1).Enabled() {
			self.log.Infof("[keys]a recovery binding's key was not learned at %d: %s", entry.Pin.GetVersion(), err)
		}
	}
	if err := self.syncRecoverySeal(authority, entry.Pin); err != nil {
		self.log.Warningf("[keys]keychain.wrap's recovery copy was not brought to the current binding at %d: %s", entry.Pin.GetVersion(), err)
	}
}

// The spans keychain.wrap was sealed to the binding of keySha256, each as its two marshalled AuthPins: where this
// device sealed and where the copy was replaced or removed, the second nil while the copy stands.
func (self *Sidecar) RecoverySealSpans(keySha256 []byte) ([][2][]byte, error) {
	self.recovery.stateLock.Lock()
	defer self.recovery.stateLock.Unlock()
	record, err := self.loadRecoverySealRecord()
	if err != nil {
		return nil, err
	}
	spans := [][2][]byte{}
	for _, span := range record.Spans {
		if bytes.Equal(span.KeySha256, keySha256) {
			spans = append(spans, [2][]byte{bytes.Clone(span.SealedAt), bytes.Clone(span.EndedAt)})
		}
	}
	return spans, nil
}

// recovery_rebind's Evidence at a void (§5.6's alarm row): the newest span keychain.wrap was sealed to the voided
// binding, from its seal to its end, or to pin, the void's own entry, while the copy still stands. Both empty when
// this device never sealed to it.
func (self *Sidecar) recoverySealEvidence(keySha256 []byte, pin *bridge.AuthPin) [2][]byte {
	spans, err := self.RecoverySealSpans(keySha256)
	if err != nil || len(spans) == 0 {
		return [2][]byte{}
	}
	evidence := spans[len(spans)-1]
	if evidence[1] == nil {
		if pinBytes, err := proto.Marshal(pin); err == nil {
			evidence[1] = pinBytes
		}
	}
	return evidence
}
