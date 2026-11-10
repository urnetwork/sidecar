// §10.5's key hierarchy above MLS: a repo's key generations RK_g, the commitment C_g that gen/<g> signs
// for each, what one generation derives, the ladder by which each opens the one before it, and the
// 72-byte seals of one key under another (§10.6's sizes). gkm holds each of these only as ciphertext or
// a hash (I-1).
//
// The bytes every reader must reproduce, as testdata/gkm/ladder.json pins them:
//
//	C_g          SHA-256("UR evs 1.0 commit" || repo_id || u64be(g) || RK_g)
//	K_<purpose>  HKDF-SHA256(RK_g, salt repo_id, info "UR evs 1.0 " || purpose || u64be(g) [|| group_id || u64be(e)])
//	seal         nonce[24] || XChaCha20-Poly1305(key, nonce, plaintext, aad), the nonce random
//	GenLink_g    seal(K_link_g, RK_{g-1}; aad repo_id || u64be(g) || u8(cause_g))
//	GenWrap_e    seal(KEK_e, RK_g; aad group_id || u64be(e) || u64be(g)), and LeafWrap alike
//	GroupInfo_e  seal(K_groupinfo, GroupInfo; aad group_id || u64be(e))
//
// §10.5 writes those AADs without widths. The ones here are its own elsewhere: u64be for a generation or
// an epoch, as C_g, the HKDF info and wrap_aad spell them, and one byte for an enum, as wrap_aad encodes
// its kinds (keys-ladder-aad-widths.md asks that §10.5 say so). Every id is 16 bytes, so each AAD has one
// reading.
//
// Trust runs one way. A key is accepted only against a gen/<g> statement the caller verified (GkmGeneration),
// when its C_g matches; the newer verified generation authenticates each GenLink, whose AAD carries the cause
// §11's checkpoint rule reads; and a key that is not there is refused, never defaulted (ePrint 2024/546), the RK_g
// of an EvsRepoKey that holds none, as a declared or nil one does not, included.
// `ref` derives from RK_1 at every generation (D-KEYS-22), so an EvsRepoKey that has not reached generation 1
// refuses it.
//
// On every leg, with no connect import. Every key this file creates, derives or unwraps passes through
// testHookSecret before its first use. Package-level functions are safe for concurrent use, and so is an
// EvsRepoKey, which never changes.

package sidecar

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hpke"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What RK_g derives (§10.5's content keys), each its own HKDF info.
const (
	// K_link_g, which seals RK_{g-1} into GenLink_g.
	EvsKeyPurposeLink = "link"
	// Wraps each object's random key (§11.7).
	EvsKeyPurposeFek = "fek"
	// Names, entry fields, push metadata and ref names (§11).
	EvsKeyPurposeManifest = "manifest"
	// Path tokens of path epoch p, from RK_p (§11.6).
	EvsKeyPurposePath = "path"
	// Ref ids and the search index's document keys, from RK_1 for the repo's life (D-KEYS-22).
	EvsKeyPurposeRef = "ref"
	// The seed of the generation's X-Wing drop key pair (D-KEYS-17; QD-466).
	EvsKeyPurposeDrop = "drop"
	// K_groupinfo, per (group_id, epoch): its context is GkmGroupInfoContext's.
	EvsKeyPurposeGroupInfo = "groupinfo"
	// The search index's keyed pad, per generation (§11.14).
	EvsKeyPurposeIndex = "index"
	// K_statement: the key a sealed field of a config record seals under (plan-TEAM-sealed-field-format,
	// config_seal.go).
	EvsKeyPurposeStatement = "statement"
)

// The formats of 10.5's records.
const (
	// group_id, repo_id, sidecar_id and member_id (QD-442).
	gkmIdByteCount = 16
	// RK_g and every key it derives.
	gkmRepoKeyByteCount = 32
	// C_g.
	gkmCommitmentByteCount = sha256.Size
	// AuthPin.chain, A_n.
	gkmAuthChainByteCount = sha256.Size
	// holders_sha256 and a recipient's key digest.
	gkmDigestByteCount = sha256.Size
	// KEK_e, MLS-Exporter("UR evs 1.0 kek", repo_id, 32).
	gkmKekByteCount = 32
	// A 32-byte key under a seal: nonce, key and tag, §10.6's 72 B.
	gkmSealedKeyByteCount = chacha20poly1305.NonceSizeX + gkmRepoKeyByteCount + chacha20poly1305.Overhead
	// group_id || u64be(e).
	gkmGroupInfoContextByteCount = gkmIdByteCount + 8
	// An X-Wing public key (§10.6's inputs).
	gkmXWingPublicKeyByteCount = 1216

	gkmKeyInfoPrefix    = "UR evs 1.0 "
	gkmCommitmentPrefix = "UR evs 1.0 commit"
	// The exporter label of KEK_e (§10.5).
	gkmKekLabel = "UR evs 1.0 kek"

	gkmGenRotatePurpose = "gen-rotate"
)

var (
	// A key this sidecar does not hold or cannot reach is refused, never defaulted (§10.5): a generation the
	// ladder has not reached, a statement that is not there, or RK_1 for `ref` before a walk reached it.
	ErrGkmKeyMissing = errors.New("gkm key missing")
	// A record that does not parse, or breaks its format, or an argument that cannot make one.
	ErrGkmMalformed = errors.New("gkm record malformed")
	// A seal that does not open, a key that does not match its commitment, or a signature that does not
	// verify.
	ErrGkmAuthentication = errors.New("gkm record failed authentication")
)

// Why a generation exists (GenRotate.cause, §10.5). Zero is no cause, and refused.
type GkmCause uint32

const (
	// It covers a shrink, an authorization expiry or a compromise retirement since its parent, or its parent
	// is poisoned (§10.9), so §11.7 checkpoints each file at its next write.
	GkmCauseRemove GkmCause = 1
	// `ur keys rotate`.
	GkmCauseRequest GkmCause = 2
	// The 30-day rotation.
	GkmCauseSchedule GkmCause = 3
)

// Whether the cause is one GenRotate may carry.
func (self GkmCause) valid() bool {
	return GkmCauseRemove <= self && self <= GkmCauseSchedule
}

// The admitted identity key of a signer, from the caller's verified state (§7.9). An error refuses what
// it signed.
type GkmIdentityKeyFunction func(signerId Id) ([]byte, error)

// Signs as this sidecar's identity key, in the shape of Sidecar.Sign (CORE-M1-05), so a Sidecar's method
// value is one. Signed.body must come back as the body given.
type GkmSignFunction func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error)

// One generation of one repo's key, RK_g, with what gen/<g> states of it: the generation pin
// {group_id, g, C_g} (§11.8), and the cause, auth pin and time §11 reads for its pins, its checkpoint after
// a REMOVE generation and its path epochs. It holds RK_1 once the ladder has reached generation 1, so `ref`
// derives at any generation. Immutable; every accessor returns a copy.
type EvsRepoKey struct {
	repoId     Id
	groupId    Id
	generation uint64
	commitment []byte
	// C_{g-1}, empty at generation 1
	parentCommitment []byte
	cause            GkmCause
	auth             *bridge.AuthPin
	timeMs           int64
	// GenLink_g, empty at generation 1
	genLink []byte
	repoKey []byte
	// nil until the ladder reaches generation 1
	firstRepoKey []byte
}

// The repo the key belongs to.
func (self *EvsRepoKey) RepoId() Id {
	return self.repoId
}

// The group whose gen/<g> statement names it.
func (self *EvsRepoKey) GroupId() Id {
	return self.groupId
}

// g.
func (self *EvsRepoKey) Generation() uint64 {
	return self.generation
}

// C_g, all 32 bytes.
func (self *EvsRepoKey) Commitment() []byte {
	return bytes.Clone(self.commitment)
}

// The generation pin a head carries (§11.8), in HeadCheck's form (§6.4).
func (self *EvsRepoKey) GenHead() *protocol.GenHead {
	return &protocol.GenHead{
		GroupId:    self.groupId.Bytes(),
		Generation: self.generation,
		Commitment: bytes.Clone(self.commitment),
	}
}

// What gen/<g> says the generation is for, which tells §11.7 that a REMOVE generation's first write to each
// file is a full checkpoint (R-KEYS-3).
func (self *EvsRepoKey) Cause() GkmCause {
	return self.cause
}

// The state KeyHolders was computed at (§7.9).
func (self *EvsRepoKey) Auth() *bridge.AuthPin {
	return proto.Clone(self.auth).(*bridge.AuthPin)
}

// gen/<g>'s evaluation time for expiries.
func (self *EvsRepoKey) Time() time.Time {
	return time.UnixMilli(self.timeMs)
}

// Whether `ref` derives here, which needs RK_1.
func (self *EvsRepoKey) HoldsFirst() bool {
	return self.firstRepoKey != nil
}

// ErrGkmKeyMissing unless this key holds its RK_g. Only this file's constructors fill one, so an EvsRepoKey any
// caller declares, or a nil one, holds none, and every use of the secret refuses it here rather than derive or seal
// from nothing (§10.5; ePrint 2024/546).
func (self *EvsRepoKey) checkHeld() error {
	if self == nil || len(self.repoKey) != gkmRepoKeyByteCount {
		return fmt.Errorf("%w: an EvsRepoKey that holds no RK_g", ErrGkmKeyMissing)
	}
	return nil
}

// The key of one purpose: HKDF-SHA256(RK_g, salt repo_id, info "UR evs 1.0 " || purpose || u64be(g) ||
// context), 32 bytes (§10.5). Only groupinfo takes a context, exactly GkmGroupInfoContext's, and every
// other purpose refuses one. ref derives from RK_1 with g = 1 at every generation, and is ErrGkmKeyMissing
// until the ladder has given this key RK_1. An unknown purpose is refused, and so is a key that holds no RK_g.
func (self *EvsRepoKey) DeriveKey(purpose string, context []byte) ([]byte, error) {
	if err := self.checkHeld(); err != nil {
		return nil, err
	}
	secret := self.repoKey
	generation := self.generation
	switch purpose {
	case EvsKeyPurposeRef:
		if self.firstRepoKey == nil {
			return nil, fmt.Errorf("%w: ref derives from RK_1, which no ladder walk has reached", ErrGkmKeyMissing)
		}
		secret = self.firstRepoKey
		generation = 1
	case EvsKeyPurposeGroupInfo:
		if len(context) != gkmGroupInfoContextByteCount {
			return nil, fmt.Errorf("%w: a groupinfo context of %d bytes", ErrGkmMalformed, len(context))
		}
	case EvsKeyPurposeLink, EvsKeyPurposeFek, EvsKeyPurposeManifest, EvsKeyPurposePath, EvsKeyPurposeDrop,
		EvsKeyPurposeIndex, EvsKeyPurposeStatement:
	default:
		return nil, fmt.Errorf("%w: no purpose %q", ErrGkmMalformed, purpose)
	}
	if purpose != EvsKeyPurposeGroupInfo && len(context) != 0 {
		return nil, fmt.Errorf("%w: purpose %q takes no context", ErrGkmMalformed, purpose)
	}
	return gkmDeriveKey(secret, self.repoId, purpose, generation, context)
}

// group_id || u64be(e), the groupinfo context of one group's epoch.
func GkmGroupInfoContext(groupId Id, epoch uint64) []byte {
	return binary.BigEndian.AppendUint64(groupId.Bytes(), epoch)
}

// The generation's X-Wing drop key pair, DeriveKeyPair(K_drop) (QD-466): what opens deposits sealed to its
// GenRotate's drop_public_key. Every generation derives one, and only a kind that takes deposits publishes
// it (D-KEYS-17).
func (self *EvsRepoKey) DropKeyPair() (hpke.PrivateKey, error) {
	dropKey, err := self.DeriveKey(EvsKeyPurposeDrop, nil)
	if err != nil {
		return nil, err
	}
	defer clear(dropKey)
	privateKey, err := hpke.MLKEM768X25519().DeriveKeyPair(dropKey)
	if err != nil {
		return nil, fmt.Errorf("gkm: drop key pair: %w", err)
	}
	if err := gkmHookPrivateKey("drop_private_key", privateKey); err != nil {
		return nil, err
	}
	return privateKey, nil
}

// The same key with RK_1 from first, the generation-1 key of its repo, so `ref` derives. A key that already
// holds RK_1 must hold this one.
func (self *EvsRepoKey) WithFirst(first *EvsRepoKey) (*EvsRepoKey, error) {
	if err := self.checkHeld(); err != nil {
		return nil, err
	}
	if first == nil || first.generation != 1 || first.repoId != self.repoId {
		return nil, fmt.Errorf("%w: not generation 1 of this repo", ErrGkmMalformed)
	}
	if self.firstRepoKey != nil && subtle.ConstantTimeCompare(self.firstRepoKey, first.repoKey) != 1 {
		return nil, fmt.Errorf("%w: another RK_1", ErrGkmAuthentication)
	}
	withFirst := *self
	withFirst.firstRepoKey = bytes.Clone(first.repoKey)
	return &withFirst, nil
}

// HKDF-SHA256 as DeriveKey does it, from secret, which is RK_g of generation g.
func gkmDeriveKey(secret []byte, repoId Id, purpose string, generation uint64, context []byte) ([]byte, error) {
	info := make([]byte, 0, len(gkmKeyInfoPrefix)+len(purpose)+8+len(context))
	info = append(info, gkmKeyInfoPrefix...)
	info = append(info, purpose...)
	info = binary.BigEndian.AppendUint64(info, generation)
	info = append(info, context...)
	derived, err := hkdf.Key(sha256.New, secret, repoId.Bytes(), string(info), gkmRepoKeyByteCount)
	if err != nil {
		return nil, fmt.Errorf("gkm: derive %s: %w", purpose, err)
	}
	testHookSecret(gkmDerivedKeyKinds[purpose], derived)
	return derived, nil
}

// What each derivation hooks as, §10.5's and §11.6's names.
var gkmDerivedKeyKinds = map[string]string{
	EvsKeyPurposeLink:      "K_link",
	EvsKeyPurposeFek:       "K_fek",
	EvsKeyPurposeManifest:  "K_manifest",
	EvsKeyPurposePath:      "K_path",
	EvsKeyPurposeRef:       "K_ref",
	EvsKeyPurposeDrop:      "K_drop",
	EvsKeyPurposeGroupInfo: "K_groupinfo",
	EvsKeyPurposeIndex:     "K_index",
	EvsKeyPurposeStatement: "K_statement",
}

// C_g = SHA-256("UR evs 1.0 commit" || repo_id || u64be(g) || RK_g).
func gkmCommitment(repoId Id, generation uint64, repoKey []byte) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(gkmCommitmentPrefix))
	hasher.Write(repoId.Bytes())
	hasher.Write(binary.BigEndian.AppendUint64(nil, generation))
	hasher.Write(repoKey)
	return hasher.Sum(nil)
}

// A fresh RK_g.
func gkmNewRepoKey() []byte {
	repoKey := make([]byte, gkmRepoKeyByteCount)
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	cryptorand.Read(repoKey)
	testHookSecret("RK_g", repoKey)
	return repoKey
}

// Hooks an X-Wing private key's seed, the 32 bytes the rest of it is computed from.
func gkmHookPrivateKey(kind string, privateKey hpke.PrivateKey) error {
	seed, err := privateKey.Bytes()
	if err != nil {
		return fmt.Errorf("gkm: private key: %w", err)
	}
	testHookSecret(kind, seed)
	return nil
}

// seal(key, plaintext; aad) under a random nonce.
func gkmSeal(key []byte, plaintext []byte, additionalData []byte) ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	cryptorand.Read(nonce)
	return gkmSealWithNonce(key, nonce, plaintext, additionalData)
}

// gkmSeal with its nonce given, which only fixed vectors have a reason to do.
func gkmSealWithNonce(key []byte, nonce []byte, plaintext []byte, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("%w: a seal key of %d bytes", ErrGkmMalformed, len(key))
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("%w: a nonce of %d bytes", ErrGkmMalformed, len(nonce))
	}
	sealed := make([]byte, len(nonce), len(nonce)+len(plaintext)+chacha20poly1305.Overhead)
	copy(sealed, nonce)
	return aead.Seal(sealed, nonce, plaintext, additionalData), nil
}

// The plaintext of a seal, or ErrGkmAuthentication. The caller hooks it when it is a key.
func gkmOpen(key []byte, sealed []byte, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("%w: a seal key of %d bytes", ErrGkmMalformed, len(key))
	}
	if len(sealed) < chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return nil, fmt.Errorf("%w: a seal of %d bytes", ErrGkmMalformed, len(sealed))
	}
	nonce := sealed[:chacha20poly1305.NonceSizeX]
	plaintext, err := aead.Open(nil, nonce, sealed[chacha20poly1305.NonceSizeX:], additionalData)
	if err != nil {
		return nil, fmt.Errorf("%w: seal does not open", ErrGkmAuthentication)
	}
	return plaintext, nil
}

// RK from a 72-byte seal, hooked.
func gkmOpenRepoKey(key []byte, sealed []byte, additionalData []byte) ([]byte, error) {
	if len(sealed) != gkmSealedKeyByteCount {
		return nil, fmt.Errorf("%w: a sealed key of %d bytes", ErrGkmMalformed, len(sealed))
	}
	repoKey, err := gkmOpen(key, sealed, additionalData)
	if err != nil {
		return nil, err
	}
	testHookSecret("RK_g", repoKey)
	return repoKey, nil
}

// GenLink_g's AAD: repo_id || u64be(g) || u8(cause_g).
func gkmGenLinkAad(repoId Id, generation uint64, cause GkmCause) []byte {
	aad := binary.BigEndian.AppendUint64(repoId.Bytes(), generation)
	return append(aad, byte(cause))
}

// GenWrap_e's and LeafWrap's AAD: group_id || u64be(e) || u64be(g).
func gkmKeyWrapAad(groupId Id, epoch uint64, generation uint64) []byte {
	aad := binary.BigEndian.AppendUint64(groupId.Bytes(), epoch)
	return binary.BigEndian.AppendUint64(aad, generation)
}

// GroupInfo_e's AAD: group_id || u64be(e).
func gkmGroupInfoAad(groupId Id, epoch uint64) []byte {
	return GkmGroupInfoContext(groupId, epoch)
}

// What a new generation's GenRotate states besides its keys, which the rotator decides (§10.5's Rotate).
type GkmGenerationArgs struct {
	Cause GkmCause
	// The state KeyHolders was computed at (§7.9). Required.
	Auth *bridge.AuthPin
	// The evaluation time for expiries, which gkm holds within 10 min of its clock. Required.
	Time time.Time
	// SHA-256 over the sorted KeyHolders(R, auth, time) identities. Required.
	HoldersSha256 []byte
	// The staged wraps and recovery wraps the rotation made.
	WrapCount uint32
	// For a kind that takes deposits (D-KEYS-17), when its drop key stops taking them. Zero: the GenRotate
	// carries no drop key.
	DropNotAfter time.Time
	// For a leaf rotator whose epoch's tree holds no leaf outside the holders (§10.5's step 3): that epoch's
	// KEK, so one LeafWrap serves every leaf. Nil: no LeafWrap.
	LeafWrapKek []byte
	// The epoch LeafWrapKek is of.
	LeafWrapEpoch uint64
}

// Generation 1 of a new group: a fresh RK_1, its commitment, and gen/1's statement, unsigned, with no parent
// (KF1).
func NewGkmFirstGeneration(repoId Id, groupId Id, args *GkmGenerationArgs) (*EvsRepoKey, *protocol.GenRotate, error) {
	return newGkmGeneration(repoId, groupId, nil, args)
}

// Generation g+1 after this one: a fresh RK_{g+1}, its commitment, and gen/<g+1>'s statement, unsigned, whose
// GenLink opens this key (§10.5's Rotate, step 2). Nothing is persisted or claimed here, and a key that holds no
// RK_g links to nothing.
func (self *EvsRepoKey) NextGeneration(args *GkmGenerationArgs) (*EvsRepoKey, *protocol.GenRotate, error) {
	if err := self.checkHeld(); err != nil {
		return nil, nil, err
	}
	return newGkmGeneration(self.repoId, self.groupId, self, args)
}

// Generation g+1 after this one in groupId, the group that re-formed this generation's (§10.8; plan-KEYS-reform-ladder
// rule 9): a re-formed group's ladder holds its old generations naming their old group, and the first rotation past
// them names the new one. GenLink's AAD and C_g hold no group_id, so the link opens as any other.
func (self *EvsRepoKey) NextGenerationIn(groupId Id, args *GkmGenerationArgs) (*EvsRepoKey, *protocol.GenRotate, error) {
	if err := self.checkHeld(); err != nil {
		return nil, nil, err
	}
	if groupId == (Id{}) {
		return nil, nil, fmt.Errorf("%w: a generation needs its group", ErrGkmMalformed)
	}
	return newGkmGeneration(self.repoId, groupId, self, args)
}

// A generation's keys and statement; parent nil for generation 1.
func newGkmGeneration(repoId Id, groupId Id, parent *EvsRepoKey, args *GkmGenerationArgs) (*EvsRepoKey, *protocol.GenRotate, error) {
	if args == nil || !args.Cause.valid() || args.Time.IsZero() || len(args.HoldersSha256) != gkmDigestByteCount {
		return nil, nil, fmt.Errorf("%w: a generation needs a cause, a time and a holders hash", ErrGkmMalformed)
	}
	if args.Auth == nil || args.Auth.GetVersion() == 0 || len(args.Auth.GetChain()) != gkmAuthChainByteCount {
		return nil, nil, fmt.Errorf("%w: a generation needs its auth pin", ErrGkmMalformed)
	}
	if args.LeafWrapKek != nil && len(args.LeafWrapKek) != gkmKekByteCount {
		return nil, nil, fmt.Errorf("%w: a KEK of %d bytes", ErrGkmMalformed, len(args.LeafWrapKek))
	}

	generation := uint64(1)
	if parent != nil {
		generation = parent.generation + 1
	}
	repoKey := gkmNewRepoKey()
	key := &EvsRepoKey{
		repoId:     repoId,
		groupId:    groupId,
		generation: generation,
		commitment: gkmCommitment(repoId, generation, repoKey),
		cause:      args.Cause,
		auth:       proto.Clone(args.Auth).(*bridge.AuthPin),
		timeMs:     args.Time.UnixMilli(),
		repoKey:    repoKey,
	}
	rotate := &protocol.GenRotate{
		GroupId:       groupId.Bytes(),
		RepoId:        repoId.Bytes(),
		Generation:    generation,
		Commitment:    bytes.Clone(key.commitment),
		Cause:         uint32(args.Cause),
		Auth:          proto.Clone(args.Auth).(*bridge.AuthPin),
		TimeMs:        key.timeMs,
		HoldersSha256: bytes.Clone(args.HoldersSha256),
		WrapCount:     args.WrapCount,
	}

	if parent == nil {
		key.firstRepoKey = repoKey
	} else {
		linkKey, err := gkmDeriveKey(repoKey, repoId, EvsKeyPurposeLink, generation, nil)
		if err != nil {
			return nil, nil, err
		}
		defer clear(linkKey)
		genLink, err := gkmSeal(linkKey, parent.repoKey, gkmGenLinkAad(repoId, generation, args.Cause))
		if err != nil {
			return nil, nil, err
		}
		key.parentCommitment = bytes.Clone(parent.commitment)
		key.genLink = genLink
		key.firstRepoKey = parent.firstRepoKey
		rotate.ParentCommitment = bytes.Clone(parent.commitment)
		rotate.Genlink = bytes.Clone(genLink)
	}

	if args.LeafWrapKek != nil {
		leafWrap, err := gkmSeal(args.LeafWrapKek, repoKey, gkmKeyWrapAad(groupId, args.LeafWrapEpoch, generation))
		if err != nil {
			return nil, nil, err
		}
		rotate.LeafWrap = &protocol.LeafWrap{Epoch: args.LeafWrapEpoch, Ciphertext: leafWrap}
	}

	if !args.DropNotAfter.IsZero() {
		dropKey, err := key.DropKeyPair()
		if err != nil {
			return nil, nil, err
		}
		rotate.DropPublicKey = dropKey.PublicKey().Bytes()
		rotate.DropNotAfterMs = args.DropNotAfter.UnixMilli()
	}
	return key, rotate, nil
}

// gen/<g>'s object as stored and verified: the Signed bytes a re-form copies byte for byte (QD-074), whose
// identity key signed them, and the statement. ParseGenRotate makes one, and nothing else should.
type GkmGeneration struct {
	Signed   *bridge.Signed
	SignerId Id
	Rotate   *protocol.GenRotate
}

// gen/<g>'s statement as signed: its deterministic encoding under the rotator's identity key, purpose
// gen-rotate (§10.5).
func SignGenRotate(rotate *protocol.GenRotate, sign GkmSignFunction) (*bridge.Signed, error) {
	if err := checkGkmGenRotate(rotate); err != nil {
		return nil, err
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(rotate)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGkmMalformed, err)
	}
	return gkmSign(gkmGenRotatePurpose, bridge.SignedType_SIGNED_GEN_ROTATE, body, sign)
}

// Calls sign and holds what comes back to what was asked for.
func gkmSign(purpose string, signedType bridge.SignedType, body []byte, sign GkmSignFunction) (*bridge.Signed, error) {
	signed, err := sign(purpose, signedType, body, nil)
	if err != nil {
		return nil, err
	}
	if signed == nil || signed.GetType() != uint32(signedType) || !bytes.Equal(signed.GetBody(), body) {
		return nil, fmt.Errorf("%w: the signer returned another statement", ErrGkmMalformed)
	}
	return signed, nil
}

// gen/<g>'s object in groupId: a Signed GenRotate, verified under its signer's identity key, which
// identityKey resolves, and held to its format and to the group and generation its key names. Unknown fields
// are kept and signed like any other (§22.6). Who may sign one is §10.9's rotation checks' (KEYS-M2-19).
func ParseGenRotate(objectBytes []byte, groupId Id, generation uint64, identityKey GkmIdentityKeyFunction) (*GkmGeneration, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(objectBytes, signed); err != nil {
		return nil, fmt.Errorf("%w: gen object: %w", ErrGkmMalformed, err)
	}
	signerId, err := IdFromBytes(signed.GetSignerId())
	if err != nil {
		return nil, fmt.Errorf("%w: gen object names no signer", ErrGkmMalformed)
	}
	publicKey, err := identityKey(signerId)
	if err != nil {
		return nil, err
	}
	err = bridge.VerifySigned(signed, gkmGenRotatePurpose, bridge.SignedType_SIGNED_GEN_ROTATE, bridge.SignedKeyAlgEd25519, publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGkmAuthentication, err)
	}
	rotate := &protocol.GenRotate{}
	if err := proto.Unmarshal(signed.GetBody(), rotate); err != nil {
		return nil, fmt.Errorf("%w: GenRotate: %w", ErrGkmMalformed, err)
	}
	if err := checkGkmGenRotate(rotate); err != nil {
		return nil, err
	}
	if !bytes.Equal(rotate.GetGroupId(), groupId.Bytes()) || rotate.GetGeneration() != generation {
		return nil, fmt.Errorf("%w: gen/%d of another group or generation", ErrGkmMalformed, generation)
	}
	return &GkmGeneration{Signed: signed, SignerId: signerId, Rotate: rotate}, nil
}

// GenRotate's format: its ids, digests and seals at their sizes, a cause, an auth pin and a time, a parent and
// a GenLink exactly when g > 1, and a drop key with its expiry or neither.
func checkGkmGenRotate(rotate *protocol.GenRotate) error {
	malformed := func(reason string) error {
		return fmt.Errorf("%w: GenRotate %s", ErrGkmMalformed, reason)
	}
	if rotate == nil {
		return malformed("missing")
	}
	if len(rotate.GetGroupId()) != gkmIdByteCount || len(rotate.GetRepoId()) != gkmIdByteCount {
		return malformed("ids")
	}
	if rotate.GetGeneration() == 0 {
		return malformed("generation 0")
	}
	if len(rotate.GetCommitment()) != gkmCommitmentByteCount {
		return malformed("commitment")
	}
	if rotate.GetGeneration() == 1 {
		if len(rotate.GetParentCommitment()) != 0 || len(rotate.GetGenlink()) != 0 {
			return malformed("parent at generation 1")
		}
	} else if len(rotate.GetParentCommitment()) != gkmCommitmentByteCount || len(rotate.GetGenlink()) != gkmSealedKeyByteCount {
		return malformed("parent")
	}
	if !GkmCause(rotate.GetCause()).valid() {
		return malformed("cause")
	}
	auth := rotate.GetAuth()
	if auth == nil || auth.GetVersion() == 0 || len(auth.GetChain()) != gkmAuthChainByteCount {
		return malformed("auth pin")
	}
	if rotate.GetTimeMs() <= 0 {
		return malformed("time")
	}
	if len(rotate.GetHoldersSha256()) != gkmDigestByteCount {
		return malformed("holders hash")
	}
	if leafWrap := rotate.GetLeafWrap(); leafWrap != nil && len(leafWrap.GetCiphertext()) != gkmSealedKeyByteCount {
		return malformed("leaf wrap")
	}
	if len(rotate.GetDropPublicKey()) == 0 {
		if rotate.GetDropNotAfterMs() != 0 {
			return malformed("drop expiry without a drop key")
		}
	} else {
		if len(rotate.GetDropPublicKey()) != gkmXWingPublicKeyByteCount || rotate.GetDropNotAfterMs() <= 0 {
			return malformed("drop key")
		}
		if _, err := hpke.MLKEM768X25519().NewPublicKey(rotate.GetDropPublicKey()); err != nil {
			return malformed("drop key")
		}
	}
	return nil
}

// A key accepted against gen/<g>: RK_g must match its C_g. RK_1 comes with it at generation 1.
func OpenEvsRepoKey(generation *GkmGeneration, repoKey []byte) (*EvsRepoKey, error) {
	if generation == nil || generation.Rotate == nil {
		return nil, fmt.Errorf("%w: no gen/<g> to check a key against", ErrGkmKeyMissing)
	}
	rotate := generation.Rotate
	if err := checkGkmGenRotate(rotate); err != nil {
		return nil, err
	}
	if len(repoKey) != gkmRepoKeyByteCount {
		return nil, fmt.Errorf("%w: a key of %d bytes", ErrGkmMalformed, len(repoKey))
	}
	testHookSecret("RK_g", repoKey)
	repoId := Id(rotate.GetRepoId())
	commitment := gkmCommitment(repoId, rotate.GetGeneration(), repoKey)
	if subtle.ConstantTimeCompare(commitment, rotate.GetCommitment()) != 1 {
		return nil, fmt.Errorf("%w: RK_g does not match gen/%d's C_g", ErrGkmAuthentication, rotate.GetGeneration())
	}
	key := &EvsRepoKey{
		repoId:           repoId,
		groupId:          Id(rotate.GetGroupId()),
		generation:       rotate.GetGeneration(),
		commitment:       commitment,
		parentCommitment: bytes.Clone(rotate.GetParentCommitment()),
		cause:            GkmCause(rotate.GetCause()),
		auth:             proto.Clone(rotate.GetAuth()).(*bridge.AuthPin),
		timeMs:           rotate.GetTimeMs(),
		genLink:          bytes.Clone(rotate.GetGenlink()),
		repoKey:          bytes.Clone(repoKey),
	}
	if key.generation == 1 {
		key.firstRepoKey = key.repoKey
	}
	return key, nil
}

// Generation g-1's key from this one's GenLink_g, against parent, gen/<g-1>'s verified statement, whose C_{g-1}
// this generation names as its parent and the opened key must match (§10.5's ladder). The link's AAD carries
// g's cause, so a statement whose cause was changed opens nothing.
func (self *EvsRepoKey) OpenParent(parent *GkmGeneration) (*EvsRepoKey, error) {
	if err := self.checkHeld(); err != nil {
		return nil, err
	}
	if self.generation <= 1 {
		return nil, fmt.Errorf("%w: generation 1 has no parent", ErrGkmKeyMissing)
	}
	if parent == nil || parent.Rotate == nil {
		return nil, fmt.Errorf("%w: gen/%d is not there", ErrGkmKeyMissing, self.generation-1)
	}
	rotate := parent.Rotate
	if rotate.GetGeneration() != self.generation-1 || !bytes.Equal(rotate.GetRepoId(), self.repoId.Bytes()) {
		return nil, fmt.Errorf("%w: gen/%d is not this key's parent", ErrGkmMalformed, rotate.GetGeneration())
	}
	if !bytes.Equal(rotate.GetCommitment(), self.parentCommitment) {
		return nil, fmt.Errorf("%w: gen/%d's commitment is not this key's parent", ErrGkmAuthentication, rotate.GetGeneration())
	}
	linkKey, err := gkmDeriveKey(self.repoKey, self.repoId, EvsKeyPurposeLink, self.generation, nil)
	if err != nil {
		return nil, err
	}
	defer clear(linkKey)
	parentRepoKey, err := gkmOpenRepoKey(linkKey, self.genLink, gkmGenLinkAad(self.repoId, self.generation, self.cause))
	if err != nil {
		return nil, err
	}
	defer clear(parentRepoKey)
	parentKey, err := OpenEvsRepoKey(parent, parentRepoKey)
	if err != nil {
		return nil, err
	}
	if self.firstRepoKey != nil && parentKey.firstRepoKey == nil {
		parentKey.firstRepoKey = self.firstRepoKey
	}
	return parentKey, nil
}

// Every generation below top, from its ladder: generations holds gen/1 to gen/<g-1>, each verified, in order,
// and each key returned holds RK_1, top's too, last. A gap or a statement out of order is ErrGkmKeyMissing:
// the walk never skips a generation it cannot open.
func OpenGkmLadder(top *EvsRepoKey, generations []*GkmGeneration) ([]*EvsRepoKey, error) {
	if err := top.checkHeld(); err != nil {
		return nil, err
	}
	if uint64(len(generations)) != top.generation-1 {
		return nil, fmt.Errorf("%w: %d statements below generation %d", ErrGkmKeyMissing, len(generations), top.generation)
	}
	keys := make([]*EvsRepoKey, top.generation)
	keys[top.generation-1] = top
	for generation := top.generation - 1; 1 <= generation; generation -= 1 {
		parent := generations[generation-1]
		if parent == nil || parent.Rotate == nil || parent.Rotate.GetGeneration() != generation {
			return nil, fmt.Errorf("%w: gen/%d is not there", ErrGkmKeyMissing, generation)
		}
		parentKey, err := keys[generation].OpenParent(parent)
		if err != nil {
			return nil, err
		}
		keys[generation-1] = parentKey
	}
	first := keys[0]
	for index, key := range keys {
		withFirst, err := key.WithFirst(first)
		if err != nil {
			return nil, err
		}
		keys[index] = withFirst
	}
	return keys, nil
}

// GenWrap_e: this generation's key under KEK_e of groupId's epoch e, for epoch object e (§10.6).
func SealGkmGenWrap(key *EvsRepoKey, groupId Id, epoch uint64, kek []byte) ([]byte, error) {
	if err := key.checkHeld(); err != nil {
		return nil, err
	}
	if len(kek) != gkmKekByteCount {
		return nil, fmt.Errorf("%w: a KEK of %d bytes", ErrGkmMalformed, len(kek))
	}
	return gkmSeal(kek, key.repoKey, gkmKeyWrapAad(groupId, epoch, key.generation))
}

// RK_g from GenWrap_e of groupId's epoch e, accepted against generation, gen/<g>'s verified statement, whose
// generation the wrap's AAD names: a joiner's first key, before it holds anything else (§10.6's Welcome).
func OpenGkmGenWrap(generation *GkmGeneration, groupId Id, epoch uint64, kek []byte, genWrap []byte) (*EvsRepoKey, error) {
	if generation == nil || generation.Rotate == nil {
		return nil, fmt.Errorf("%w: no gen/<g> to check a key against", ErrGkmKeyMissing)
	}
	if len(kek) != gkmKekByteCount {
		return nil, fmt.Errorf("%w: a KEK of %d bytes", ErrGkmMalformed, len(kek))
	}
	repoKey, err := gkmOpenRepoKey(kek, genWrap, gkmKeyWrapAad(groupId, epoch, generation.Rotate.GetGeneration()))
	if err != nil {
		return nil, err
	}
	defer clear(repoKey)
	return OpenEvsRepoKey(generation, repoKey)
}

// RK_g from gen/<g>'s LeafWrap, for a leaf of its epoch: kek is that epoch's KEK in the GenRotate's group.
func OpenGkmLeafWrap(generation *GkmGeneration, kek []byte) (*EvsRepoKey, error) {
	if generation == nil || generation.Rotate == nil {
		return nil, fmt.Errorf("%w: no gen/<g> to check a key against", ErrGkmKeyMissing)
	}
	leafWrap := generation.Rotate.GetLeafWrap()
	if leafWrap == nil {
		return nil, fmt.Errorf("%w: gen/%d carries no leaf wrap", ErrGkmKeyMissing, generation.Rotate.GetGeneration())
	}
	return OpenGkmGenWrap(generation, Id(generation.Rotate.GetGroupId()), leafWrap.GetEpoch(), kek, leafWrap.GetCiphertext())
}

// GroupInfo_e: groupInfo, ratchet_tree included, under K_groupinfo of this generation for groupId's epoch e
// (§10.5), which epoch e's object, or above 16 leaves group-info, carries.
func SealGkmGroupInfo(key *EvsRepoKey, groupId Id, epoch uint64, groupInfo []byte) ([]byte, error) {
	groupInfoKey, err := key.DeriveKey(EvsKeyPurposeGroupInfo, GkmGroupInfoContext(groupId, epoch))
	if err != nil {
		return nil, err
	}
	defer clear(groupInfoKey)
	return gkmSeal(groupInfoKey, groupInfo, gkmGroupInfoAad(groupId, epoch))
}

// The GroupInfo inside GroupInfo_e, which MLS must still verify, signature and tree (§10.6's Welcome): this
// opens it and checks nothing in it.
func OpenGkmGroupInfo(key *EvsRepoKey, groupId Id, epoch uint64, sealed []byte) ([]byte, error) {
	groupInfoKey, err := key.DeriveKey(EvsKeyPurposeGroupInfo, GkmGroupInfoContext(groupId, epoch))
	if err != nil {
		return nil, err
	}
	defer clear(groupInfoKey)
	return gkmOpen(groupInfoKey, sealed, gkmGroupInfoAad(groupId, epoch))
}
