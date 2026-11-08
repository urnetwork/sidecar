// Object keys and slots (§11.6's object key row, §11.8's slot/ row). Every record body is sealed under an object
// key, 32 random bytes, kept in one of three places:
//
//   - general repos: one per segment or inline chain, in the 72 B wrapped-key block that segment or chain carries:
//     24 B nonce | 32 B key sealed | 16 B tag, under fek_g, AAD "UR evs 1.0 object key" || repo_id || u64be(g)
//     (plan-EVS1-format-bytes#2); it goes with the segment, and the repo's erasure erases it;
//   - record-class repos and group inboxes: one per entry or chain, as a key of a slot/ object, which an ERASE can
//     drop alone; a key wrapped under fek is the same 72 B block, its AAD included (EVS-FORMAT.md);
//   - deposits: one per deposit, in a slot of its own, HPKE-XWing to generation g's drop key, which CONSUME deletes.
//     Its parameters are §10.6's wraps': base mode, X-Wing, HKDF-SHA256 and AES-128-GCM, with info
//     "UR evs 1.0 deposit key" and AAD repo_id || u64be(g). The depositor holds no manifest key, so the deposit's
//     header, fields and metadata go under K_dep, derived from this key (plan-EVS1-format-bytes#5).
//
// A slot/ object is EvsSlotObject: at most 64 keys in ascending key_index, each index drawn once in its slot and
// never reused, at most 8 KiB, all wrapped one way. An erased key leaves the list and no index shifts, so a record
// naming (slot_id, key_index) never reaches another key. Slot ids are 16 random bytes drawn per statement, kept by
// a retry of that statement and drawn again for a rebuilt push (§11.6).
//
// evs reads slot objects, to erase keys and check what a push names, and never opens a key: it holds no fek and no
// drop key (I-1). On every leg. Package-level functions are safe for concurrent use, and an EvsObjectKey, which
// never changes, is too.

package sidecar

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hpke"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"slices"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The layouts of this file.
const (
	// A wrapped-key block: nonce, key and tag.
	EvsWrappedKeyByteCount = chacha20poly1305.NonceSizeX + evsKeyByteCount + chacha20poly1305.Overhead
	// A deposit's key under HPKE-XWing: the encapsulation, then the key and AES-128-GCM's tag.
	EvsDepositWrappedKeyByteCount = gkmXWingEncapsulationByteCount + evsKeyByteCount + 16
	// §11.8's slot/ bounds.
	EvsSlotMaxKeyCount  = 64
	evsSlotMaxByteCount = 8 * 1024

	evsObjectKeyAadLabel   = "UR evs 1.0 object key"
	evsDepositKeyHpkeInfo  = "UR evs 1.0 deposit key"
	evsDepositManifestInfo = "UR evs 1.0 deposit"
)

// A record body's key.
type EvsObjectKey struct {
	key []byte
}

// A fresh object key, hooked before its first use.
func NewEvsObjectKey() *EvsObjectKey {
	key := make([]byte, evsKeyByteCount)
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	cryptorand.Read(key)
	testHookSecret("object_key", key)
	return &EvsObjectKey{key: key}
}

// An object key from bytes already hooked.
func evsObjectKeyOf(key []byte) *EvsObjectKey {
	return &EvsObjectKey{key: key}
}

// ErrEvsKeyMissing unless this holds a key, which only this file makes.
func (self *EvsObjectKey) checkHeld() error {
	if self == nil || len(self.key) != evsKeyByteCount {
		return fmt.Errorf("%w: no object key", ErrEvsKeyMissing)
	}
	return nil
}

// A fresh slot id: 16 random bytes, drawn per statement (§11.6).
func NewEvsSlotId() Id {
	slotId := Id{}
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	cryptorand.Read(slotId[:])
	return slotId
}

// The 72 B wrapped-key block of objectKey under fek_g.
func EvsWrapObjectKey(fekKey *EvsFekKey, objectKey *EvsObjectKey) ([]byte, error) {
	if err := fekKey.checkHeld(); err != nil {
		return nil, err
	}
	if err := objectKey.checkHeld(); err != nil {
		return nil, err
	}
	return evsSeal(fekKey.key, objectKey.key, evsLabeledAad(evsObjectKeyAadLabel, fekKey.repoId, fekKey.generation))
}

// The object key a 72 B wrapped-key block holds under fek_g, hooked; ErrEvsSealInvalid for any other block.
func EvsUnwrapObjectKey(fekKey *EvsFekKey, wrapped []byte) (*EvsObjectKey, error) {
	if err := fekKey.checkHeld(); err != nil {
		return nil, err
	}
	if len(wrapped) != EvsWrappedKeyByteCount {
		return nil, fmt.Errorf("%w: a wrapped key of %d bytes", ErrEvsSealInvalid, len(wrapped))
	}
	key, err := evsOpen(fekKey.key, wrapped, evsLabeledAad(evsObjectKeyAadLabel, fekKey.repoId, fekKey.generation))
	if err != nil {
		return nil, err
	}
	testHookSecret("object_key", key)
	return evsObjectKeyOf(key), nil
}

// A deposit's object key HPKE-XWing to dropPublicKey, generation g's drop key, as its slot holds it.
func EvsWrapDepositKey(dropPublicKey hpke.PublicKey, repoId Id, generation uint64, objectKey *EvsObjectKey) ([]byte, error) {
	if err := objectKey.checkHeld(); err != nil {
		return nil, err
	}
	if dropPublicKey == nil || dropPublicKey.KEM().ID() != hpke.MLKEM768X25519().ID() {
		return nil, fmt.Errorf("%w: a drop key that is not X-Wing", ErrEvsKeyMissing)
	}
	encapsulation, sender, err := hpke.NewSender(dropPublicKey, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(evsDepositKeyHpkeInfo))
	if err != nil {
		return nil, fmt.Errorf("evs: deposit key hpke setup: %w", err)
	}
	aad := evsLabeledAad("", repoId, generation)
	ciphertext, err := sender.Seal(aad, objectKey.key)
	if err != nil {
		return nil, fmt.Errorf("evs: deposit key hpke seal: %w", err)
	}
	return append(encapsulation, ciphertext...), nil
}

// A deposit's object key, opened by generation g's drop private key and hooked; ErrEvsSealInvalid for anything
// else.
func EvsUnwrapDepositKey(dropPrivateKey hpke.PrivateKey, repoId Id, generation uint64, wrapped []byte) (*EvsObjectKey, error) {
	if dropPrivateKey == nil || dropPrivateKey.KEM().ID() != hpke.MLKEM768X25519().ID() {
		return nil, fmt.Errorf("%w: no X-Wing drop key", ErrEvsKeyMissing)
	}
	if len(wrapped) != EvsDepositWrappedKeyByteCount {
		return nil, fmt.Errorf("%w: a deposit key of %d bytes", ErrEvsSealInvalid, len(wrapped))
	}
	recipient, err := hpke.NewRecipient(wrapped[:gkmXWingEncapsulationByteCount], dropPrivateKey, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(evsDepositKeyHpkeInfo))
	if err != nil {
		return nil, fmt.Errorf("%w: deposit key hpke setup", ErrEvsSealInvalid)
	}
	key, err := recipient.Open(evsLabeledAad("", repoId, generation), wrapped[gkmXWingEncapsulationByteCount:])
	if err != nil || len(key) != evsKeyByteCount {
		return nil, fmt.Errorf("%w: the deposit key does not open", ErrEvsSealInvalid)
	}
	testHookSecret("object_key", key)
	return evsObjectKeyOf(key), nil
}

// K_dep = HKDF-SHA256(object key, salt repo_id, info "UR evs 1.0 deposit"): what seals a deposit's record header,
// sealed fields and a deposit push's metadata in manifest's place, for a deposit to generation g's drop key.
func NewEvsDepositManifestKey(repoId Id, generation uint64, objectKey *EvsObjectKey) (*EvsManifestKey, error) {
	if err := objectKey.checkHeld(); err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, objectKey.key, repoId.Bytes(), evsDepositManifestInfo, evsKeyByteCount)
	if err != nil {
		return nil, fmt.Errorf("evs: derive K_dep: %w", err)
	}
	testHookSecret("K_dep", key)
	return &EvsManifestKey{repoId: repoId, generation: generation, deposit: true, key: key}, nil
}

// A slot object's keys held to §11.8: at most 64 in ascending key_index below 64, each with a generation and all
// wrapped one way, under fek or to a drop key; and the object within 8 KiB.
func checkEvsSlotObject(slot *protocol.EvsSlotObject, byteCount int) error {
	if evsSlotMaxByteCount < byteCount {
		return fmt.Errorf("%w: a slot of %d bytes", ErrEvsSealInvalid, byteCount)
	}
	if EvsSlotMaxKeyCount < len(slot.GetKeys()) {
		return fmt.Errorf("%w: a slot of %d keys", ErrEvsSealInvalid, len(slot.GetKeys()))
	}
	wrappedByteCount := 0
	for i, slotKey := range slot.GetKeys() {
		if EvsSlotMaxKeyCount <= slotKey.GetKeyIndex() {
			return fmt.Errorf("%w: key index %d", ErrEvsSealInvalid, slotKey.GetKeyIndex())
		}
		if 0 < i && slotKey.GetKeyIndex() <= slot.GetKeys()[i-1].GetKeyIndex() {
			return fmt.Errorf("%w: key indexes not ascending", ErrEvsSealInvalid)
		}
		if slotKey.GetGeneration() == 0 {
			return fmt.Errorf("%w: a key of no generation", ErrEvsSealInvalid)
		}
		length := len(slotKey.GetWrapped())
		if length != EvsWrappedKeyByteCount && length != EvsDepositWrappedKeyByteCount {
			return fmt.Errorf("%w: a wrapped key of %d bytes", ErrEvsSealInvalid, length)
		}
		if wrappedByteCount != 0 && length != wrappedByteCount {
			return fmt.Errorf("%w: a slot wrapping keys two ways", ErrEvsSealInvalid)
		}
		wrappedByteCount = length
	}
	return nil
}

// A new slot/ object's bytes: one key at least, held to §11.8, deterministic.
func EvsEncodeSlotObject(slot *protocol.EvsSlotObject) ([]byte, error) {
	if len(slot.GetKeys()) == 0 {
		return nil, fmt.Errorf("%w: a new slot with no key", ErrEvsSealInvalid)
	}
	objectBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(slot)
	if err != nil {
		return nil, fmt.Errorf("evs: slot: %w", err)
	}
	if err := checkEvsSlotObject(slot, len(objectBytes)); err != nil {
		return nil, err
	}
	return objectBytes, nil
}

// A stored slot/ object, held to §11.8. One whose every key was erased holds none.
func EvsDecodeSlotObject(objectBytes []byte) (*protocol.EvsSlotObject, error) {
	slot := &protocol.EvsSlotObject{}
	if err := proto.Unmarshal(objectBytes, slot); err != nil {
		return nil, fmt.Errorf("%w: a slot that does not parse", ErrEvsSealInvalid)
	}
	if err := checkEvsSlotObject(slot, len(objectBytes)); err != nil {
		return nil, err
	}
	return slot, nil
}

// The key at keyIndex, or false once it is erased or was never drawn.
func EvsSlotKeyAt(slot *protocol.EvsSlotObject, keyIndex uint32) (*protocol.EvsSlotKey, bool) {
	for _, slotKey := range slot.GetKeys() {
		if slotKey.GetKeyIndex() == keyIndex {
			return slotKey, true
		}
	}
	return nil, false
}

// What evs rewrites a slot to after an ERASE commits (§11.12): the object without the keys at keyIndexes, every
// other key and index as it was, and how many it dropped. Dropping none gives the bytes back unchanged, which the
// caller answers as NOTHING_TO_ERASE where that applies.
func EvsSlotWithoutKeys(objectBytes []byte, keyIndexes []uint32) ([]byte, int, error) {
	slot, err := EvsDecodeSlotObject(objectBytes)
	if err != nil {
		return nil, 0, err
	}
	kept := slot.GetKeys()[:0:0]
	for _, slotKey := range slot.GetKeys() {
		if !slices.Contains(keyIndexes, slotKey.GetKeyIndex()) {
			kept = append(kept, slotKey)
		}
	}
	removedCount := len(slot.GetKeys()) - len(kept)
	if removedCount == 0 {
		return bytes.Clone(objectBytes), 0, nil
	}
	slot.Keys = kept
	rewritten, err := proto.MarshalOptions{Deterministic: true}.Marshal(slot)
	if err != nil {
		return nil, 0, fmt.Errorf("evs: slot: %w", err)
	}
	return rewritten, removedCount, nil
}

// The object key a fek-wrapped slot key holds, under fek of the key's own generation.
func EvsOpenSlotKey(fekKey *EvsFekKey, slotKey *protocol.EvsSlotKey) (*EvsObjectKey, error) {
	if err := fekKey.checkHeld(); err != nil {
		return nil, err
	}
	if slotKey.GetGeneration() != fekKey.generation {
		return nil, fmt.Errorf("%w: a key of generation %d under fek of %d", ErrEvsKeyMissing, slotKey.GetGeneration(), fekKey.generation)
	}
	return EvsUnwrapObjectKey(fekKey, slotKey.GetWrapped())
}

// The object key a deposit's slot key holds, opened by the drop private key of the key's generation.
func EvsOpenDepositSlotKey(dropPrivateKey hpke.PrivateKey, repoId Id, slotKey *protocol.EvsSlotKey) (*EvsObjectKey, error) {
	return EvsUnwrapDepositKey(dropPrivateKey, repoId, slotKey.GetGeneration(), slotKey.GetWrapped())
}
