// The recovery code and the keys it derives (§5.9's Recovery code, D-CORE-10, D-CORE-14, R-CORE-15, I-1; owner
// decisions 23, 62, 127, 149; plan-CORE-recovery-derivation #1 and #2, the second decided by the owner as QD-010).
//
// A code is 128 random bits, shown once per membership as 12 BIP-39 words: the 16 bytes E, then the first 4 bits of
// SHA-256(E), cut into twelve 11-bit indexes into the English list (keys_recovery_words.go). One membership draws one
// code, so no recovery key links a person's networks (owner decision 23), and no device keeps it: nothing here writes
// a code, a word or a derived private key to any store, and the code erases itself once its keys are derived.
//
// The keys come from E, never from the words and with no BIP-39 PBKDF2 step (QD-010):
//
//	ed25519_seed = HKDF-SHA256(ikm E, no salt, info "urnetwork-sidecar-v1/recovery-ed25519", 32 B)
//	xwing_seed   = HKDF-SHA256(ikm E, no salt, info "urnetwork-sidecar-v1/recovery-xwing", 32 B)
//
// the second being crypto/hpke's MLKEM768X25519().NewPrivateKey(xwing_seed). A RecoveryBind binds both public keys to
// the member (§7.9), its genesis_sig the Ed25519 key's signature over
//
//	"urnetwork-sidecar-v1/recovery-genesis" || network_id || SHA-256(Signed Genesis)
//
// which is §7.9's recovery anchor: a code-only device checks it before it acts (CORE-M2-06). The binding's name in the
// log and in rows is SHA-256 of the raw Ed25519 public key (RecoveryKeys.KeySha256), and a statement the key signs
// carries signer_id its member and key_id the raw key (protos-bridge-recovery-key-carrier). testdata/recovery/ pins a
// code to both public keys and a genesis_sig, byte-equal on every leg.
//
// testHookSecret sees E and each seed. On every leg: root Id, no connect type.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The format's values.
const (
	recoveryCodeByteCount = 16
	recoveryCodeWordCount = 12
	// the checksum's bits: one per 32 bits of E (BIP-39)
	recoveryCodeChecksumBitCount = 4
	recoveryWordBitCount         = 11
	recoverySeedByteCount        = 32

	recoveryEd25519Info  = "urnetwork-sidecar-v1/recovery-ed25519"
	recoveryXwingInfo    = "urnetwork-sidecar-v1/recovery-xwing"
	recoveryGenesisLabel = "urnetwork-sidecar-v1/recovery-genesis"
)

var (
	// Not 12 words of the list: a count, a word no list holds, or text that is no words at all. The error never
	// repeats what was typed.
	ErrRecoveryCodeWords = errors.New("a recovery code is 12 words of the list")
	// 12 list words whose checksum fails: one is wrong, or two changed places.
	ErrRecoveryCodeChecksum = errors.New("the recovery code's checksum fails: a word is wrong or out of order")
	// The code derived its keys, or was erased: it holds nothing more.
	ErrRecoveryCodeErased = errors.New("the recovery code was erased")
	// A genesis_sig that does not verify under the Ed25519 key for this network and genesis.
	ErrRecoveryGenesisSig = errors.New("the recovery key's genesis signature does not verify")
	// Keys that were erased, or key bytes of the wrong shape.
	ErrRecoveryKeys = errors.New("the recovery keys are erased or malformed")
)

// One membership's recovery code: 128 bits a person writes down as 12 words. Held only in the memory of the process
// that draws or reads it, until Keys or Erase. Not safe for concurrent use.
type RecoveryCode struct {
	entropy [recoveryCodeByteCount]byte
	erased  bool
}

// A fresh code from random.
func NewRecoveryCode(random io.Reader) (*RecoveryCode, error) {
	code := &RecoveryCode{}
	if _, err := io.ReadFull(random, code.entropy[:]); err != nil {
		return nil, fmt.Errorf("no randomness for a recovery code: %w", err)
	}
	testHookSecret("recovery_code", code.entropy[:])
	return code, nil
}

// The code a person typed: 12 words of the list, in any case, apart by any white space. A bad checksum refuses at
// entry (QD-283). The error never repeats the text.
func ParseRecoveryCode(text string) (*RecoveryCode, error) {
	words := strings.Fields(strings.ToLower(text))
	if len(words) != recoveryCodeWordCount {
		return nil, ErrRecoveryCodeWords
	}
	wordIndexes := recoveryWordIndexes()
	// 132 bits, most significant first: E, then the checksum
	var bits [recoveryCodeByteCount + 1]byte
	defer clear(bits[:])
	for i, word := range words {
		index, ok := wordIndexes[word]
		if !ok {
			return nil, ErrRecoveryCodeWords
		}
		for bit := 0; bit < recoveryWordBitCount; bit += 1 {
			if index&(1<<(recoveryWordBitCount-1-bit)) != 0 {
				position := i*recoveryWordBitCount + bit
				bits[position/8] |= 1 << (7 - position%8)
			}
		}
	}
	code := &RecoveryCode{}
	copy(code.entropy[:], bits[:recoveryCodeByteCount])
	digest := sha256.Sum256(code.entropy[:])
	if bits[recoveryCodeByteCount]>>(8-recoveryCodeChecksumBitCount) != digest[0]>>(8-recoveryCodeChecksumBitCount) {
		code.Erase()
		return nil, ErrRecoveryCodeChecksum
	}
	testHookSecret("recovery_code", code.entropy[:])
	return code, nil
}

// The code's 12 words, to show once.
func (self *RecoveryCode) Words() ([]string, error) {
	if self.erased {
		return nil, ErrRecoveryCodeErased
	}
	var bits [recoveryCodeByteCount + 1]byte
	defer clear(bits[:])
	copy(bits[:], self.entropy[:])
	digest := sha256.Sum256(self.entropy[:])
	bits[recoveryCodeByteCount] = digest[0] >> (8 - recoveryCodeChecksumBitCount) << (8 - recoveryCodeChecksumBitCount)
	wordList := recoveryWordList()
	words := make([]string, 0, recoveryCodeWordCount)
	for i := 0; i < recoveryCodeWordCount; i += 1 {
		index := 0
		for bit := 0; bit < recoveryWordBitCount; bit += 1 {
			position := i*recoveryWordBitCount + bit
			index <<= 1
			if bits[position/8]&(1<<(7-position%8)) != 0 {
				index |= 1
			}
		}
		words = append(words, wordList[index])
	}
	return words, nil
}

// Derives the code's keys and erases the code, so E lives no longer than the derivation (QD-010).
func (self *RecoveryCode) Keys() (*RecoveryKeys, error) {
	if self.erased {
		return nil, ErrRecoveryCodeErased
	}
	defer self.Erase()
	return deriveRecoveryKeys(self.entropy[:])
}

// Zeroes the code.
func (self *RecoveryCode) Erase() {
	clear(self.entropy[:])
	self.erased = true
}

// The recovery keys of one membership: the Ed25519 key that signs its genesis_sig and its recovery statements, and the
// X-Wing key its device root and repo key generations are wrapped to (§5.9, §10.8). Held in memory only, by the process
// that derived them, until Erase. Not safe for concurrent use.
type RecoveryKeys struct {
	ed25519Key     ed25519.PrivateKey
	xwingKey       hpke.PrivateKey
	xwingPublicKey []byte
}

// QD-010's derivation, the one place a code becomes keys. entropy is E's 16 bytes, which the caller erases.
func deriveRecoveryKeys(entropy []byte) (*RecoveryKeys, error) {
	if len(entropy) != recoveryCodeByteCount {
		return nil, ErrRecoveryKeys
	}
	testHookSecret("recovery_code", entropy)
	ed25519Seed, err := hkdf.Key(sha256.New, entropy, nil, recoveryEd25519Info, recoverySeedByteCount)
	if err != nil {
		return nil, err
	}
	defer clear(ed25519Seed)
	testHookSecret("recovery_ed25519_seed", ed25519Seed)
	xwingSeed, err := hkdf.Key(sha256.New, entropy, nil, recoveryXwingInfo, recoverySeedByteCount)
	if err != nil {
		return nil, err
	}
	testHookSecret("recovery_xwing_seed", xwingSeed)
	// the key keeps its seed, so it is cloned for it and this copy erased
	xwingKey, err := hpke.MLKEM768X25519().NewPrivateKey(bytes.Clone(xwingSeed))
	clear(xwingSeed)
	if err != nil {
		return nil, err
	}
	return &RecoveryKeys{
		ed25519Key:     ed25519.NewKeyFromSeed(ed25519Seed),
		xwingKey:       xwingKey,
		xwingPublicKey: xwingKey.PublicKey().Bytes(),
	}, nil
}

// The raw 32-byte Ed25519 public key: RecoveryBindBody.ed25519_public_key, and the key_id of what the key signs.
func (self *RecoveryKeys) Ed25519PublicKey() []byte {
	if self.ed25519Key == nil {
		return nil
	}
	return bytes.Clone(self.ed25519Key.Public().(ed25519.PublicKey))
}

// The X-Wing public key, 1,216 bytes: RecoveryBindBody.xwing_public_key.
func (self *RecoveryKeys) XwingPublicKey() []byte {
	return bytes.Clone(self.xwingPublicKey)
}

// The binding's name in the log and in rows: SHA-256 of the raw Ed25519 public key
// (RecoveryBind.ed25519_public_key_sha256, MemberRow.recovery_key_sha256).
func (self *RecoveryKeys) KeySha256() []byte {
	if self.ed25519Key == nil {
		return nil
	}
	return RecoveryKeySha256(self.ed25519Key.Public().(ed25519.PublicKey))
}

// A recovery binding's name from its raw Ed25519 public key.
func RecoveryKeySha256(ed25519PublicKey []byte) []byte {
	digest := sha256.Sum256(ed25519PublicKey)
	return digest[:]
}

// The X-Wing private key, which opens what was wrapped to this membership's recovery key: this network's
// keychain.wrap copy (keys_recovery_seal.go) and its member's RecoveryWraps (§10.8, KEYS-M2-24). The caller must not
// keep it past Erase.
func (self *RecoveryKeys) XwingPrivateKey() (hpke.PrivateKey, error) {
	if self.xwingKey == nil {
		return nil, ErrRecoveryKeys
	}
	return self.xwingKey, nil
}

// The bytes a genesis_sig signs.
func recoveryGenesisBytes(networkId Id, genesisSha256 []byte) ([]byte, error) {
	if len(genesisSha256) != sha256.Size {
		return nil, fmt.Errorf("%w: a genesis hash of %d bytes", ErrRecoveryGenesisSig, len(genesisSha256))
	}
	signedBytes := make([]byte, 0, len(recoveryGenesisLabel)+len(networkId)+sha256.Size)
	signedBytes = append(signedBytes, recoveryGenesisLabel...)
	signedBytes = append(signedBytes, networkId[:]...)
	return append(signedBytes, genesisSha256...), nil
}

// RecoveryBindBody.genesis_sig: this key's signature over the label, the network and A_0 = SHA-256(Signed Genesis),
// §7.9's recovery anchor.
func (self *RecoveryKeys) SignGenesis(networkId Id, genesisSha256 []byte) ([]byte, error) {
	if self.ed25519Key == nil {
		return nil, ErrRecoveryKeys
	}
	signedBytes, err := recoveryGenesisBytes(networkId, genesisSha256)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(self.ed25519Key, signedBytes), nil
}

// Checks a genesis_sig under a binding's raw Ed25519 public key: what a device signing a binding checks before it
// signs, and what a code-only device's anchor checks (§5.6's genesis row, step 3).
func VerifyRecoveryGenesisSig(ed25519PublicKey []byte, networkId Id, genesisSha256 []byte, genesisSig []byte) error {
	if len(ed25519PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: a key of %d bytes", ErrRecoveryGenesisSig, len(ed25519PublicKey))
	}
	signedBytes, err := recoveryGenesisBytes(networkId, genesisSha256)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(ed25519PublicKey), signedBytes, genesisSig) {
		return ErrRecoveryGenesisSig
	}
	return nil
}

// §6.9's Signed over body by the recovery key, standing for memberId: signer_id the member, key_id the raw Ed25519
// key, which rows hold only as a hash (protos-bridge-recovery-key-carrier). A recovery key signs only what §7.9's
// Recovery lets it, a SidecarAdmit, an AuthorityProposal or an AuthorityCosign, which its verifiers hold it to; it
// carries no presence countersignature. body is copied.
func (self *RecoveryKeys) Sign(memberId Id, purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
	if self.ed25519Key == nil {
		return nil, ErrRecoveryKeys
	}
	switch signedType {
	case bridge.SignedType_SIGNED_SIDECAR_ADMIT, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, bridge.SignedType_SIGNED_AUTHORITY_COSIGN:
	default:
		return nil, fmt.Errorf("%w: a recovery key signs no type %#x", ErrSidecarSignRefused, int32(signedType))
	}
	if purpose != bridge.SignedPurposeAuthority {
		return nil, fmt.Errorf("%w: a recovery key signs under purpose %s", ErrSidecarSignRefused, bridge.SignedPurposeAuthority)
	}
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  memberId.Bytes(),
		KeyId:     self.Ed25519PublicKey(),
		Signature: ed25519.Sign(self.ed25519Key, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

// Zeroes the Ed25519 key and drops the X-Wing key, whose bytes crypto/hpke holds and the collector frees.
func (self *RecoveryKeys) Erase() {
	clear(self.ed25519Key)
	self.ed25519Key = nil
	self.xwingKey = nil
}
