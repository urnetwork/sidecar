// The one format of every sealed field of a config record (plan-TEAM-sealed-field-format, decided by the owner): a
// RecoveryBind's and RecoveryRebind's sealed_body, an IndexerSet's sealed_services, §17.8's rule bodies and §8.8's
// RepoVersioning rules, which stay bytes in their protos, so only these two functions know what is inside.
//
//	sealed = u64be(g) || nonce (24 random B) || XChaCha20-Poly1305(K, nonce, pt, aad)
//	K      = HKDF-SHA256(RK_g, salt repo_id, info "UR evs 1.0 statement" || u64be(g)), 32 B (§10.5's statement purpose)
//	aad    = "urnetwork-sidecar-v1/sealed-body" || 0x00 || u32be(SignedType) || header.network_id || header.nonce
//	         || u64be(g)
//	pt     = the *Body message, deterministically encoded, then 0x80, then zeros to a multiple of 256 B
//
// repo_id is the config repo's, or for an owner-bound repo's RepoVersioning rules that repo's own: the EvsRepoKey's.
// A reader that holds RK_g opens the field. One that lacks g keeps the entry pending and applies its id-level effect,
// opening the field once RK_g arrives (ErrConfigSealGenerationMissing). If the AEAD or the padding fails, the id-level
// effect stands, the sealed effect is void and the reader alarms (ErrConfigSealInvalid). api and keyless device roles
// never open one.
//
// On every leg, with no connect import. testHookSecret runs at K, through EvsRepoKey.DeriveKey. Package-level
// functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

const (
	// The aad's label, ahead of its 0x00.
	configSealAadLabel = "urnetwork-sidecar-v1/sealed-body"
	// The plaintext pads to a multiple of this.
	configSealPadByteCount = 256
	// The pad's first byte; zeros follow it.
	configSealPadMarker = 0x80
	// u64be(g) ahead of the nonce.
	configSealGenerationByteCount = 8
)

var (
	// The reader does not hold RK_g yet: keep the entry pending, apply its id-level effect, and open it once the
	// generation arrives.
	ErrConfigSealGenerationMissing = errors.New("config seal: the generation's key is not held")
	// The sealed bytes do not open: too short, the AEAD refused, or the padding is wrong. The sealed effect is void and
	// the reader alarms.
	ErrConfigSealInvalid = errors.New("config seal: invalid")
)

// What a sealed field is bound to besides its key: the record's signed type and its StatementHeader's network_id and
// nonce, so a field sealed into one record opens in no other, under any key.
type ConfigSealContext struct {
	SignedType bridge.SignedType
	// The record's header.network_id, as signed.
	NetworkId []byte
	// The record's header.nonce, as signed: 16 random bytes.
	Nonce []byte
}

// The context of a field sealed into a record with this header.
func NewConfigSealContext(signedType bridge.SignedType, header *bridge.StatementHeader) *ConfigSealContext {
	return &ConfigSealContext{
		SignedType: signedType,
		NetworkId:  bytes.Clone(header.GetNetworkId()),
		Nonce:      bytes.Clone(header.GetNonce()),
	}
}

// Whether the context names what a seal is bound to: a signed type, a 16-byte network id and a 16-byte nonce.
func (self *ConfigSealContext) check() error {
	if self == nil || len(self.NetworkId) != len(Id{}) || len(self.Nonce) != configNonceByteCount {
		return fmt.Errorf("%w: the record's header names no network or nonce", ErrConfigSealInvalid)
	}
	if self.SignedType == bridge.SignedType_SIGNED_TYPE_NONE {
		return fmt.Errorf("%w: no signed type", ErrConfigSealInvalid)
	}
	return nil
}

// The aad of generation g's seal in this context.
func (self *ConfigSealContext) aad(generation uint64) []byte {
	aad := make([]byte, 0, len(configSealAadLabel)+1+4+len(self.NetworkId)+len(self.Nonce)+8)
	aad = append(aad, configSealAadLabel...)
	aad = append(aad, 0x00)
	aad = binary.BigEndian.AppendUint32(aad, uint32(self.SignedType))
	aad = append(aad, self.NetworkId...)
	aad = append(aad, self.Nonce...)
	aad = binary.BigEndian.AppendUint64(aad, generation)
	return aad
}

// The generation a sealed field names, read without a key, so a reader knows which RK_g it waits for.
func ConfigSealedGeneration(sealed []byte) (uint64, error) {
	if len(sealed) < configSealGenerationByteCount+chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return 0, fmt.Errorf("%w: %d bytes", ErrConfigSealInvalid, len(sealed))
	}
	return binary.BigEndian.Uint64(sealed[:configSealGenerationByteCount]), nil
}

// Seals body, deterministically encoded and padded, under repoKey's generation, with a nonce from random
// (crypto/rand's reader when nil).
func SealConfigBody(repoKey *EvsRepoKey, context *ConfigSealContext, body proto.Message, random io.Reader) ([]byte, error) {
	if err := context.check(); err != nil {
		return nil, err
	}
	if body == nil {
		return nil, fmt.Errorf("%w: no body", ErrConfigSealInvalid)
	}
	if random == nil {
		random = rand.Reader
	}
	key, err := repoKey.DeriveKey(EvsKeyPurposeStatement, nil)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		return nil, err
	}
	plaintext = append(plaintext, configSealPadMarker)
	if remainder := len(plaintext) % configSealPadByteCount; remainder != 0 {
		plaintext = append(plaintext, make([]byte, configSealPadByteCount-remainder)...)
	}
	generation := repoKey.Generation()
	sealed := binary.BigEndian.AppendUint64(nil, generation)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, fmt.Errorf("config seal: nonce: %w", err)
	}
	sealed = append(sealed, nonce...)
	return aead.Seal(sealed, nonce, plaintext, context.aad(generation)), nil
}

// Opens a sealed field into body with the key of the generation it names, which repoKeyAt answers: nil for a
// generation the reader does not hold, ErrConfigSealGenerationMissing here. Returns that generation. Every other
// failure is ErrConfigSealInvalid, and body is then unspecified.
func OpenConfigBody(sealed []byte, context *ConfigSealContext, repoKeyAt func(generation uint64) *EvsRepoKey, body proto.Message) (uint64, error) {
	if err := context.check(); err != nil {
		return 0, err
	}
	generation, err := ConfigSealedGeneration(sealed)
	if err != nil {
		return 0, err
	}
	repoKey := repoKeyAt(generation)
	if repoKey == nil {
		return generation, fmt.Errorf("%w: %d", ErrConfigSealGenerationMissing, generation)
	}
	if repoKey.Generation() != generation {
		return generation, fmt.Errorf("%w: the key given is generation %d's, not %d's", ErrConfigSealInvalid, repoKey.Generation(), generation)
	}
	key, err := repoKey.DeriveKey(EvsKeyPurposeStatement, nil)
	if err != nil {
		if errors.Is(err, ErrGkmKeyMissing) {
			return generation, fmt.Errorf("%w: %w", ErrConfigSealGenerationMissing, err)
		}
		return generation, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return generation, err
	}
	nonce := sealed[configSealGenerationByteCount : configSealGenerationByteCount+chacha20poly1305.NonceSizeX]
	ciphertext := sealed[configSealGenerationByteCount+chacha20poly1305.NonceSizeX:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, context.aad(generation))
	if err != nil {
		return generation, fmt.Errorf("%w: the aead refused it", ErrConfigSealInvalid)
	}
	if len(plaintext)%configSealPadByteCount != 0 {
		return generation, fmt.Errorf("%w: not padded to %d", ErrConfigSealInvalid, configSealPadByteCount)
	}
	end := len(plaintext)
	for 0 < end && plaintext[end-1] == 0x00 {
		end -= 1
	}
	if end == 0 || plaintext[end-1] != configSealPadMarker {
		return generation, fmt.Errorf("%w: no pad marker", ErrConfigSealInvalid)
	}
	if err := proto.Unmarshal(plaintext[:end-1], body); err != nil {
		return generation, fmt.Errorf("%w: the body does not parse", ErrConfigSealInvalid)
	}
	return generation, nil
}
