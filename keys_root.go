// R_n and keychain.wrap (§5.9, D-CORE-10, D-CORE-14). Each network has its own random 32-byte root,
// wrapped by the instance's U. Every key on a file comes from a root by HKDF, so nothing that opens one
// network's keychain.wrap, a recovery code above all, reaches another's files.
//
//	magic "URKW" | version 1 | network id, 16 B | root count, uint8 | root ... |
//	recovery length, uint16 | recovery
//	root: root generation, uint64 | unlock generation, uint64 | nonce, 24 B | wrapped key, 48 B
//
// Integers are big endian. Roots run from the newest generation down, and the first is current, so
// no field outside an AEAD says which. A root is wrapped under HKDF(U of its unlock generation,
// .../keychain-wrap) with the network id and both generations as additional data, so a wrap read in
// another network's file, or under another generation, fails. More than one root means a rotation
// has not finished: keys_rotate.go. recovery is CORE-M2-05's HPKE copy of R_n and stays empty until
// then, which is what no current binding means (§5.9).

package sidecar

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// The format's values.
const (
	keychainWrapMagic   = "URKW"
	keychainWrapVersion = 1
	// a rotation holds two, and a bound keeps a decoder's work small
	keychainWrapMaxRootCount = 8
	// an HPKE copy of a 32-byte key under X-Wing is about 1.2 KiB
	keychainRecoveryMaxByteCount = 8 * 1024
	keychainWrapMaxByteCount     = 16 * 1024
)

// §5.9's derivation of a file key from R_n, and of each key U stands behind. The class goes on the end
// of this.
const localKeyInfoPrefix = "urnetwork-sidecar-v1/local/"

// What U derives, beside no file: these never meet a class's key, since a file key comes from an R_n.
const (
	keychainWrapClass   = "keychain-wrap"
	unlockPreviousClass = "unlock-previous"
)

// The bytes of every key here.
const localKeyByteCount = 32

var errKeychainWrapFormat = fmt.Errorf("%w: keychain.wrap does not decode", ErrSidecarStoreFailed)

// HKDF-SHA256 with no salt and info urnetwork-sidecar-v1/local/<class> (§5.9).
func deriveLocalKey(secret []byte, class string) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, nil, localKeyInfoPrefix+class, localKeyByteCount)
}

// One R_n in a keychain.wrap.
type keychainRoot struct {
	generation       uint64
	unlockGeneration uint64
	wrapped          wrappedKey
}

// keychain.wrap's content.
type keychainWrap struct {
	networkId Id
	// newest first
	roots []keychainRoot
	// CORE-M2-05's HPKE copy. Empty while no binding is current.
	recovery []byte
}

// The additional data of one root's wrap.
func keychainRootAdditionalData(networkId Id, generation uint64, unlockGeneration uint64) []byte {
	additionalData := make([]byte, 0, len(localKeyInfoPrefix)+len(keychainWrapClass)+16+8+8)
	additionalData = append(additionalData, localKeyInfoPrefix...)
	additionalData = append(additionalData, keychainWrapClass...)
	additionalData = append(additionalData, networkId[:]...)
	additionalData = binary.BigEndian.AppendUint64(additionalData, generation)
	return binary.BigEndian.AppendUint64(additionalData, unlockGeneration)
}

// A root wrapped under U of unlockGeneration.
func wrapKeychainRoot(networkId Id, generation uint64, root []byte, unlockGeneration uint64, unlockKey []byte,
	random io.Reader) (*keychainRoot, error) {
	wrapKey, err := deriveLocalKey(unlockKey, keychainWrapClass)
	if err != nil {
		return nil, err
	}
	defer clear(wrapKey)
	testHookSecret("K_keychain_wrap", wrapKey)
	wrapped, err := sealWrappedKey(wrapKey, root, keychainRootAdditionalData(networkId, generation, unlockGeneration), random)
	if err != nil {
		return nil, err
	}
	return &keychainRoot{generation: generation, unlockGeneration: unlockGeneration, wrapped: *wrapped}, nil
}

// The root in this entry, opened under U of its unlock generation. Failure means the file is damaged,
// so it is ErrSidecarStoreFailed, never a lost key.
func (self *keychainRoot) open(networkId Id, unlockKey []byte) ([]byte, error) {
	wrapKey, err := deriveLocalKey(unlockKey, keychainWrapClass)
	if err != nil {
		return nil, err
	}
	defer clear(wrapKey)
	testHookSecret("K_keychain_wrap", wrapKey)
	root, err := self.wrapped.open(wrapKey, keychainRootAdditionalData(networkId, self.generation, self.unlockGeneration))
	if err != nil {
		return nil, err
	}
	testHookSecret("R_n", root)
	return root, nil
}

// The file's bytes.
func (self *keychainWrap) encode() []byte {
	encoded := make([]byte, 0, keychainWrapMaxByteCount)
	encoded = append(encoded, keychainWrapMagic...)
	encoded = append(encoded, keychainWrapVersion)
	encoded = append(encoded, self.networkId[:]...)
	encoded = append(encoded, byte(len(self.roots)))
	for i := range self.roots {
		root := &self.roots[i]
		encoded = binary.BigEndian.AppendUint64(encoded, root.generation)
		encoded = binary.BigEndian.AppendUint64(encoded, root.unlockGeneration)
		encoded = root.wrapped.append(encoded)
	}
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(self.recovery)))
	return append(encoded, self.recovery...)
}

// A whole keychain.wrap, or ErrSidecarStoreFailed. Total, bounded by its input, and its error never
// repeats it.
func decodeKeychainWrap(encoded []byte) (*keychainWrap, error) {
	cursor := &wrapCursor{remaining: encoded}
	if string(cursor.take(len(keychainWrapMagic))) != keychainWrapMagic ||
		cursor.takeUint8() != keychainWrapVersion {
		return nil, errKeychainWrapFormat
	}
	wrap := &keychainWrap{}
	copy(wrap.networkId[:], cursor.take(len(wrap.networkId)))
	rootCount := int(cursor.takeUint8())
	if rootCount == 0 || keychainWrapMaxRootCount < rootCount {
		return nil, errKeychainWrapFormat
	}
	for i := 0; i < rootCount; i += 1 {
		root := keychainRoot{generation: cursor.takeUint64(), unlockGeneration: cursor.takeUint64()}
		root.wrapped.read(cursor)
		if cursor.failed || root.generation == 0 || root.unlockGeneration == 0 ||
			(i != 0 && wrap.roots[i-1].generation <= root.generation) {
			return nil, errKeychainWrapFormat
		}
		wrap.roots = append(wrap.roots, root)
	}
	recoveryByteCount := int(cursor.takeUint16())
	if keychainRecoveryMaxByteCount < recoveryByteCount {
		return nil, errKeychainWrapFormat
	}
	wrap.recovery = append([]byte(nil), cursor.take(recoveryByteCount)...)
	if !cursor.finished() {
		return nil, errKeychainWrapFormat
	}
	return wrap, nil
}
