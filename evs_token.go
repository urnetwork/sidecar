// Path tokens (§11.6's tokens row): what evs sees in place of every path name. A path of n components is the
// token path t_1..t_n, each t_i = HMAC-SHA256(K_path_p, t_{i-1} || name_i)[:16] with t_0 sixteen zero bytes, so a
// token names one path in one repo and one path epoch, the same on every ref of that repo (overlays need this), and
// says nothing of the name but its place in the tree. Deposit and erasure refs hold no path key: their entries are
// named by random 16-byte ids instead (plan-EVS1-epoch-kinds#2).
//
// A name is a path component's raw bytes as git stores them. Nothing here normalizes, so NFC and NFD spellings of
// one name are two paths, as in git. A component git's tree format cannot hold, one that is empty or holds a slash or
// a NUL, is refused, since no path a reader could rebuild has one.
//
// In object keys a token is 26 lowercase RFC 4648 base32 characters, unpadded (plan-EVS1-format-bytes#9); a token
// path is at most 32 components, which keeps the deepest idx/ key within MinIO's 1,024 bytes. A token path's bytes,
// which sorting, the digest and Merkle leaves read, are its tokens concatenated in order.
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// §11.6's token and token path bounds.
const (
	EvsTokenByteCount = 16
	// The most components a token path holds.
	EvsTokenPathMaxLength = 32
	// A token's form in an object key: 128 bits in 5-bit characters.
	evsTokenKeyLength = 26
)

// The lowercase RFC 4648 alphabet, unpadded, as object keys hold tokens.
var evsTokenEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// A token or token path that breaks §11.6's form, or a name no path can hold.
var ErrEvsTokenInvalid = errors.New("evs token invalid")

// One path component's token, or a deposit's or erasure entry's random id in a token's place.
type EvsToken [EvsTokenByteCount]byte

// The token of no component, t_0, which a top-level name's token and a top-level name's seal take as parent.
var EvsRootToken = EvsToken{}

// The 26 lowercase base32 characters an object key holds.
func (self EvsToken) String() string {
	return evsTokenEncoding.EncodeToString(self[:])
}

// A copy of the 16 bytes.
func (self EvsToken) Bytes() []byte {
	return bytes.Clone(self[:])
}

// A token from its key form: exactly 26 lowercase base32 characters whose last two unused bits are zero, so each
// token has one spelling and no two keys name one token. The error never repeats the input.
func ParseEvsToken(text string) (EvsToken, error) {
	token := EvsToken{}
	if len(text) != evsTokenKeyLength {
		return token, fmt.Errorf("%w: a key form of %d characters", ErrEvsTokenInvalid, len(text))
	}
	decoded, err := evsTokenEncoding.DecodeString(text)
	if err != nil || len(decoded) != EvsTokenByteCount {
		return token, fmt.Errorf("%w: not lowercase base32", ErrEvsTokenInvalid)
	}
	copy(token[:], decoded)
	if token.String() != text {
		return EvsToken{}, fmt.Errorf("%w: a key form with unused bits set", ErrEvsTokenInvalid)
	}
	return token, nil
}

// Exactly 16 bytes as a token.
func EvsTokenFromBytes(tokenBytes []byte) (EvsToken, error) {
	if len(tokenBytes) != EvsTokenByteCount {
		return EvsToken{}, fmt.Errorf("%w: a token of %d bytes", ErrEvsTokenInvalid, len(tokenBytes))
	}
	return EvsToken(tokenBytes), nil
}

// A random 16-byte id in a token's place: a deposit's entry, or an entry of the erasure ref, whose writers hold no
// path key (§11.6, plan-EVS1-epoch-kinds#2).
func NewEvsRandomToken() EvsToken {
	token := EvsToken{}
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	cryptorand.Read(token[:])
	return token
}

// t_i = HMAC-SHA256(K_path_p, t_{i-1} || name_i)[:16]: the token of name under parent in pathKey's epoch, parent being
// EvsRootToken for a top-level name.
func EvsPathToken(pathKey *EvsPathKey, parent EvsToken, name []byte) (EvsToken, error) {
	if err := pathKey.checkHeld(); err != nil {
		return EvsToken{}, err
	}
	if err := checkEvsPathName(name); err != nil {
		return EvsToken{}, err
	}
	mac := hmac.New(sha256.New, pathKey.key)
	mac.Write(parent[:])
	mac.Write(name)
	token := EvsToken{}
	copy(token[:], mac.Sum(nil))
	return token, nil
}

// The token path of a path given as its components' raw names, in pathKey's epoch: up to 32 components, none being
// the root, whose token path is empty in every epoch (question evs1-m2-24-root-directory-names, option 1).
func EvsPathTokens(pathKey *EvsPathKey, names [][]byte) (EvsTokenPath, error) {
	if EvsTokenPathMaxLength < len(names) {
		return nil, fmt.Errorf("%w: a path of %d components", ErrEvsTokenInvalid, len(names))
	}
	if err := pathKey.checkHeld(); err != nil {
		return nil, err
	}
	tokenPath := make(EvsTokenPath, 0, len(names))
	parent := EvsRootToken
	for _, name := range names {
		token, err := EvsPathToken(pathKey, parent, name)
		if err != nil {
			return nil, err
		}
		tokenPath = append(tokenPath, token)
		parent = token
	}
	return tokenPath, nil
}

// A name git's tree format can hold: not empty, and no slash or NUL. The error never repeats the name (I-13).
func checkEvsPathName(name []byte) error {
	if len(name) == 0 || bytes.ContainsAny(name, "/\x00") {
		return fmt.Errorf("%w: a path component is empty or holds a slash or NUL", ErrEvsTokenInvalid)
	}
	return nil
}

// A path's tokens in order, 1 to 32 of them in a change; a covering prefix may be shorter, down to none.
type EvsTokenPath []EvsToken

// A token path from the components EvsChange.token_path and its kin carry: up to 32, each exactly 16 bytes. An
// empty list is the empty path: the root, or a covering prefix that covers every change.
func ParseEvsTokenPath(components [][]byte) (EvsTokenPath, error) {
	if EvsTokenPathMaxLength < len(components) {
		return nil, fmt.Errorf("%w: a token path of %d components", ErrEvsTokenInvalid, len(components))
	}
	tokenPath := make(EvsTokenPath, len(components))
	for i, component := range components {
		token, err := EvsTokenFromBytes(component)
		if err != nil {
			return nil, err
		}
		tokenPath[i] = token
	}
	return tokenPath, nil
}

// A token path a change may name: 1 to 32 components, or the empty path, the ref's root (question
// evs1-m2-24-root-directory-names, option 1; DESIGN-DETAILS 9.2.8), which only a directory's delta may name: the
// payload's checks hold a change to that, and a source path, a move and a read may name the root as well.
func ParseEvsChangedTokenPath(components [][]byte) (EvsTokenPath, error) {
	return ParseEvsTokenPath(components)
}

// Its tokens concatenated, 16 bytes per component: what sorting, the digest and Merkle leaves read.
func (self EvsTokenPath) Bytes() []byte {
	tokenPathBytes := make([]byte, 0, len(self)*EvsTokenByteCount)
	for _, token := range self {
		tokenPathBytes = append(tokenPathBytes, token[:]...)
	}
	return tokenPathBytes
}

// Each component as its own 16 bytes, the form EvsChange.token_path and its kin carry.
func (self EvsTokenPath) Components() [][]byte {
	components := make([][]byte, len(self))
	for i, token := range self {
		components[i] = token.Bytes()
	}
	return components
}

// As an EvsTokenPath message.
func (self EvsTokenPath) Proto() *protocol.EvsTokenPath {
	return &protocol.EvsTokenPath{Token: self.Components()}
}

// -1, 0 or 1 by its bytes, §11.6's order: since every token is 16 bytes this is the order of the token sequences,
// a path sorting just before its children.
func (self EvsTokenPath) Compare(other EvsTokenPath) int {
	for i := range min(len(self), len(other)) {
		if order := bytes.Compare(self[i][:], other[i][:]); order != 0 {
			return order
		}
	}
	return len(self) - len(other)
}

// Whether prefix is this path or a path holding it. The empty path holds every path.
func (self EvsTokenPath) HasPrefix(prefix EvsTokenPath) bool {
	if len(self) < len(prefix) {
		return false
	}
	for i, token := range prefix {
		if self[i] != token {
			return false
		}
	}
	return true
}

// Whether it is the same path as other.
func (self EvsTokenPath) Equal(other EvsTokenPath) bool {
	return len(self) == len(other) && self.HasPrefix(other)
}

// Its last token, or EvsRootToken for the empty path: what a name's seal binds as the child.
func (self EvsTokenPath) Last() EvsToken {
	if len(self) == 0 {
		return EvsRootToken
	}
	return self[len(self)-1]
}

// The token of the directory holding its last component, EvsRootToken at the top: what a name's seal binds as the
// parent.
func (self EvsTokenPath) Parent() EvsToken {
	if len(self) < 2 {
		return EvsRootToken
	}
	return self[len(self)-2]
}

// The key form of each token, joined by slashes, as idx/ keys hold a path: t1/t2/.../tn.
func (self EvsTokenPath) KeyString() string {
	keyString := make([]byte, 0, len(self)*(evsTokenKeyLength+1))
	for i, token := range self {
		if 0 < i {
			keyString = append(keyString, '/')
		}
		keyString = append(keyString, token.String()...)
	}
	return string(keyString)
}
