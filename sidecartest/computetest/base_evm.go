// The EVM primitives FakeBase and FakeParallel share (CTEST-M13-03; DESIGN-COMPUTE §21.5): addresses, Keccak-256 by
// x/crypto's legacy hash, EIP-712's digest of USDC's EIP-3009 TransferWithAuthorization, and secp256k1 signatures made
// and recovered for real with decred's library, so a fake that settles a payment has checked its signature as the
// chain would: a fake that accepted any signature would prove nothing. This is the fakes' own encoder, written apart
// from SRCH's (websearch_eip712.go, SRCH-M13-01), so each checks the other.
//
//	digest     keccak256(0x19 0x01 ‖ domainSeparator ‖ structHash), the domain EIP712Domain(string name,string
//	           version,uint256 chainId,address verifyingContract), the struct TransferWithAuthorization(address
//	           from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce); addresses left-padded
//	           and integers big-endian in 32-byte words
//	signature  65 bytes, r ‖ s ‖ v with v 27 or 28, as EIP-3009 takes v, r and s; decred's compact form, its header
//	           byte first, is converted and never passed as v; a high s (EIP-2) and any other v are refused
//
// Nothing here reads a clock.

package computetest

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

var (
	// An address, hash or signature that is not its size or not hex.
	ErrFakeEvmMalformed = errors.New("computetest: a malformed EVM value")
	// A signature that recovers no key: a high s, a v but 27 or 28, or a point off the curve.
	ErrFakeEvmSignature = errors.New("computetest: an EVM signature that recovers no signer")
)

// An EVM address.
type FakeEvmAddress [20]byte

// 0x and lowercase hex, as JSON-RPC answers write an address.
func (self FakeEvmAddress) Hex() string {
	return "0x" + hex.EncodeToString(self[:])
}

// EIP-55's mixed-case form, as the gateway's offer writes its asset.
func (self FakeEvmAddress) ChecksumHex() string {
	lower := hex.EncodeToString(self[:])
	hash := fakeKeccak([]byte(lower))
	out := []byte(lower)
	for i, c := range out {
		nibble := hash[i/2]
		if i%2 == 0 {
			nibble >>= 4
		}
		if c >= 'a' && c <= 'f' && nibble&0x0f >= 8 {
			out[i] = c - 'a' + 'A'
		}
	}
	return "0x" + string(out)
}

// An address from 0x and 40 hex digits in any case; an EIP-55 checksum is not checked.
func ParseFakeEvmAddress(value string) (FakeEvmAddress, error) {
	var address FakeEvmAddress
	digits, ok := strings.CutPrefix(value, "0x")
	if !ok || len(digits) != 40 {
		return address, fmt.Errorf("%w: address %q", ErrFakeEvmMalformed, value)
	}
	if _, err := hex.Decode(address[:], []byte(strings.ToLower(digits))); err != nil {
		return address, fmt.Errorf("%w: address %q", ErrFakeEvmMalformed, value)
	}
	return address, nil
}

// 0x and exactly 2n hex digits.
func fakeEvmParseBytes(value string, byteCount int) ([]byte, error) {
	digits, ok := strings.CutPrefix(value, "0x")
	if !ok || len(digits) != 2*byteCount {
		return nil, fmt.Errorf("%w: %d bytes %q", ErrFakeEvmMalformed, byteCount, value)
	}
	out, err := hex.DecodeString(strings.ToLower(digits))
	if err != nil {
		return nil, fmt.Errorf("%w: %q", ErrFakeEvmMalformed, value)
	}
	return out, nil
}

func fakeKeccak(parts ...[]byte) [32]byte {
	hash := sha3.NewLegacyKeccak256()
	for _, part := range parts {
		hash.Write(part)
	}
	var out [32]byte
	hash.Sum(out[:0])
	return out
}

// A 32-byte word: an address left-padded.
func fakeEvmWordAddress(address FakeEvmAddress) []byte {
	word := make([]byte, 32)
	copy(word[12:], address[:])
	return word
}

// A 32-byte word: an unsigned integer big-endian; one past 256 bits is refused by its caller's parse.
func fakeEvmWordInt(value *big.Int) []byte {
	word := make([]byte, 32)
	value.FillBytes(word)
	return word
}

func fakeEvmWordUint(value uint64) []byte {
	return fakeEvmWordInt(new(big.Int).SetUint64(value))
}

// The identifiers EIP-3009 and USDC's events and calls hash from their signatures.
var (
	fakeEip712DomainTypeHash          = fakeKeccak([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
	fakeTransferWithAuthorizationHash = fakeKeccak([]byte("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"))
	fakeTransferTopic                 = fakeKeccak([]byte("Transfer(address,address,uint256)"))
	fakeAuthorizationUsedTopic        = fakeKeccak([]byte("AuthorizationUsed(address,bytes32)"))
	fakeBalanceOfSelector             = fakeKeccak([]byte("balanceOf(address)"))
	fakeAuthorizationStateSelector    = fakeKeccak([]byte("authorizationState(address,bytes32)"))
	fakeDomainSeparatorSelector       = fakeKeccak([]byte("DOMAIN_SEPARATOR()"))
	fakeTransferWithAuthSelector      = fakeKeccak([]byte("transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)"))
	fakeTransferSelector              = fakeKeccak([]byte("transfer(address,uint256)"))
)

// A token's EIP-712 domain.
type FakeEip712Domain struct {
	Name              string
	Version           string
	ChainId           uint64
	VerifyingContract FakeEvmAddress
}

func (self *FakeEip712Domain) separator() [32]byte {
	name := fakeKeccak([]byte(self.Name))
	version := fakeKeccak([]byte(self.Version))
	return fakeKeccak(fakeEip712DomainTypeHash[:], name[:], version[:], fakeEvmWordUint(self.ChainId), fakeEvmWordAddress(self.VerifyingContract))
}

// EIP-3009's TransferWithAuthorization, as x402's exact payload carries it.
type FakeTransferAuthorization struct {
	From        FakeEvmAddress
	To          FakeEvmAddress
	Value       *big.Int
	ValidAfter  uint64
	ValidBefore uint64
	Nonce       [32]byte
}

// The digest a payer signs for auth under domain (see the file header).
func FakeTransferWithAuthorizationDigest(domain *FakeEip712Domain, auth *FakeTransferAuthorization) [32]byte {
	structHash := fakeKeccak(fakeTransferWithAuthorizationHash[:], fakeEvmWordAddress(auth.From), fakeEvmWordAddress(auth.To),
		fakeEvmWordInt(auth.Value), fakeEvmWordUint(auth.ValidAfter), fakeEvmWordUint(auth.ValidBefore), auth.Nonce[:])
	separator := domain.separator()
	return fakeKeccak([]byte{0x19, 0x01}, separator[:], structHash[:])
}

// secp256k1's order's half: an s above it is the malleable twin EIP-2 refuses.
var fakeSecp256k1HalfOrder = new(big.Int).Rsh(secp256k1.S256().N, 1)

// The address that signed digest, from r ‖ s ‖ v (see the file header's signature row).
func FakeRecoverEvmSigner(digest [32]byte, signature []byte) (FakeEvmAddress, error) {
	var address FakeEvmAddress
	if len(signature) != 65 {
		return address, fmt.Errorf("%w: %d bytes", ErrFakeEvmSignature, len(signature))
	}
	v := signature[64]
	if v != 27 && v != 28 {
		return address, fmt.Errorf("%w: v %d", ErrFakeEvmSignature, v)
	}
	if new(big.Int).SetBytes(signature[32:64]).Cmp(fakeSecp256k1HalfOrder) > 0 {
		return address, fmt.Errorf("%w: a high s", ErrFakeEvmSignature)
	}
	compact := make([]byte, 65)
	compact[0] = v
	copy(compact[1:], signature[:64])
	publicKey, _, err := ecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		return address, fmt.Errorf("%w: %v", ErrFakeEvmSignature, err)
	}
	return fakeEvmAddressOf(publicKey), nil
}

// The address of a public key: the last 20 bytes of the Keccak-256 of its uncompressed X ‖ Y.
func fakeEvmAddressOf(publicKey *secp256k1.PublicKey) FakeEvmAddress {
	uncompressed := publicKey.SerializeUncompressed()
	hash := fakeKeccak(uncompressed[1:])
	var address FakeEvmAddress
	copy(address[:], hash[12:])
	return address
}

// A secp256k1 key drawn from a seed: a test payer's, a facilitator's or a sender's.
type FakeEvmKey struct {
	privateKey *secp256k1.PrivateKey
	address    FakeEvmAddress
}

// A key from seed and label: the first scalar of their stream that secp256k1 takes.
func NewFakeEvmKey(seed string, label string) *FakeEvmKey {
	stream := newFakeStream(seed, "secp256k1 "+label)
	scalar := make([]byte, 32)
	for {
		io.ReadFull(stream, scalar)
		var modN secp256k1.ModNScalar
		if overflow := modN.SetByteSlice(scalar); !overflow && !modN.IsZero() {
			privateKey := secp256k1.NewPrivateKey(&modN)
			return &FakeEvmKey{privateKey: privateKey, address: fakeEvmAddressOf(privateKey.PubKey())}
		}
	}
}

func (self *FakeEvmKey) Address() FakeEvmAddress {
	return self.address
}

// r ‖ s ‖ v over digest, deterministic (RFC 6979) and low-s, v 27 or 28.
func (self *FakeEvmKey) SignDigest(digest [32]byte) []byte {
	compact := ecdsa.SignCompact(self.privateKey, digest[:], false)
	signature := make([]byte, 65)
	copy(signature, compact[1:])
	signature[64] = compact[0]
	return signature
}

// The signature of auth under domain.
func (self *FakeEvmKey) SignTransferWithAuthorization(domain *FakeEip712Domain, auth *FakeTransferAuthorization) []byte {
	return self.SignDigest(FakeTransferWithAuthorizationDigest(domain, auth))
}

// The malleable twin of a signature: s replaced by n - s and v flipped, which recovers the same signer on a curve that
// accepts it, and which EIP-2 and every check here refuse.
func FakeEvmMalleate(signature []byte) []byte {
	twin := append([]byte{}, signature...)
	s := new(big.Int).SetBytes(signature[32:64])
	new(big.Int).Sub(secp256k1.S256().N, s).FillBytes(twin[32:64])
	twin[64] = 27 + 28 - signature[64]
	return twin
}
