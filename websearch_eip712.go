//go:build !ios_extension && !sidecar_http

// EIP-3009's TransferWithAuthorization under EIP-712, as USDC's FiatToken checks it on Base (DESIGN-COMPUTE §21.5,
// D-SRCH-2, D-SRCH-12, IC-10; SRCH-M13-01): the digest searchsigner signs, the device checks before it pays, and the
// window both take from the admission's minute.
//
//	digest     keccak256(0x19 0x01 ‖ domainSeparator ‖ structHash): the domain EIP712Domain(string name,string
//	           version,uint256 chainId,address verifyingContract), name and version from the policy's asset, chainId
//	           from its CAIP-2 network, verifyingContract its contract; the struct TransferWithAuthorization(address
//	           from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce); each string hashed,
//	           each address left-padded and each integer big-endian in a 32-byte word; Keccak-256 is x/crypto's legacy
//	           hash, never SHA3-256
//	signature  65 bytes, r ‖ s ‖ v, v 27 or 28, as EIP-3009's transferWithAuthorization takes v, r and s and x402's
//	           exact payload carries them. decred's compact signature puts its header byte first, 27 + recid and 4 more
//	           for a compressed key: it is converted, never passed as v. A high s (EIP-2) and any other v are refused
//	window     valid_after the minute's start less WindowBefore, valid_before its start plus WindowAfter (60 s and
//	           120 s), a fixed function of the minute and nothing else, so nothing URnetwork chose goes on chain
//
// An address is compared as its 20 bytes, never as hex of either case. A nonce that is not exactly 32 bytes and an
// address that is not exactly 20 are refused before anything is hashed. Nothing here reads a clock.
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"

	"github.com/urnetwork/sidecar/protocol"
)

// The type strings EIP-712 and EIP-3009 hash, and EIP-712's prefix: identifiers of the format.
const (
	webSearchEip712DomainType      = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
	webSearchTransferWithAuthType  = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
	webSearchEip155Prefix          = "eip155:"
	webSearchCompactUncompressedV  = 27
	webSearchCompactCompressedV    = 31
	webSearchCompactLastV          = 34
	webSearchEvmSignatureByteCount = 65
	webSearchAddressByteCount      = 20
	webSearchHashByteCount         = 32
)

// EIP-712's prefix of a typed digest.
var webSearchEip712Prefix = []byte{0x19, 0x01}

var (
	// An address, nonce, signature, network or window that is not of its format: refused before anything is hashed.
	ErrWebSearchEvmMalformed = errors.New("web search: a malformed EVM value")
	// A signature that recovers no signer: a high s, a v but 27 or 28, a scalar out of range or no point.
	ErrWebSearchEvmSignature = errors.New("web search: an EVM signature that recovers no signer")
)

// The hashes of the two type strings, which FiatToken's source declares: TRANSFER_WITH_AUTHORIZATION_TYPEHASH and the
// domain's.
var (
	webSearchDomainTypeHash   = webSearchKeccak([]byte(webSearchEip712DomainType))
	webSearchTransferTypeHash = webSearchKeccak([]byte(webSearchTransferWithAuthType))
	// secp256k1's order's half: an s above it is the malleable twin EIP-2 refuses.
	webSearchSecp256k1HalfOrder = new(big.Int).Rsh(secp256k1.S256().N, 1)
)

// An EVM address.
type WebSearchAddress [webSearchAddressByteCount]byte

// The address of exactly 20 bytes; ErrWebSearchEvmMalformed for any other length.
func WebSearchAddressOf(value []byte) (WebSearchAddress, error) {
	var address WebSearchAddress
	if len(value) != len(address) {
		return address, fmt.Errorf("%w: an address of %d bytes", ErrWebSearchEvmMalformed, len(value))
	}
	copy(address[:], value)
	return address, nil
}

// An address from 0x and 40 hex digits in either case; an EIP-55 checksum is not checked, the bytes being what is
// compared.
func ParseWebSearchAddress(value string) (WebSearchAddress, error) {
	var address WebSearchAddress
	digits, ok := strings.CutPrefix(value, "0x")
	if !ok || len(digits) != 2*len(address) {
		return address, fmt.Errorf("%w: an address that is not 0x and 40 hex digits", ErrWebSearchEvmMalformed)
	}
	if _, err := hex.Decode(address[:], []byte(digits)); err != nil {
		return address, fmt.Errorf("%w: an address that is not hex", ErrWebSearchEvmMalformed)
	}
	return address, nil
}

// 0x and lowercase hex.
func (self WebSearchAddress) Hex() string {
	return "0x" + hex.EncodeToString(self[:])
}

// EIP-55's mixed-case form.
func (self WebSearchAddress) ChecksumHex() string {
	lower := hex.EncodeToString(self[:])
	hash := webSearchKeccak([]byte(lower))
	out := []byte(lower)
	for i, c := range out {
		nibble := hash[i/2]
		if i%2 == 0 {
			nibble >>= 4
		}
		if 'a' <= c && c <= 'f' && 8 <= nibble&0x0f {
			out[i] = c - 'a' + 'A'
		}
	}
	return "0x" + string(out)
}

// The address of a secp256k1 public key: the last 20 bytes of the Keccak-256 of its uncompressed X ‖ Y.
func WebSearchAddressOfKey(publicKey *secp256k1.PublicKey) WebSearchAddress {
	uncompressed := publicKey.SerializeUncompressed()
	hash := webSearchKeccak(uncompressed[1:])
	var address WebSearchAddress
	copy(address[:], hash[len(hash)-len(address):])
	return address
}

// Keccak-256 of the parts in order.
func webSearchKeccak(parts ...[]byte) [webSearchHashByteCount]byte {
	hash := sha3.NewLegacyKeccak256()
	for _, part := range parts {
		hash.Write(part)
	}
	var out [webSearchHashByteCount]byte
	hash.Sum(out[:0])
	return out
}

// A 32-byte word: an address left-padded.
func webSearchWordAddress(address WebSearchAddress) []byte {
	word := make([]byte, webSearchHashByteCount)
	copy(word[len(word)-len(address):], address[:])
	return word
}

// A 32-byte word: an unsigned integer big-endian.
func webSearchWordUint(value uint64) []byte {
	word := make([]byte, webSearchHashByteCount)
	new(big.Int).SetUint64(value).FillBytes(word)
	return word
}

// The chain id of a CAIP-2 EVM network, eip155 and a decimal id with no leading zero, above zero and within 64 bits.
func WebSearchChainId(network string) (uint64, error) {
	digits, ok := strings.CutPrefix(network, webSearchEip155Prefix)
	if !ok || digits == "" || digits[0] == '0' || strings.TrimLeft(digits, "0123456789") != "" {
		return 0, fmt.Errorf("%w: a network that is not eip155:<chain id>", ErrWebSearchEvmMalformed)
	}
	chainId, err := strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: a chain id past 64 bits", ErrWebSearchEvmMalformed)
	}
	return chainId, nil
}

// An asset's EIP-712 domain: its name and version, as the policy pins them, the chain and the contract.
type WebSearchEip712Domain struct {
	Name              string
	Version           string
	ChainId           uint64
	VerifyingContract WebSearchAddress
}

// The domain's separator.
func (self *WebSearchEip712Domain) separator() [webSearchHashByteCount]byte {
	name := webSearchKeccak([]byte(self.Name))
	version := webSearchKeccak([]byte(self.Version))
	return webSearchKeccak(webSearchDomainTypeHash[:], name[:], version[:], webSearchWordUint(self.ChainId),
		webSearchWordAddress(self.VerifyingContract))
}

// The digest a payer signs for authorization under domain (see the file header): its from, to, value, window and nonce,
// its signature not read. ErrWebSearchEvmMalformed for an address that is not 20 bytes, a nonce that is not 32, a
// negative window or one that closes before it opens.
func WebSearchTransferDigest(domain *WebSearchEip712Domain, authorization *protocol.ComputeSearchAuthorization) ([webSearchHashByteCount]byte, error) {
	var digest [webSearchHashByteCount]byte
	if domain == nil || authorization == nil {
		return digest, fmt.Errorf("%w: no domain or no authorization", ErrWebSearchEvmMalformed)
	}
	from, err := WebSearchAddressOf(authorization.GetFrom())
	if err != nil {
		return digest, err
	}
	to, err := WebSearchAddressOf(authorization.GetTo())
	if err != nil {
		return digest, err
	}
	nonce := authorization.GetNonce()
	if len(nonce) != webSearchHashByteCount {
		return digest, fmt.Errorf("%w: a nonce of %d bytes", ErrWebSearchEvmMalformed, len(nonce))
	}
	validAfter, validBefore := authorization.GetValidAfterS(), authorization.GetValidBeforeS()
	if validAfter < 0 || validBefore <= validAfter {
		return digest, fmt.Errorf("%w: a window from %d to %d", ErrWebSearchEvmMalformed, validAfter, validBefore)
	}
	structHash := webSearchKeccak(webSearchTransferTypeHash[:], webSearchWordAddress(from), webSearchWordAddress(to),
		webSearchWordUint(authorization.GetValue()), webSearchWordUint(uint64(validAfter)), webSearchWordUint(uint64(validBefore)),
		nonce)
	separator := domain.separator()
	return webSearchKeccak(webSearchEip712Prefix, separator[:], structHash[:]), nil
}

// The address that signed digest, from r ‖ s ‖ v (see the file header's signature row).
func WebSearchRecoverSigner(digest [webSearchHashByteCount]byte, signature []byte) (WebSearchAddress, error) {
	var address WebSearchAddress
	if len(signature) != webSearchEvmSignatureByteCount {
		return address, fmt.Errorf("%w: %d bytes", ErrWebSearchEvmSignature, len(signature))
	}
	v := signature[64]
	if v != webSearchCompactUncompressedV && v != webSearchCompactUncompressedV+1 {
		return address, fmt.Errorf("%w: v %d", ErrWebSearchEvmSignature, v)
	}
	if webSearchSecp256k1HalfOrder.Cmp(new(big.Int).SetBytes(signature[32:64])) < 0 {
		return address, fmt.Errorf("%w: a high s", ErrWebSearchEvmSignature)
	}
	// decred's compact form: the header byte for an uncompressed key, then r and s
	compact := make([]byte, webSearchEvmSignatureByteCount)
	compact[0] = v
	copy(compact[1:], signature[:64])
	publicKey, _, err := ecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		return address, fmt.Errorf("%w: %v", ErrWebSearchEvmSignature, err)
	}
	return WebSearchAddressOfKey(publicKey), nil
}

// r ‖ s ‖ v from decred's compact signature, its header byte 27 + recid, 4 more for a compressed key, first: v is
// 27 + recid whichever the key's form, and a high s is refused, as RFC 6979's signer never makes one.
func WebSearchEvmSignature(compact []byte) ([]byte, error) {
	if len(compact) != webSearchEvmSignatureByteCount {
		return nil, fmt.Errorf("%w: a compact signature of %d bytes", ErrWebSearchEvmSignature, len(compact))
	}
	header := compact[0]
	if header < webSearchCompactUncompressedV || webSearchCompactLastV < header {
		return nil, fmt.Errorf("%w: a compact header %d", ErrWebSearchEvmSignature, header)
	}
	recid := header - webSearchCompactUncompressedV
	if webSearchCompactCompressedV <= header {
		recid = header - webSearchCompactCompressedV
	}
	if 1 < recid {
		// recids 2 and 3 name an r past the order, which no signer of a 256-bit hash makes and EIP-3009 cannot carry
		return nil, fmt.Errorf("%w: recovery id %d", ErrWebSearchEvmSignature, recid)
	}
	if webSearchSecp256k1HalfOrder.Cmp(new(big.Int).SetBytes(compact[33:65])) < 0 {
		return nil, fmt.Errorf("%w: a high s", ErrWebSearchEvmSignature)
	}
	signature := make([]byte, webSearchEvmSignatureByteCount)
	copy(signature, compact[1:])
	signature[64] = webSearchCompactUncompressedV + recid
	return signature, nil
}

// The window of the minute starting at minuteS (see the file header's window row): valid_after and valid_before, in
// Unix seconds. ErrWebSearchEvmMalformed for a minute that is not on the grain, or whose window would open before 0.
func WebSearchWindow(settings *WebSearchSettings, minuteS int64) (int64, int64, error) {
	grain := int64(settings.AuthorizationGrain.Seconds())
	before, after := int64(settings.WindowBefore.Seconds()), int64(settings.WindowAfter.Seconds())
	if grain <= 0 || before < 0 || after <= 0 {
		return 0, 0, fmt.Errorf("%w: settings without a grain or a window", ErrWebSearchEvmMalformed)
	}
	if minuteS%grain != 0 || minuteS < before {
		return 0, 0, fmt.Errorf("%w: a minute of %d s", ErrWebSearchEvmMalformed, minuteS)
	}
	return minuteS - before, minuteS + after, nil
}

// The minute whose window validAfterS and validBeforeS are, and false where they are no minute's.
func WebSearchWindowMinute(settings *WebSearchSettings, validAfterS int64, validBeforeS int64) (int64, bool) {
	minuteS := validAfterS + int64(settings.WindowBefore.Seconds())
	after, before, err := WebSearchWindow(settings, minuteS)
	if err != nil || after != validAfterS || before != validBeforeS {
		return 0, false
	}
	return minuteS, true
}
