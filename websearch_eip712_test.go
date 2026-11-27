//go:build !ios_extension && !sidecar_http

package sidecar_test

// EIP-3009's digest, the signature's conversion and recovery, and the authorization's window (SRCH-M13-01), held to
// Circle's TRANSFER_WITH_AUTHORIZATION_TYPEHASH, a plain encoder written here, and the fakes' own encoder
// (computetest's base_evm.go), written apart, so each checks the other.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest/computetest"
)

// TRANSFER_WITH_AUTHORIZATION_TYPEHASH as FiatToken's EIP3009.sol declares it, and EIP-712's domain type hash.
const (
	testTransferWithAuthorizationTypeHash = "7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267"
	testEip712DomainTypeHash              = "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f"
)

func testKeccak(parts ...[]byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	for _, part := range parts {
		hash.Write(part)
	}
	return hash.Sum(nil)
}

func testHexBytes(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// Synthetic bytes from a label, never a live value.
func testSyntheticBytes(label string, count int) []byte {
	out := []byte{}
	for i := 0; len(out) < count; i += 1 {
		sum := sha256.Sum256([]byte(label + string(rune('a'+i))))
		out = append(out, sum[:]...)
	}
	return out[:count]
}

// A synthetic domain on a test chain, its contract drawn from a label.
func testWebSearchDomain(t *testing.T) *sidecar.WebSearchEip712Domain {
	t.Helper()
	contract, err := sidecar.WebSearchAddressOf(testSyntheticBytes("test usdc contract", 20))
	if err != nil {
		t.Fatal(err)
	}
	return &sidecar.WebSearchEip712Domain{Name: "USD Coin", Version: "2", ChainId: 84532, VerifyingContract: contract}
}

// A synthetic authorization, unsigned.
func testWebSearchAuthorization(value uint64, minuteS int64) *protocol.ComputeSearchAuthorization {
	return &protocol.ComputeSearchAuthorization{
		From:         testSyntheticBytes("test payer", 20),
		To:           testSyntheticBytes("test payee", 20),
		Value:        value,
		ValidAfterS:  minuteS - 60,
		ValidBeforeS: minuteS + 120,
		Nonce:        testSyntheticBytes("test nonce", 32),
	}
}

// The plain encoder: each word built by hand with math/big, the type hashes the declared constants.
func testPlainDigest(t *testing.T, domain *sidecar.WebSearchEip712Domain, authorization *protocol.ComputeSearchAuthorization) []byte {
	t.Helper()
	word := func(value *big.Int) []byte {
		out := make([]byte, 32)
		value.FillBytes(out)
		return out
	}
	address := func(value []byte) []byte {
		return word(new(big.Int).SetBytes(value))
	}
	separator := testKeccak(testHexBytes(t, testEip712DomainTypeHash), testKeccak([]byte(domain.Name)),
		testKeccak([]byte(domain.Version)), word(new(big.Int).SetUint64(domain.ChainId)), address(domain.VerifyingContract[:]))
	structHash := testKeccak(testHexBytes(t, testTransferWithAuthorizationTypeHash), address(authorization.From),
		address(authorization.To), word(new(big.Int).SetUint64(authorization.Value)),
		word(big.NewInt(authorization.ValidAfterS)), word(big.NewInt(authorization.ValidBeforeS)), authorization.Nonce)
	return testKeccak([]byte{0x19, 0x01}, separator, structHash)
}

// The Keccak-256 of each type string is the hash FiatToken declares, and the digest hashes with exactly those: a type
// string off by a byte would change both.
func TestWebSearchTypehash(t *testing.T) {
	transferType := "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
	if got := hex.EncodeToString(testKeccak([]byte(transferType))); got != testTransferWithAuthorizationTypeHash {
		t.Fatalf("the transfer type hashes to %s", got)
	}
	domainType := "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
	if got := hex.EncodeToString(testKeccak([]byte(domainType))); got != testEip712DomainTypeHash {
		t.Fatalf("the domain type hashes to %s", got)
	}
	domain := testWebSearchDomain(t)
	authorization := testWebSearchAuthorization(10000, 1767225600)
	digest, err := sidecar.WebSearchTransferDigest(domain, authorization)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digest[:], testPlainDigest(t, domain, authorization)) {
		t.Fatal("the digest does not hash with FiatToken's type hashes")
	}
}

// The plain encoder and the fakes' encoder agree with WebSearchTransferDigest on the domain separator and the struct
// hash, across values, windows, chains and names.
func TestWebSearchDigestVector(t *testing.T) {
	domain := testWebSearchDomain(t)
	cases := []struct {
		domain        *sidecar.WebSearchEip712Domain
		authorization *protocol.ComputeSearchAuthorization
	}{
		{domain: domain, authorization: testWebSearchAuthorization(10000, 1767225600)},
		{domain: domain, authorization: testWebSearchAuthorization(15000, 1767225660)},
		{domain: domain, authorization: testWebSearchAuthorization(1, 60)},
		{domain: &sidecar.WebSearchEip712Domain{Name: "Synthetic Dollar", Version: "1", ChainId: 1 << 40, VerifyingContract: domain.VerifyingContract},
			authorization: testWebSearchAuthorization(^uint64(0), 1767225600)},
	}
	for _, c := range cases {
		digest, err := sidecar.WebSearchTransferDigest(c.domain, c.authorization)
		if err != nil {
			t.Fatal(err)
		}
		if plain := testPlainDigest(t, c.domain, c.authorization); !bytes.Equal(digest[:], plain) {
			t.Errorf("the plain encoder's digest %x, and %x", plain, digest)
		}
		fakeDomain := &computetest.FakeEip712Domain{Name: c.domain.Name, Version: c.domain.Version, ChainId: c.domain.ChainId,
			VerifyingContract: computetest.FakeEvmAddress(c.domain.VerifyingContract)}
		fakeAuth := &computetest.FakeTransferAuthorization{
			From:        computetest.FakeEvmAddress(c.authorization.From),
			To:          computetest.FakeEvmAddress(c.authorization.To),
			Value:       new(big.Int).SetUint64(c.authorization.Value),
			ValidAfter:  uint64(c.authorization.ValidAfterS),
			ValidBefore: uint64(c.authorization.ValidBeforeS),
			Nonce:       [32]byte(c.authorization.Nonce),
		}
		if fake := computetest.FakeTransferWithAuthorizationDigest(fakeDomain, fakeAuth); fake != digest {
			t.Errorf("the fakes' digest %x, and %x", fake, digest)
		}
	}
}

// Nothing is hashed for an address that is not 20 bytes, a nonce that is not 32, or a window that closes before it
// opens or opens before 0.
func TestWebSearchDigestRefusesMalformed(t *testing.T) {
	domain := testWebSearchDomain(t)
	planted := []func(authorization *protocol.ComputeSearchAuthorization){
		func(authorization *protocol.ComputeSearchAuthorization) { authorization.From = authorization.From[:19] },
		func(authorization *protocol.ComputeSearchAuthorization) { authorization.To = append(authorization.To, 0) },
		func(authorization *protocol.ComputeSearchAuthorization) { authorization.Nonce = authorization.Nonce[:31] },
		func(authorization *protocol.ComputeSearchAuthorization) { authorization.Nonce = append(authorization.Nonce, 0) },
		func(authorization *protocol.ComputeSearchAuthorization) { authorization.ValidAfterS = -1 },
		func(authorization *protocol.ComputeSearchAuthorization) {
			authorization.ValidBeforeS = authorization.ValidAfterS
		},
	}
	for i, plant := range planted {
		authorization := testWebSearchAuthorization(10000, 1767225600)
		plant(authorization)
		if _, err := sidecar.WebSearchTransferDigest(domain, authorization); !errors.Is(err, sidecar.ErrWebSearchEvmMalformed) {
			t.Errorf("planted %d: %v", i, err)
		}
	}
}

// A test key from a label: the first scalar of its hash secp256k1 takes.
func testSecp256k1Key(t *testing.T, label string) *secp256k1.PrivateKey {
	t.Helper()
	var scalar secp256k1.ModNScalar
	if overflow := scalar.SetByteSlice(testSyntheticBytes(label, 32)); overflow || scalar.IsZero() {
		t.Fatal("the test scalar is not a key")
	}
	return secp256k1.NewPrivateKey(&scalar)
}

// A test key signs, decred's compact form converts to r ‖ s ‖ v whichever form its key takes, and recovery names its
// address; a high s, and v of 0, 1 and 29, are refused.
func TestWebSearchRecoverRoundTrip(t *testing.T) {
	key := testSecp256k1Key(t, "test payer key")
	address := sidecar.WebSearchAddressOfKey(key.PubKey())
	domain := testWebSearchDomain(t)
	authorization := testWebSearchAuthorization(10000, 1767225600)
	authorization.From = address[:]
	digest, err := sidecar.WebSearchTransferDigest(domain, authorization)
	if err != nil {
		t.Fatal(err)
	}
	for _, compressed := range []bool{false, true} {
		compact := ecdsa.SignCompact(key, digest[:], compressed)
		signature, err := sidecar.WebSearchEvmSignature(compact)
		if err != nil {
			t.Fatal(err)
		}
		if v := signature[64]; v != 27 && v != 28 {
			t.Fatalf("v %d from header %d", v, compact[0])
		}
		if !bytes.Equal(signature[:64], compact[1:]) {
			t.Fatal("r and s moved in the conversion")
		}
		recovered, err := sidecar.WebSearchRecoverSigner(digest, signature)
		if err != nil || recovered != address {
			t.Fatalf("recovered %s, %v; want %s", recovered.Hex(), err, address.Hex())
		}
		// RFC 6979: the same digest signs to the same bytes
		if again := ecdsa.SignCompact(key, digest[:], compressed); !bytes.Equal(again, compact) {
			t.Fatal("two signatures of one digest differ")
		}
		// the fakes recover it too
		if fake, err := computetest.FakeRecoverEvmSigner(digest, signature); err != nil || fake != computetest.FakeEvmAddress(address) {
			t.Fatalf("the fakes recover %v, %v", fake, err)
		}
	}
	signature, _ := sidecar.WebSearchEvmSignature(ecdsa.SignCompact(key, digest[:], false))
	malleated := computetest.FakeEvmMalleate(signature)
	if _, err := sidecar.WebSearchRecoverSigner(digest, malleated); !errors.Is(err, sidecar.ErrWebSearchEvmSignature) {
		t.Errorf("a high s: %v", err)
	}
	highCompact := append([]byte{malleated[64]}, malleated[:64]...)
	if _, err := sidecar.WebSearchEvmSignature(highCompact); !errors.Is(err, sidecar.ErrWebSearchEvmSignature) {
		t.Errorf("a compact high s: %v", err)
	}
	for _, v := range []byte{0, 1, 29} {
		planted := bytes.Clone(signature)
		planted[64] = v
		if _, err := sidecar.WebSearchRecoverSigner(digest, planted); !errors.Is(err, sidecar.ErrWebSearchEvmSignature) {
			t.Errorf("v %d: %v", v, err)
		}
	}
	if _, err := sidecar.WebSearchRecoverSigner(digest, signature[:64]); !errors.Is(err, sidecar.ErrWebSearchEvmSignature) {
		t.Errorf("64 bytes: %v", err)
	}
	for _, header := range []byte{26, 35} {
		planted := append([]byte{header}, signature[:64]...)
		if _, err := sidecar.WebSearchEvmSignature(planted); !errors.Is(err, sidecar.ErrWebSearchEvmSignature) {
			t.Errorf("header %d: %v", header, err)
		}
	}
	// another digest recovers another address, never the signer's
	other := digest
	other[0] ^= 1
	if recovered, err := sidecar.WebSearchRecoverSigner(other, signature); err == nil && recovered == address {
		t.Error("another digest recovered the signer")
	}
}

// A minute's window is 180 s at most, valid_after its start less 60 s and valid_before its start plus 120 s; a minute
// off the grain, or one whose window would open before 0, has none; and the window reads back to its minute alone.
func TestWebSearchWindowBounds(t *testing.T) {
	settings := sidecar.DefaultWebSearchSettings()
	minuteS := time.Date(2026, 1, 1, 12, 34, 0, 0, time.UTC).Unix()
	validAfter, validBefore, err := sidecar.WebSearchWindow(settings, minuteS)
	if err != nil {
		t.Fatal(err)
	}
	if validAfter != minuteS-60 || validBefore != minuteS+120 || 180 < validBefore-validAfter {
		t.Fatalf("the window %d to %d of minute %d", validAfter, validBefore, minuteS)
	}
	if back, ok := sidecar.WebSearchWindowMinute(settings, validAfter, validBefore); !ok || back != minuteS {
		t.Fatalf("the window reads back to %d, %v", back, ok)
	}
	for _, planted := range [][2]int64{{validAfter + 1, validBefore + 1}, {validAfter, validBefore + 1}, {validAfter - 60, validBefore}} {
		if _, ok := sidecar.WebSearchWindowMinute(settings, planted[0], planted[1]); ok {
			t.Errorf("%v reads as a minute's window", planted)
		}
	}
	for _, planted := range []int64{minuteS + 1, minuteS - 30, 0, -60} {
		if _, _, err := sidecar.WebSearchWindow(settings, planted); !errors.Is(err, sidecar.ErrWebSearchEvmMalformed) {
			t.Errorf("minute %d: %v", planted, err)
		}
	}
	// the offer's 300 s holds the whole window
	if settings.WindowBefore+settings.WindowAfter > 300*time.Second {
		t.Error("the window passes the offer's reach")
	}
}

// CAIP-2's eip155 networks read to their chain ids; anything else is refused.
func TestWebSearchChainId(t *testing.T) {
	if chainId, err := sidecar.WebSearchChainId("eip155:84532"); err != nil || chainId != 84532 {
		t.Fatalf("eip155:84532 reads %d, %v", chainId, err)
	}
	for _, planted := range []string{"", "eip155:", "eip155:0", "eip155:084532", "eip155:-1", "eip155:1a", "solana:1", "eip155:18446744073709551616", "EIP155:1"} {
		if _, err := sidecar.WebSearchChainId(planted); !errors.Is(err, sidecar.ErrWebSearchEvmMalformed) {
			t.Errorf("%q: %v", planted, err)
		}
	}
}

// Addresses parse in either case to their bytes, and print lowercase or as EIP-55 writes them, which the fakes write too.
func TestWebSearchAddressForms(t *testing.T) {
	address, err := sidecar.WebSearchAddressOf(testSyntheticBytes("test address", 20))
	if err != nil {
		t.Fatal(err)
	}
	for _, form := range []string{address.Hex(), address.ChecksumHex()} {
		parsed, err := sidecar.ParseWebSearchAddress(form)
		if err != nil || parsed != address {
			t.Errorf("%s parses to %s, %v", form, parsed.Hex(), err)
		}
	}
	if fake := computetest.FakeEvmAddress(address).ChecksumHex(); fake != address.ChecksumHex() {
		t.Errorf("EIP-55: %s and the fakes' %s", address.ChecksumHex(), fake)
	}
	for _, planted := range []string{address.Hex()[2:], address.Hex()[:41], "0x" + address.Hex()[2:41] + "g"} {
		if _, err := sidecar.ParseWebSearchAddress(planted); !errors.Is(err, sidecar.ErrWebSearchEvmMalformed) {
			t.Errorf("%q: %v", planted, err)
		}
	}
	if _, err := sidecar.WebSearchAddressOf(make([]byte, 19)); !errors.Is(err, sidecar.ErrWebSearchEvmMalformed) {
		t.Error("19 bytes made an address")
	}
}
