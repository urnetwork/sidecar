// The commitments of DESIGN-DETAILS 3.2.2 on the witness side: the curve's completeness, the generators
// against literals kept in testdata/vectors/commit.json, the wire form, and the blinds' freshness.

package smtpproof

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

// a = -1 is a square in F_r and d is not, which is what makes the addition law complete: no pair of
// points of the curve has a zero denominator. And l is prime, with the cofactor 8 the curve's order over l.
func TestCommitCurveIsComplete(t *testing.T) {
	curve := twistededwards.GetEdwardsCurve()
	var minusOne fr.Element
	minusOne.SetOne()
	minusOne.Neg(&minusOne)
	if !curve.A.Equal(&minusOne) {
		t.Fatalf("a is %s", curve.A.String())
	}
	if curve.A.Legendre() != 1 {
		t.Error("a = -1 is not a square in F_r")
	}
	if curve.D.Legendre() != -1 {
		t.Error("d is a square in F_r: the law is not complete")
	}
	if want, _ := new(big.Int).SetString("12181644023421730124874158521699555681764249180949974110617291017600649128846", 10); curve.D.BigInt(new(big.Int)).Cmp(want) != 0 {
		t.Errorf("d is %s", curve.D.String())
	}
	if want, _ := new(big.Int).SetString("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10); curve.Order.Cmp(want) != 0 || !curve.Order.ProbablyPrime(64) {
		t.Errorf("l is %s", curve.Order.String())
	}
	// 2^251 > l > 2^250: a blind of 251 bits covers every value below l
	if curve.Order.BitLen() != commitBlindBits {
		t.Errorf("l has %d bits", curve.Order.BitLen())
	}
}

// One generator as the vector file keeps it.
type testCommitGeneratorVector struct {
	Tag   string `json:"tag"`
	Index uint32 `json:"index"`
	X     string `json:"x"`
	Y     string `json:"y"`
}

type testCommitVectors struct {
	Generators []*testCommitGeneratorVector `json:"generators"`
}

// Each generator is computed and is also a literal in testdata/vectors/commit.json, so a change to
// either fails: each of order l, none the identity, and all distinct. SMTPPROOF_WRITE_VECTORS writes
// the file from the code, which is how it was made.
func TestCommitGeneratorsAreFixed(t *testing.T) {
	keyGenerators, scanGenerators := commitGeneratorSets()
	type named struct {
		tag   string
		index uint32
		point twistededwards.PointAffine
	}
	var computed []named
	for i, point := range keyGenerators.runs {
		computed = append(computed, named{tag: commitTagKey, index: uint32(i), point: point})
	}
	computed = append(computed,
		named{tag: commitTagKeyBlind, point: keyGenerators.blind},
		named{tag: commitTagScan, point: scanGenerators.runs[0]},
		named{tag: commitTagScanBlind, point: scanGenerators.blind})
	if len(keyGenerators.runs) != 3 {
		t.Errorf("%d key generators: 704 bits take 3 runs", len(keyGenerators.runs))
	}
	curve := twistededwards.GetEdwardsCurve()
	vectors := &testCommitVectors{}
	for i, generator := range computed {
		point := generator.point
		if !point.IsOnCurve() || point.IsZero() {
			t.Errorf("%s %d is the identity or off the curve", generator.tag, generator.index)
		}
		var times twistededwards.PointAffine
		times.ScalarMultiplication(&point, &curve.Order)
		if !times.IsZero() {
			t.Errorf("%s %d is not of order l", generator.tag, generator.index)
		}
		for _, other := range computed[:i] {
			if other.point.Equal(&point) {
				t.Errorf("%s %d repeats %s %d", generator.tag, generator.index, other.tag, other.index)
			}
		}
		x := point.X.Bytes()
		y := point.Y.Bytes()
		vectors.Generators = append(vectors.Generators, &testCommitGeneratorVector{Tag: generator.tag, Index: generator.index, X: hex.EncodeToString(x[:]), Y: hex.EncodeToString(y[:])})
	}
	encoded, err := json.MarshalIndent(vectors, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	path := filepath.Join("testdata", "vectors", "commit.json")
	if os.Getenv("SMTPPROOF_WRITE_VECTORS") != "" {
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written, encoded) {
		t.Errorf("%s differs from the generators this build computes; set SMTPPROOF_WRITE_VECTORS to rewrite it", path)
	}
}

// A commitment is the sum DESIGN-DETAILS 3.2.2 writes: run j of 246 bits on G_j and the blind on H, which
// gnark-crypto's own arithmetic gives the same, and the wire form round-trips.
func TestCommitKeysIsTheWrittenSum(t *testing.T) {
	keyGenerators, _ := commitGeneratorSets()
	clientKey := bytes.Repeat([]byte{0x11}, tlsAes128KeyBytes)
	serverKey := bytes.Repeat([]byte{0x22}, tlsAes128KeyBytes)
	clientIv := bytes.Repeat([]byte{0x33}, tlsIv13Bytes)
	serverIv := bytes.Repeat([]byte{0x44}, tlsIv13Bytes)
	blind := big.NewInt(12345)
	commitment, err := commitKeys(clientKey, clientIv, serverKey, serverIv, blind)
	if err != nil {
		t.Fatal(err)
	}
	// the octets in order, least significant bit first, as integers of 246 bits
	bits := commitOctetBits(clientKey, clientIv, serverKey, serverIv)
	if len(bits) != 448 {
		t.Fatalf("%d bits", len(bits))
	}
	var want twistededwards.PointAffine
	want.X.SetZero()
	want.Y.SetOne()
	for run := 0; run*commitRunBits < len(bits); run += 1 {
		value := new(big.Int)
		for i := run * commitRunBits; i < min((run+1)*commitRunBits, len(bits)); i += 1 {
			if bits[i] == 1 {
				value.SetBit(value, i-run*commitRunBits, 1)
			}
		}
		var term twistededwards.PointAffine
		term.ScalarMultiplication(&keyGenerators.runs[run], value)
		want.Add(&want, &term)
	}
	var blinded twistededwards.PointAffine
	blinded.ScalarMultiplication(&keyGenerators.blind, blind)
	want.Add(&want, &blinded)
	if !want.Equal(&commitment) {
		t.Error("the commitment is not the written sum")
	}
	decoded, err := decodeCommitment(encodeCommitment(commitment))
	if err != nil || !decoded.Equal(&commitment) {
		t.Errorf("the wire form does not round-trip: %v", err)
	}
	// a 1.2 salt commits as the salt and 8 zero octets
	salted, err := commitKeys(clientKey, clientIv[:tlsSalt12Bytes], serverKey, serverIv[:tlsSalt12Bytes], blind)
	if err != nil {
		t.Fatal(err)
	}
	padded, err := commitKeys(clientKey, append(bytes.Clone(clientIv[:tlsSalt12Bytes]), make([]byte, 8)...), serverKey, append(bytes.Clone(serverIv[:tlsSalt12Bytes]), make([]byte, 8)...), blind)
	if err != nil || !salted.Equal(&padded) {
		t.Errorf("a salt does not commit as the salt and 8 zero octets: %v", err)
	}
	// another server key is another commitment
	other, _ := commitKeys(clientKey, clientIv, clientKey, serverIv, blind)
	if other.Equal(&commitment) {
		t.Error("another server key gave the same commitment")
	}
	curve := twistededwards.GetEdwardsCurve()
	if _, err := commitKeys(clientKey, clientIv, serverKey, serverIv, &curve.Order); err == nil {
		t.Error("a blind of l was taken")
	}
}

// DESIGN-DETAILS 3.2.5's form: 64 octets, each coordinate below r, a point of the curve. Anything else
// is no commitment.
func TestCommitmentFormIsRefusedOtherwise(t *testing.T) {
	commitment, err := commitCarry(0x123456, big.NewInt(99))
	if err != nil {
		t.Fatal(err)
	}
	encoded := encodeCommitment(commitment)
	modulus := fr.Modulus().FillBytes(make([]byte, commitCoordinateBytes))
	offCurve := bytes.Clone(encoded)
	offCurve[commitmentBytes-1] ^= 1
	for _, c := range []struct {
		name    string
		encoded []byte
	}{
		{name: "empty", encoded: nil},
		{name: "short", encoded: encoded[:commitmentBytes-1]},
		{name: "long", encoded: append(bytes.Clone(encoded), 0)},
		{name: "x of r", encoded: append(bytes.Clone(modulus), encoded[commitCoordinateBytes:]...)},
		{name: "y of r", encoded: append(bytes.Clone(encoded[:commitCoordinateBytes]), modulus...)},
		{name: "off the curve", encoded: offCurve},
	} {
		if _, err := decodeCommitment(c.encoded); !errors.Is(err, errCommitmentForm) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if _, err := decodeCommitment(encoded); err != nil {
		t.Error(err)
	}
	if _, err := commitCarry(1<<carryStateBits, big.NewInt(1)); err == nil {
		t.Error("a 25-bit state was committed")
	}
}

// Every blind is drawn fresh, below l, from crypto/rand: two connections' key blinds and two carries'
// blinds differ, and the same keys under two blinds give two commitments.
func TestCommitBlindsAreFresh(t *testing.T) {
	curve := twistededwards.GetEdwardsCurve()
	seen := map[string]bool{}
	for range 64 {
		blind, err := newCommitBlind("test_commit_blind")
		if err != nil {
			t.Fatal(err)
		}
		if blind.Sign() < 0 || curve.Order.Cmp(blind) <= 0 {
			t.Fatalf("a blind of %d bits outside [0, l)", blind.BitLen())
		}
		if seen[blind.String()] {
			t.Fatal("a blind repeated")
		}
		seen[blind.String()] = true
	}
	key := bytes.Repeat([]byte{7}, tlsAes128KeyBytes)
	iv := bytes.Repeat([]byte{8}, tlsIv13Bytes)
	first, _ := newCommitBlind("test_commit_blind")
	second, _ := newCommitBlind("test_commit_blind")
	a, _ := commitKeys(key, iv, key, iv, first)
	b, _ := commitKeys(key, iv, key, iv, second)
	if a.Equal(&b) {
		t.Error("one set of keys under two fresh blinds gave one commitment")
	}
}
