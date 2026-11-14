package smtpproof

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

// The Pedersen commitments of DESIGN-DETAILS 3.2.2, on the witness side: the key commitment C that the
// key part publishes over both directions' keys and IVs, and the carry a scan's state crosses records
// in. Both are over gnark-crypto's twisted Edwards curve whose base field is BN254's scalar field, so a
// point is two circuit wires (circuit_commit.go is the circuit side, which computes the same sums).
//
// Hiding is perfect: every generator has prime order l and a blind is uniform below l, so a commitment
// is a uniform point of the order-l subgroup whatever it holds. Binding is computational: two openings
// give a discrete-log relation among generators whose logs nobody knows. A blind is drawn here, from
// crypto/rand, once a connection and once a carry, and never derived or reused.

// The curve's and the commitments' fixed values: identifiers and cryptographic constants, not settings.
const (
	// What every generator's hash starts with.
	commitDomain = "urnetwork smtpproof commit v1"
	// The generator tags: the key commitment's runs and blind, and the carry's state and blind.
	commitTagKey       = "key"
	commitTagKeyBlind  = "key blind"
	commitTagScan      = "scan"
	commitTagScanBlind = "scan blind"
	// A message's bits are cut into runs of this many, each an integer below l.
	commitRunBits = 246
	// A blind's bits: l is just under 2^251.6, so 251 bits by rejection give every value below l.
	commitBlindBits = 251
	// A commitment on the wire: x then y, each 32 octets big-endian and below r.
	commitCoordinateBytes = 32
	commitmentBytes       = 2 * commitCoordinateBytes
	// The bits of a scan's state (DESIGN-DETAILS 3.2.4).
	carryStateBits = 24
	// The curve's cofactor, which a generator is cleared by.
	commitCofactor = 8
)

var (
	errCommitmentForm = errors.New("not a commitment: 64 octets, two values below r, a point of the curve")
)

// The key commitment's generators: one a run of key bits, and the blind's.
type commitGenerators struct {
	runs  []twistededwards.PointAffine
	blind twistededwards.PointAffine
}

var (
	commitGeneratorsOnce sync.Once
	commitKeyGenerators  *commitGenerators
	commitScanGenerators *commitGenerators
)

// The generators, computed once: three runs cover a ChaCha20 session's 704 key bits, and one run a
// scan's 24 state bits.
func commitGeneratorSets() (*commitGenerators, *commitGenerators) {
	commitGeneratorsOnce.Do(func() {
		keyRunCount := (8*(2*tlsChachaKeyBytes+2*tlsIv13Bytes) + commitRunBits - 1) / commitRunBits
		commitKeyGenerators = &commitGenerators{blind: commitGenerator(commitTagKeyBlind, 0)}
		for i := range keyRunCount {
			commitKeyGenerators.runs = append(commitKeyGenerators.runs, commitGenerator(commitTagKey, uint32(i)))
		}
		commitScanGenerators = &commitGenerators{
			runs:  []twistededwards.PointAffine{commitGenerator(commitTagScan, 0)},
			blind: commitGenerator(commitTagScanBlind, 0),
		}
	})
	return commitKeyGenerators, commitScanGenerators
}

// generator(tag, i) of DESIGN-DETAILS 3.2.2: a point of order l whose discrete log nobody knows. Each
// counter's hash is taken as y; a y with no x on the curve is skipped; x is the smaller root; and the
// point is multiplied by the cofactor, so it lies in the order-l subgroup.
func commitGenerator(tag string, index uint32) twistededwards.PointAffine {
	curve := twistededwards.GetEdwardsCurve()
	modulus := fr.Modulus()
	var one fr.Element
	one.SetOne()
	for counter := uint32(0); ; counter += 1 {
		message := make([]byte, 0, len(commitDomain)+len(tag)+10)
		message = append(message, commitDomain...)
		message = append(message, 0)
		message = append(message, tag...)
		message = append(message, 0)
		message = binary.BigEndian.AppendUint32(message, index)
		message = binary.BigEndian.AppendUint32(message, counter)
		digest := sha256.Sum256(message)
		yInteger := new(big.Int).SetBytes(digest[:])
		yInteger.Mod(yInteger, modulus)
		var y, ySquare, numerator, denominator, xSquare, x fr.Element
		y.SetBigInt(yInteger)
		ySquare.Square(&y)
		// -x^2 + y^2 = 1 + d x^2 y^2, so x^2 = (1 - y^2) / (-1 - d y^2)
		numerator.Sub(&one, &ySquare)
		denominator.Mul(&curve.D, &ySquare)
		denominator.Add(&denominator, &one)
		denominator.Neg(&denominator)
		if denominator.IsZero() {
			continue
		}
		xSquare.Div(&numerator, &denominator)
		if xSquare.Legendre() < 0 {
			continue
		}
		if x.Sqrt(&xSquare) == nil {
			continue
		}
		var negated fr.Element
		negated.Neg(&x)
		var xInteger, negatedInteger big.Int
		x.BigInt(&xInteger)
		negated.BigInt(&negatedInteger)
		if negatedInteger.Cmp(&xInteger) < 0 {
			x = negated
		}
		point := twistededwards.NewPointAffine(x, y)
		var cleared twistededwards.PointAffine
		cleared.ScalarMultiplication(&point, big.NewInt(commitCofactor))
		if cleared.IsZero() {
			continue
		}
		return cleared
	}
}

// Com of DESIGN-DETAILS 3.2.2: the bits, least significant first, cut into runs of commitRunBits, run j
// the integer sum of bit_i 2^i on generator j, and the blind on its own generator.
func commitBits(generators *commitGenerators, bits []uint8, blind *big.Int) (twistededwards.PointAffine, error) {
	runCount := (len(bits) + commitRunBits - 1) / commitRunBits
	if len(generators.runs) < runCount {
		return twistededwards.PointAffine{}, fmt.Errorf("%d bits need %d generators", len(bits), runCount)
	}
	var sum twistededwards.PointAffine
	sum.X.SetZero()
	sum.Y.SetOne()
	for run := range runCount {
		value := new(big.Int)
		for i := min((run+1)*commitRunBits, len(bits)) - 1; run*commitRunBits <= i; i -= 1 {
			value.Lsh(value, 1)
			if bits[i] != 0 {
				value.SetBit(value, 0, 1)
			}
		}
		var term twistededwards.PointAffine
		term.ScalarMultiplication(&generators.runs[run], value)
		sum.Add(&sum, &term)
	}
	var blinded twistededwards.PointAffine
	blinded.ScalarMultiplication(&generators.blind, blind)
	sum.Add(&sum, &blinded)
	return sum, nil
}

// Octets as bits, each octet least significant first, in order.
func commitOctetBits(octetRuns ...[]byte) []uint8 {
	var bits []uint8
	for _, octets := range octetRuns {
		for _, octet := range octets {
			for i := range 8 {
				bits = append(bits, (octet>>i)&1)
			}
		}
	}
	return bits
}

// The IV the key commitment holds for a direction: 1.3's 12-octet IV as it is, and 1.2's 4-octet salt
// followed by 8 zero octets, which is the nonce's IV with the explicit part entering by the counter.
func commitIv(iv []byte) []byte {
	if len(iv) == tlsIv13Bytes {
		return iv
	}
	padded := make([]byte, tlsIv13Bytes)
	copy(padded, iv)
	return padded
}

// C = Com(G, H, ck || civ || sk || siv, rho): 448 bits under AES-128-GCM, 704 under ChaCha20.
func commitKeys(clientKey []byte, clientIv []byte, serverKey []byte, serverIv []byte, blind *big.Int) (twistededwards.PointAffine, error) {
	if len(clientKey) != len(serverKey) || len(clientKey) == 0 || len(commitIv(clientIv)) != tlsIv13Bytes || len(commitIv(serverIv)) != tlsIv13Bytes {
		return twistededwards.PointAffine{}, errors.New("a key commitment holds two keys of one length and two 12-octet IVs")
	}
	if err := checkCommitBlind(blind); err != nil {
		return twistededwards.PointAffine{}, err
	}
	keyGenerators, _ := commitGeneratorSets()
	return commitBits(keyGenerators, commitOctetBits(clientKey, commitIv(clientIv), serverKey, commitIv(serverIv)), blind)
}

// S = Com(T, U, state, sigma): a scan's 24 state bits.
func commitCarry(state uint32, blind *big.Int) (twistededwards.PointAffine, error) {
	if state>>carryStateBits != 0 {
		return twistededwards.PointAffine{}, fmt.Errorf("a scan state of more than %d bits", carryStateBits)
	}
	if err := checkCommitBlind(blind); err != nil {
		return twistededwards.PointAffine{}, err
	}
	bits := make([]uint8, carryStateBits)
	for i := range bits {
		bits[i] = uint8((state >> i) & 1)
	}
	_, scanGenerators := commitGeneratorSets()
	return commitBits(scanGenerators, bits, blind)
}

// A blind is a value below l.
func checkCommitBlind(blind *big.Int) error {
	curve := twistededwards.GetEdwardsCurve()
	if blind == nil || blind.Sign() < 0 || curve.Order.Cmp(blind) <= 0 {
		return errors.New("a blind is a value below the subgroup's order")
	}
	return nil
}

// A fresh blind, uniform below l, by rejection over 251 bits from crypto/rand: never derived from
// anything, and drawn once for each commitment it hides. kind names it for the privacy harness, which
// sees it here, where it is drawn.
func newCommitBlind(kind string) (*big.Int, error) {
	curve := twistededwards.GetEdwardsCurve()
	octets := make([]byte, (commitBlindBits+7)/8)
	for {
		if _, err := rand.Read(octets); err != nil {
			return nil, err
		}
		// the top octet keeps the blind's 251 bits and no more
		octets[0] &= byte(1<<(commitBlindBits-8*(len(octets)-1))) - 1
		blind := new(big.Int).SetBytes(octets)
		if blind.Cmp(&curve.Order) < 0 {
			testHookSecret(kind, octets)
			return blind, nil
		}
	}
}

// A blind's 251 bits, least significant first, as the circuit's private wires take them.
func commitBlindBitsOf(blind *big.Int) []uint8 {
	bits := make([]uint8, commitBlindBits)
	for i := range bits {
		bits[i] = uint8(blind.Bit(i))
	}
	return bits
}

// A commitment as the wire and the public inputs carry it: x || y, each 32 octets big-endian.
func encodeCommitment(point twistededwards.PointAffine) []byte {
	x := point.X.Bytes()
	y := point.Y.Bytes()
	encoded := make([]byte, 0, commitmentBytes)
	encoded = append(encoded, x[:]...)
	return append(encoded, y[:]...)
}

// The gate's form check (DESIGN-DETAILS 3.2.5 steps 4 and 11): exactly 64 octets, each coordinate
// below r, and the pair a point of the curve.
func decodeCommitment(encoded []byte) (twistededwards.PointAffine, error) {
	var point twistededwards.PointAffine
	if len(encoded) != commitmentBytes {
		return point, errCommitmentForm
	}
	if err := point.X.SetBytesCanonical(encoded[:commitCoordinateBytes]); err != nil {
		return point, errCommitmentForm
	}
	if err := point.Y.SetBytesCanonical(encoded[commitCoordinateBytes:]); err != nil {
		return point, errCommitmentForm
	}
	if !point.IsOnCurve() {
		return point, errCommitmentForm
	}
	return point, nil
}
