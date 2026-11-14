package checker

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
)

// The key commitment of DESIGN-DETAILS 3.2.2, read from that text alone and computed in math/big: the
// twisted Edwards curve -x^2 + y^2 = 1 + d x^2 y^2 over BN254's scalar field, generators found by hashing
// to y and clearing the cofactor, and C = sum m_j G_j + rho H over runs of 246 bits. Slow, and only an
// oracle's: the circuits and the prover take theirs from gnark-crypto.

// The curve's parameters, r and the generators' rules: cryptographic constants.
const (
	commitFieldDecimal  = "21888242871839275222246405745257275088548364400416034343698204186575808495617"
	commitDDecimal      = "12181644023421730124874158521699555681764249180949974110617291017600649128846"
	commitOrderDecimal  = "2736030358979909402780800718157159386076813972158567259200215660948447373041"
	commitDomain        = "urnetwork smtpproof commit v1"
	commitRunBits       = 246
	commitCoordinateLen = 32
)

func commitInteger(decimal string) *big.Int {
	value, _ := new(big.Int).SetString(decimal, 10)
	return value
}

// An affine point of the curve.
type commitPoint struct {
	x *big.Int
	y *big.Int
}

func commitIdentity() *commitPoint {
	return &commitPoint{x: big.NewInt(0), y: big.NewInt(1)}
}

func (self *commitPoint) equal(other *commitPoint) bool {
	return self.x.Cmp(other.x) == 0 && self.y.Cmp(other.y) == 0
}

// The complete law: (x1 y2 + y1 x2) / (1 + d t), (y1 y2 + x1 x2) / (1 - d t), t = x1 x2 y1 y2, all mod r.
func (self *commitPoint) add(other *commitPoint) *commitPoint {
	r := commitInteger(commitFieldDecimal)
	d := commitInteger(commitDDecimal)
	mod := func(value *big.Int) *big.Int { return value.Mod(value, r) }
	t := mod(new(big.Int).Mul(mod(new(big.Int).Mul(self.x, other.x)), mod(new(big.Int).Mul(self.y, other.y))))
	dt := mod(new(big.Int).Mul(d, t))
	xNumerator := mod(new(big.Int).Add(new(big.Int).Mul(self.x, other.y), new(big.Int).Mul(self.y, other.x)))
	yNumerator := mod(new(big.Int).Add(new(big.Int).Mul(self.y, other.y), new(big.Int).Mul(self.x, other.x)))
	xDenominator := mod(new(big.Int).Add(big.NewInt(1), dt))
	yDenominator := mod(new(big.Int).Sub(big.NewInt(1), dt))
	return &commitPoint{
		x: mod(new(big.Int).Mul(xNumerator, new(big.Int).ModInverse(xDenominator, r))),
		y: mod(new(big.Int).Mul(yNumerator, new(big.Int).ModInverse(yDenominator, r))),
	}
}

// scalar times the point, by doubling and adding from the top bit.
func (self *commitPoint) times(scalar *big.Int) *commitPoint {
	result := commitIdentity()
	for i := scalar.BitLen() - 1; 0 <= i; i -= 1 {
		result = result.add(result)
		if scalar.Bit(i) == 1 {
			result = result.add(self)
		}
	}
	return result
}

func (self *commitPoint) onCurve() bool {
	r := commitInteger(commitFieldDecimal)
	d := commitInteger(commitDDecimal)
	xx := new(big.Int).Mul(self.x, self.x)
	yy := new(big.Int).Mul(self.y, self.y)
	left := new(big.Int).Sub(yy, xx)
	right := new(big.Int).Add(big.NewInt(1), new(big.Int).Mul(d, new(big.Int).Mul(xx, yy)))
	return new(big.Int).Mod(left, r).Cmp(new(big.Int).Mod(right, r)) == 0
}

// generator(tag, i): y from SHA-256 of the domain, tag, index and counter, the smaller x of the curve at
// that y, and the point times 8; a counter with no x, or whose point clears to the identity, is skipped.
func commitGenerator(tag string, index uint32) *commitPoint {
	r := commitInteger(commitFieldDecimal)
	d := commitInteger(commitDDecimal)
	for counter := uint32(0); ; counter += 1 {
		message := []byte(commitDomain)
		message = append(message, 0)
		message = append(message, tag...)
		message = append(message, 0)
		message = binary.BigEndian.AppendUint32(message, index)
		message = binary.BigEndian.AppendUint32(message, counter)
		digest := sha256.Sum256(message)
		y := new(big.Int).Mod(new(big.Int).SetBytes(digest[:]), r)
		yy := new(big.Int).Mul(y, y)
		numerator := new(big.Int).Mod(new(big.Int).Sub(big.NewInt(1), yy), r)
		denominator := new(big.Int).Mod(new(big.Int).Sub(big.NewInt(-1), new(big.Int).Mul(d, yy)), r)
		if denominator.Sign() == 0 {
			continue
		}
		xx := new(big.Int).Mod(new(big.Int).Mul(numerator, new(big.Int).ModInverse(denominator, r)), r)
		x := new(big.Int).ModSqrt(xx, r)
		if x == nil {
			continue
		}
		if other := new(big.Int).Sub(r, x); x.Sign() != 0 && other.Cmp(x) < 0 {
			x = other
		}
		point := (&commitPoint{x: x, y: y}).times(big.NewInt(8))
		if point.equal(commitIdentity()) {
			continue
		}
		return point
	}
}

// C over a session's keys and IVs, each IV of 12 octets (a 1.2 salt then 8 zero octets).
func keyCommitment(clientKey []byte, clientIv []byte, serverKey []byte, serverIv []byte, blind *big.Int) *commitPoint {
	pad := func(iv []byte) []byte {
		padded := make([]byte, 12)
		copy(padded, iv)
		return padded
	}
	var bits []uint
	for _, octets := range [][]byte{clientKey, pad(clientIv), serverKey, pad(serverIv)} {
		for _, octet := range octets {
			for i := range 8 {
				bits = append(bits, uint(octet>>i)&1)
			}
		}
	}
	sum := commitIdentity()
	for run := 0; run*commitRunBits < len(bits); run += 1 {
		value := new(big.Int)
		for i := run * commitRunBits; i < min((run+1)*commitRunBits, len(bits)); i += 1 {
			value.SetBit(value, i-run*commitRunBits, bits[i])
		}
		sum = sum.add(commitGenerator("key", uint32(run)).times(value))
	}
	return sum.add(commitGenerator("key blind", 0).times(blind))
}

// C as the wire carries it, checked as the gate checks it: 64 octets, each coordinate below r, on the
// curve.
func parseKeyCommitment(encoded []byte) (*commitPoint, error) {
	r := commitInteger(commitFieldDecimal)
	if len(encoded) != 2*commitCoordinateLen {
		return nil, errors.New("a key commitment is 64 octets")
	}
	point := &commitPoint{x: new(big.Int).SetBytes(encoded[:commitCoordinateLen]), y: new(big.Int).SetBytes(encoded[commitCoordinateLen:])}
	if r.Cmp(point.x) <= 0 || r.Cmp(point.y) <= 0 || !point.onCurve() {
		return nil, errors.New("a key commitment is two values below r on the curve")
	}
	return point, nil
}

// Z1's opening: the keys and the blind give C. A blind not below l is no blind.
func checkKeyCommitment(witness *PartWitness, encoded []byte) error {
	want, err := parseKeyCommitment(encoded)
	if err != nil {
		return err
	}
	blind := new(big.Int).SetBytes(witness.KeyBlind)
	if commitInteger(commitOrderDecimal).Cmp(blind) <= 0 {
		return errors.New("the blind is not below l")
	}
	if len(witness.ClientKey) == 0 || len(witness.ClientKey) != len(witness.ServerKey) || 12 < len(witness.ClientIv) || 12 < len(witness.ServerIv) {
		return errors.New("the witness holds no keys of one length")
	}
	if !keyCommitment(witness.ClientKey, witness.ClientIv, witness.ServerKey, witness.ServerIv, blind).equal(want) {
		return errors.New("the keys and blind do not open C")
	}
	return nil
}

// A commitment as the wire carries it, checked as the gate checks C and a carry: 64 octets, each
// coordinate below r, on the curve.
func parseCommitment(encoded []byte) (*commitPoint, error) {
	return parseKeyCommitment(encoded)
}

// A carry over a scan's 24-bit state (DESIGN-DETAILS 3.2.2): S = state T + sigma U, with T the generator
// tagged "scan" and U "scan blind", the state one run of 24 bits.
func carryCommitment(state uint32, blind *big.Int) *commitPoint {
	return commitGenerator("scan", 0).times(new(big.Int).SetUint64(uint64(state))).add(commitGenerator("scan blind", 0).times(blind))
}

// The carry the edge holds where a scan starts: the start state, pos 2 alone, under a zero blind.
func startCarry() []byte {
	return encodeCommitment(carryCommitment(scanPosLf, new(big.Int)))
}

// A point as the wire carries it: x then y, 32 octets each, big-endian.
func encodeCommitment(point *commitPoint) []byte {
	encoded := make([]byte, 2*commitCoordinateLen)
	point.x.FillBytes(encoded[:commitCoordinateLen])
	point.y.FillBytes(encoded[commitCoordinateLen:])
	return encoded
}

// Whether a carry on the wire opens to state under a blind below l.
func checkCarry(encoded []byte, state uint32, blindOctets []byte) error {
	want, err := parseCommitment(encoded)
	if err != nil {
		return err
	}
	blind := new(big.Int).SetBytes(blindOctets)
	if commitInteger(commitOrderDecimal).Cmp(blind) <= 0 {
		return errors.New("the carry's blind is not below l")
	}
	if !carryCommitment(state, blind).equal(want) {
		return errors.New("the carry does not open to the scan's state there")
	}
	return nil
}
