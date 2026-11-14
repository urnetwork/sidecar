package smtpproof

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
)

// The commitment gadget of DESIGN-DETAILS 3.2.2: the sum Com computes, over bit wires, with no lookup,
// no gnark Commit and nothing from gnark's std/ (SPEC.md 10.1).
//
// Bits go three at a time. Window w of a run on generator G selects v 8^w G, v the window's value, as the
// multilinear form of a table of eight constants in the three bits: four products, shared by both
// coordinates. Each selected point after the first is added to the running point by the curve's complete
// law, which needs no case for the identity or for equal points: a = -1 is a square in F_r and d is not
// (TestCommitCurveIsComplete), so no denominator is ever zero. The bits must be boolean wires; the caller
// asserts that once, where they enter.

// One window's eight points, as the multilinear form's coefficients of each coordinate: the constant,
// b0, b1, b2, b0 b1, b0 b2, b1 b2 and b0 b1 b2.
type commitWindowForm struct {
	x [8]*big.Int
	y [8]*big.Int
}

// The coefficients of a window's table T[v] = v base, v = b0 + 2 b1 + 4 b2.
func newCommitWindowForm(base *twistededwards.PointAffine) *commitWindowForm {
	var table [8]twistededwards.PointAffine
	table[0].X.SetZero()
	table[0].Y.SetOne()
	for v := 1; v < 8; v += 1 {
		table[v].Add(&table[v-1], base)
	}
	coefficients := func(coordinate func(point *twistededwards.PointAffine) *fr.Element) [8]*big.Int {
		t := func(v int) fr.Element { return *coordinate(&table[v]) }
		combine := func(plus []int, minus []int) *big.Int {
			var sum fr.Element
			for _, v := range plus {
				value := t(v)
				sum.Add(&sum, &value)
			}
			for _, v := range minus {
				value := t(v)
				sum.Sub(&sum, &value)
			}
			return sum.BigInt(new(big.Int))
		}
		return [8]*big.Int{
			combine([]int{0}, nil),
			combine([]int{1}, []int{0}),
			combine([]int{2}, []int{0}),
			combine([]int{4}, []int{0}),
			combine([]int{3, 0}, []int{2, 1}),
			combine([]int{5, 0}, []int{4, 1}),
			combine([]int{6, 0}, []int{4, 2}),
			combine([]int{7, 4, 2, 1}, []int{6, 5, 3, 0}),
		}
	}
	return &commitWindowForm{
		x: coefficients(func(point *twistededwards.PointAffine) *fr.Element { return &point.X }),
		y: coefficients(func(point *twistededwards.PointAffine) *fr.Element { return &point.Y }),
	}
}

// A point of the circuit: two wires.
type circuitPoint struct {
	x frontend.Variable
	y frontend.Variable
}

// The window's point at its bits, nil standing for a bit fixed at 0 past a run's end.
func (self *commitWindowForm) selectAt(api frontend.API, bits [3]frontend.Variable) *circuitPoint {
	monomials := [8]frontend.Variable{1, bits[0], bits[1], bits[2]}
	product := func(a frontend.Variable, b frontend.Variable) frontend.Variable {
		if a == nil || b == nil {
			return nil
		}
		return api.Mul(a, b)
	}
	monomials[4] = product(bits[0], bits[1])
	monomials[5] = product(bits[0], bits[2])
	monomials[6] = product(bits[1], bits[2])
	monomials[7] = product(monomials[4], bits[2])
	form := func(coefficients [8]*big.Int) frontend.Variable {
		sum := frontend.Variable(coefficients[0])
		for i := 1; i < len(monomials); i += 1 {
			if monomials[i] != nil && coefficients[i].Sign() != 0 {
				sum = api.Add(sum, api.Mul(coefficients[i], monomials[i]))
			}
		}
		return sum
	}
	return &circuitPoint{x: form(self.x), y: form(self.y)}
}

// The complete law with a = -1: (x1 y2 + y1 x2) / (1 + d t) and (y1 y2 + x1 x2) / (1 - d t), t = x1 x2 y1 y2.
// Six constraints. Both points are on the curve, so neither denominator is zero and each quotient is the
// one value its single constraint q (1 ± d t) = n allows: the unchecked division needs no inverse check.
func circuitPointAdd(api frontend.API, d *big.Int, a *circuitPoint, b *circuitPoint) *circuitPoint {
	xx := api.Mul(a.x, b.x)
	yy := api.Mul(a.y, b.y)
	cross := api.Sub(api.Mul(api.Add(a.x, a.y), api.Add(b.x, b.y)), xx, yy)
	dt := api.Mul(d, api.Mul(xx, yy))
	return &circuitPoint{
		x: api.DivUnchecked(cross, api.Add(1, dt)),
		y: api.DivUnchecked(api.Add(yy, xx), api.Sub(1, dt)),
	}
}

// The windows of one run of bits on its generator, in order.
func commitRunWindows(generator twistededwards.PointAffine, bitCount int) []*commitWindowForm {
	var windows []*commitWindowForm
	base := generator
	for offset := 0; offset < bitCount; offset += 3 {
		windows = append(windows, newCommitWindowForm(&base))
		var next twistededwards.PointAffine
		next.ScalarMultiplication(&base, big.NewInt(8))
		base = next
	}
	return windows
}

// Com over bit wires: the runs of bits on generators' runs, and the blind's bits on the blind's
// generator. bits and blindBits must be boolean wires.
func circuitCommit(api frontend.API, generators *commitGenerators, bits []frontend.Variable, blindBits []frontend.Variable) *circuitPoint {
	curve := twistededwards.GetEdwardsCurve()
	d := curve.D.BigInt(new(big.Int))
	var running *circuitPoint
	add := func(generator twistededwards.PointAffine, runBits []frontend.Variable) {
		for i, window := range commitRunWindows(generator, len(runBits)) {
			var windowBits [3]frontend.Variable
			for j := range windowBits {
				if 3*i+j < len(runBits) {
					windowBits[j] = runBits[3*i+j]
				}
			}
			selected := window.selectAt(api, windowBits)
			if running == nil {
				running = selected
			} else {
				running = circuitPointAdd(api, d, running, selected)
			}
		}
	}
	for run := 0; run*commitRunBits < len(bits); run += 1 {
		add(generators.runs[run], bits[run*commitRunBits:min((run+1)*commitRunBits, len(bits))])
	}
	add(generators.blind, blindBits)
	return running
}

// Asserts the commitment of bits and blindBits is the public point.
func assertCommitment(api frontend.API, generators *commitGenerators, bits []frontend.Variable, blindBits []frontend.Variable, public []frontend.Variable) {
	point := circuitCommit(api, generators, bits, blindBits)
	api.AssertIsEqual(point.x, public[0])
	api.AssertIsEqual(point.y, public[1])
}

// The bits of octets, each least significant first, in order: what a commitment of circuit octets takes.
func commitCircuitBits(octetRuns ...[]circuitByte) []frontend.Variable {
	var bits []frontend.Variable
	for _, octets := range octetRuns {
		for _, octet := range octets {
			bits = append(bits, octet[:]...)
		}
	}
	return bits
}

// A commitment's public wires from its encoding: x then y.
func assignCommitment(encoded []byte) ([]frontend.Variable, error) {
	point, err := decodeCommitment(encoded)
	if err != nil {
		return nil, err
	}
	return []frontend.Variable{point.X.BigInt(new(big.Int)), point.Y.BigInt(new(big.Int))}, nil
}
