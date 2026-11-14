package smtpproof

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// The state a scan carries from one record to the next (DESIGN-DETAILS 3.2.4). A part that opens a
// header or body record publishes the state it leaves as the carry, a perfectly hiding commitment
// (3.2.2), and the gate hands that commitment to the next part as its CarryIn, which the next part's
// circuit opens to the state it starts from. The bit positions are identifiers, not settings:
//
//	0-1    pos      0 inside a line; 1 the last octet was CR; 2 it was LF, so a line starts next;
//	                3 it was "." at a line's start (body only)
//	2      name     a field name is unfinished: a line that is no continuation has not reached its colon
//	3-9    run      octets so far of the line in progress, when it began in this record and is no
//	                continuation: 1 to 126, or 127 for more; 127 for a line that began in an earlier record;
//	                0 after a line's end and inside a continuation
//	10-15  prefix   one bit for each of scanLiterals: run is under that literal's length and the line so
//	                far is its first run octets (names without case, the signature's prefix exactly)
//	16     single   the line that ended at the last octet is one of rule 4's or rule 6's single fields
//	17-23  zero
type scanState uint32

const (
	scanPosShift    = 0
	scanPosBits     = 2
	scanNameShift   = 2
	scanRunShift    = 3
	scanRunBits     = 7
	scanPrefixShift = 10
	scanSingleShift = 16
	// The bits a state uses. The rest of carryStateBits are zero.
	scanUsedBits = 17

	scanPosLine = 0
	scanPosCr   = 1
	scanPosLf   = 2
	scanPosDot  = 3
	// run's value for a line longer than it counts, or one that began in an earlier record.
	scanRunMore = 1<<scanRunBits - 1
)

// Before a header block's first octet and before a body's: pos 2 and nothing else.
const scanStart scanState = scanPosLf << scanPosShift

func (self scanState) pos() uint32 {
	return uint32(self) >> scanPosShift & (1<<scanPosBits - 1)
}

func (self scanState) name() bool {
	return uint32(self)>>scanNameShift&1 == 1
}

func (self scanState) run() int {
	return int(uint32(self) >> scanRunShift & (1<<scanRunBits - 1))
}

func (self scanState) prefix(literal int) bool {
	return uint32(self)>>(scanPrefixShift+literal)&1 == 1
}

func (self scanState) single() bool {
	return uint32(self)>>scanSingleShift&1 == 1
}

// A state from its fields. run is clamped to its 7 bits by the caller.
func newScanState(pos uint32, name bool, run int, prefix [scanLiteralCount]bool, single bool) scanState {
	state := pos << scanPosShift
	if name {
		state |= 1 << scanNameShift
	}
	state |= uint32(run) << scanRunShift
	for i, set := range prefix {
		if set {
			state |= 1 << (scanPrefixShift + i)
		}
	}
	if single {
		state |= 1 << scanSingleShift
	}
	return scanState(state)
}

// A literal the header scan finds at a line's start: rule 4's and 6's single fields by name and colon,
// and rule 5's fixed signature by its prefix (SPEC.md Z5). Records are at least HeaderRecordMinByteCount
// octets, longer than any of these, so one can straddle a record boundary and never two.
type scanLiteral struct {
	octets string
	// A field name and its colon, compared without case. The signature's prefix compares exactly.
	folded bool
}

// The literals, in the order of the state's prefix bits. These are SPEC.md's literals, identifiers.
const (
	scanLiteralFrom = iota
	scanLiteralMessageId
	scanLiteralXUrRef
	scanLiteralFeedbackId
	// Single only on a BULK message (rule 6).
	scanLiteralUnsubscribe
	scanLiteralDkim
	scanLiteralCount
)

var scanLiterals = [scanLiteralCount]scanLiteral{
	{octets: "from:", folded: true},
	{octets: "message-id:", folded: true},
	{octets: "x-ur-ref:", folded: true},
	{octets: "feedback-id:", folded: true},
	{octets: "list-unsubscribe-post:", folded: true},
	{octets: literalDkimPrefix},
}

// Whether a literal is one of the single fields: rule 4's always, rule 6's on a BULK message.
func scanLiteralSingle(literal int, bulk bool) bool {
	switch literal {
	case scanLiteralFrom, scanLiteralMessageId, scanLiteralXUrRef, scanLiteralFeedbackId:
		return true
	case scanLiteralUnsubscribe:
		return bulk
	default:
		return false
	}
}

// Whether a literal counts in this message: every one but the one-click field, which counts only on a
// BULK message, where it is single.
func scanLiteralCounts(literal int, bulk bool) bool {
	return literal != scanLiteralUnsubscribe || bulk
}

// The carry wherever a scan starts: Com(T, U, start, 0). The start state is public, so its commitment
// needs no blind (DESIGN-DETAILS 3.2.4): the gate supplies it before a body's first record, and after
// the header block's last.
func scanStartCarry() []byte {
	commitment, err := commitCarry(uint32(scanStart), new(big.Int))
	if err != nil {
		// a constant state of 24 bits and the zero blind are always in range
		panic(err)
	}
	return encodeCommitment(commitment)
}

// A scan state as wires, each bit boolean or a constant.
type circuitScanState struct {
	pos    [scanPosBits]frontend.Variable
	name   frontend.Variable
	run    [scanRunBits]frontend.Variable
	prefix [scanLiteralCount]frontend.Variable
	single frontend.Variable
}

// A constant state.
func newCircuitScanStateConstant(state scanState) *circuitScanState {
	bit := func(shift int) frontend.Variable {
		return int((uint32(state) >> shift) & 1)
	}
	result := &circuitScanState{name: bit(scanNameShift), single: bit(scanSingleShift)}
	for i := range result.pos {
		result.pos[i] = bit(scanPosShift + i)
	}
	for i := range result.run {
		result.run[i] = bit(scanRunShift + i)
	}
	for i := range result.prefix {
		result.prefix[i] = bit(scanPrefixShift + i)
	}
	return result
}

// A state from private wires, scanUsedBits of them in the state's order, each asserted boolean here.
func newCircuitScanStateWires(api frontend.API, wires []frontend.Variable) *circuitScanState {
	for _, wire := range wires {
		api.AssertIsBoolean(wire)
	}
	result := &circuitScanState{name: wires[scanNameShift], single: wires[scanSingleShift]}
	copy(result.pos[:], wires[scanPosShift:scanPosShift+scanPosBits])
	copy(result.run[:], wires[scanRunShift:scanRunShift+scanRunBits])
	copy(result.prefix[:], wires[scanPrefixShift:scanPrefixShift+scanLiteralCount])
	return result
}

// A state whose pos alone is private wires, each asserted boolean here: what a body record starts from,
// since B3 leaves every other bit zero.
func newCircuitScanStatePos(api frontend.API, wires []frontend.Variable) *circuitScanState {
	result := newCircuitScanStateConstant(0)
	for i := range result.pos {
		api.AssertIsBoolean(wires[i])
		result.pos[i] = wires[i]
	}
	return result
}

// The state's carryStateBits bits, least significant first, the unused ones constant zero.
func (self *circuitScanState) bits() []frontend.Variable {
	bits := make([]frontend.Variable, carryStateBits)
	for i := range bits {
		bits[i] = 0
	}
	copy(bits[scanPosShift:], self.pos[:])
	bits[scanNameShift] = self.name
	copy(bits[scanRunShift:], self.run[:])
	copy(bits[scanPrefixShift:], self.prefix[:])
	bits[scanSingleShift] = self.single
	return bits
}

// 1 when pos holds value, from its two bits.
func (self *circuitScanState) posIs(api frontend.API, value int) frontend.Variable {
	low := self.pos[0]
	high := self.pos[1]
	if value&1 == 0 {
		low = api.Sub(1, low)
	}
	if value&2 == 0 {
		high = api.Sub(1, high)
	}
	return api.Mul(low, high)
}

// run as one value.
func (self *circuitScanState) runValue(api frontend.API) frontend.Variable {
	terms := make([]frontend.Variable, 0, scanRunBits)
	for i, bit := range self.run {
		terms = append(terms, api.Mul(bit, 1<<i))
	}
	return api.Add(terms[0], terms[1], terms[2:]...)
}

// Asserts Com(T, U, state, blind) is the public pair (DESIGN-DETAILS 3.2.2). The blind's bits must be
// boolean wires; the caller asserts that where they enter.
func assertCarry(api frontend.API, state *circuitScanState, blind []frontend.Variable, public []frontend.Variable) {
	_, scanGenerators := commitGeneratorSets()
	assertCommitment(api, scanGenerators, state.bits(), blind, public)
}

// A blind's private wires, each asserted boolean.
func privateBlindBits(api frontend.API, bits []frontend.Variable) []frontend.Variable {
	for _, bit := range bits {
		api.AssertIsBoolean(bit)
	}
	return bits
}

// Asserts 0 <= value < bound, for a value its caller knows is small: value and bound - 1 - value each
// fit bound's bit length.
func assertBelow(api frontend.API, value frontend.Variable, bound int) {
	bitCount := big.NewInt(int64(bound)).BitLen()
	bitsOf(api, value, bitCount)
	bitsOf(api, api.Sub(bound-1, value), bitCount)
}
