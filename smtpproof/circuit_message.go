package smtpproof

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// Z5 and Z6 in the circuit, a record at a time (DESIGN-DETAILS 3.2.4): the header block's records, the
// first in the msg shape and each later one in a hdr shape, and DATA's body records, one a body shape.
// What a scan must remember across a record boundary arrives as the state the gate's carry opens to and
// leaves as the state the part's own carry commits to (circuit_scan.go).
//
// The header block's offsets are private, so a field cannot be found by a public template. Every
// position is examined instead: a literal is matched by a fingerprint of the octets from there, which is
// what makes "exactly once" a sum, and a matching line's whole value is then read at that one position
// and compared with the public literal. Octets past the record's end read as 0 everywhere, so nothing
// matched or read there can be a literal, all of whose octets are nonzero.
//
// Fingerprints are linear in the octets and fit a field element, so comparing one costs two constraints
// however long it is. Reading a value costs one product per octet per 31-octet word.

const (
	// Octets a fingerprint or an extracted word holds: the most below the field's 254 bits.
	wordBytes = 31

	octetTab   = 9
	octetLf    = 10
	octetCr    = 13
	octetSp    = 32
	octetColon = 58
	octetLt    = 60
	octetDot   = 46
	octetDel   = 127
)

// A public literal and which of its octets count.
type literalCheck struct {
	Expected []frontend.Variable `gnark:",public"`
	Used     []frontend.Variable `gnark:",public"`
}

func newLiteralCheck(capacity int) *literalCheck {
	return &literalCheck{Expected: make([]frontend.Variable, capacity), Used: make([]frontend.Variable, capacity)}
}

func zeroLiteralCheck(check *literalCheck) {
	for i := range check.Expected {
		check.Expected[i] = 0
		check.Used[i] = 0
	}
}

func assignLiteralCheck(check *literalCheck, literal []byte) error {
	if len(check.Expected) < len(literal) {
		return errors.New("a literal is longer than the shape's capacity")
	}
	for i, octet := range literal {
		check.Expected[i] = octet
		check.Used[i] = 1
	}
	return nil
}

// One header record and what the edge knows of its positions: the msg shape's head, the header block's
// first record, or a hdr shape's rest, a later one.
type headerRecordScan struct {
	Blocks []*poolBlock
	// A content octet of the record.
	Active []frontend.Variable `gnark:",public"`
	// A content octet before the header block's final CRLF, where a line must be a field or a
	// continuation: every content octet but the last record's final two (H13).
	Field []frontend.Variable `gnark:",public"`

	// The first record's alone: rule 4's and 5's literal forms, each read where its field begins (H10).
	MessageId *literalCheck
	XUrRef    *literalCheck
	Feedback  *literalCheck
	Address   *literalCheck
	DkimTags  *literalCheck
	// 1 if BULK is set: the first record holds the one-click field once (Z5.6), and a later one may not.
	Bulk frontend.Variable `gnark:",public"`

	// The first record's alone. One-hot, private: where From's < and @ are.
	FromAngle []frontend.Variable
	FromAt    []frontend.Variable
}

func newHeaderRecordScan(shape *partShape, blocks int, first bool) *headerRecordScan {
	size := blocks * shape.blockBytes()
	scan := &headerRecordScan{
		Active: make([]frontend.Variable, size),
		Field:  make([]frontend.Variable, size),
	}
	if first {
		scan.MessageId = newLiteralCheck(shape.literalLineBytes)
		scan.XUrRef = newLiteralCheck(shape.literalLineBytes)
		scan.Feedback = newLiteralCheck(shape.literalLineBytes)
		scan.Address = newLiteralCheck(shape.literalAddressBytes)
		scan.DkimTags = newLiteralCheck(shape.literalTagBytes)
		scan.FromAngle = make([]frontend.Variable, size)
		scan.FromAt = make([]frontend.Variable, size)
	}
	for range blocks {
		scan.Blocks = append(scan.Blocks, newPoolBlock(shape.blockBytes(), false))
	}
	return scan
}

// Whether a scan is the header block's first record's, which carries the literal forms.
func (self *headerRecordScan) first() bool {
	return self.MessageId != nil
}

func zeroPoolBlock(block *poolBlock) {
	block.Counter = 0
	for i := range block.Cipher {
		block.Cipher[i] = 0
		block.Literal[i] = 0
		block.IsLiteral[i] = 0
	}
	for i := range block.IsLocal {
		block.IsLocal[i] = 0
	}
}

func zeroHeaderRecordScan(scan *headerRecordScan) {
	for _, block := range scan.Blocks {
		zeroPoolBlock(block)
	}
	for i := range scan.Active {
		scan.Active[i] = 0
		scan.Field[i] = 0
	}
	for i := range scan.FromAngle {
		scan.FromAngle[i] = 0
		scan.FromAt[i] = 0
	}
	for _, check := range []*literalCheck{scan.MessageId, scan.XUrRef, scan.Feedback, scan.Address, scan.DkimTags} {
		if check != nil {
			zeroLiteralCheck(check)
		}
	}
	scan.Bulk = 0
}

// The fingerprint of a constant, little-endian.
func constantFingerprint(octets []byte) *big.Int {
	fingerprint := new(big.Int)
	for i := len(octets) - 1; 0 <= i; i -= 1 {
		fingerprint.Lsh(fingerprint, 8)
		fingerprint.Add(fingerprint, big.NewInt(int64(octets[i])))
	}
	return fingerprint
}

// The fingerprint of count wires from start, as a linear combination. Past the end counts as zero.
func wireFingerprint(api frontend.API, wires []frontend.Variable, start int, count int) frontend.Variable {
	terms := []frontend.Variable{}
	for j := range count {
		if start+j < len(wires) {
			terms = append(terms, api.Mul(wires[start+j], new(big.Int).Lsh(big.NewInt(1), uint(8*j))))
		}
	}
	return sumWires(api, terms)
}

// The sum of wires, 0 for none.
func sumWires(api frontend.API, terms []frontend.Variable) frontend.Variable {
	switch len(terms) {
	case 0:
		return 0
	case 1:
		return terms[0]
	}
	return api.Add(terms[0], terms[1], terms[2:]...)
}

// The product of a running match and one more, which skips a constant 1.
func mulMatch(api frontend.API, match frontend.Variable, more frontend.Variable) frontend.Variable {
	if _, ok := api.Compiler().ConstantValue(match); ok {
		return more
	}
	return api.Mul(match, more)
}

// Whether wires from start equal a constant of any length, as 0 or 1.
func matchesConstant(api frontend.API, wires []frontend.Variable, start int, constant []byte) frontend.Variable {
	match := frontend.Variable(1)
	for offset := 0; offset < len(constant); offset += wordBytes {
		end := min(offset+wordBytes, len(constant))
		fingerprint := wireFingerprint(api, wires, start+offset, end-offset)
		match = mulMatch(api, match, api.IsZero(api.Sub(fingerprint, constantFingerprint(constant[offset:end]))))
	}
	return match
}

// Whether the active octets from start equal a literal's first octets, as many as the record still
// holds, up to the literal's length. masked is 0 past the record, and so is the literal's side there:
// a record that ends inside the literal matches its beginning.
func matchesLiteralPrefix(api frontend.API, masked []frontend.Variable, active []frontend.Variable, start int, literal string) frontend.Variable {
	match := frontend.Variable(1)
	for offset := 0; offset < len(literal); offset += wordBytes {
		end := min(offset+wordBytes, len(literal))
		terms := []frontend.Variable{}
		for j := offset; j < end && start+j < len(masked); j += 1 {
			weight := new(big.Int).Lsh(big.NewInt(1), uint(8*(j-offset)))
			// the octet as the record holds it, less the literal's where the record holds an octet
			terms = append(terms, api.Mul(api.Sub(masked[start+j], api.Mul(active[start+j], int(literal[j]))), weight))
		}
		if len(terms) == 0 {
			break
		}
		match = mulMatch(api, match, api.IsZero(sumWires(api, terms)))
	}
	return match
}

// Reads len(check.Expected) octets at the one position hits marks, plus skip, and compares them with
// the literal. hits must be one-hot, which its caller establishes.
func checkLiteralAt(api frontend.API, values []frontend.Variable, hits []frontend.Variable, skip int, check *literalCheck) {
	for offset := 0; offset < len(check.Expected); offset += wordBytes {
		count := min(wordBytes, len(check.Expected)-offset)
		terms := []frontend.Variable{}
		for i := range hits {
			if start := i + skip + offset; start < len(values) {
				terms = append(terms, api.Mul(hits[i], wireFingerprint(api, values, start, count)))
			}
		}
		bits := bitsOf(api, sumWires(api, terms), 8*count)
		for j := range count {
			var octet circuitByte
			copy(octet[:], bits[8*j:8*j+8])
			api.AssertIsEqual(api.Mul(check.Used[offset+j], api.Sub(byteValue(api, octet), check.Expected[offset+j])), 0)
		}
	}
}

// A or b, of boolean wires.
func orWires(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	return api.Sub(api.Add(a, b), api.Mul(a, b))
}

// The octets of a record's blocks, each template position checked (Z3, and H13's final CRLF CRLF).
func openTemplatedBlocks(api frontend.API, stream *circuitKeystream, blocks []*poolBlock) []*openOctet {
	var octets []*openOctet
	for _, block := range blocks {
		for i, octet := range openBlock(api, stream, block.Counter, block.Cipher) {
			api.AssertIsEqual(api.Mul(block.IsLiteral[i], api.Sub(octet.value, block.Literal[i])), 0)
			octets = append(octets, octet)
		}
	}
	return octets
}

// Z5 over one header record, DESIGN-DETAILS 3.2.4's H1 to H13, from the state in, returning the state
// it leaves. The first record (scan.first()) starts from the start state and holds each single field
// and the fixed signature's prefix exactly once, every such line whole inside it (H8 to H11); a later
// record starts from the gate's carry and holds none of them, whole or crossing in from the record
// before (H12). H13 is in the template: the last record's final CRLF CRLF is literal, and Field is 0
// on its last two octets.
func checkHeaderRecordCircuit(api frontend.API, shape *partShape, stream *circuitKeystream, scan *headerRecordScan, in *circuitScanState) *circuitScanState {
	octets := openTemplatedBlocks(api, stream, scan.Blocks)
	size := len(octets)
	active := scan.Active
	// the record's last content octet: the edge's Active is a run from position 0
	lastAt := func(i int) frontend.Variable {
		if i+1 < size {
			return api.Sub(active[i], active[i+1])
		}
		return active[i]
	}
	values := make([]frontend.Variable, size)
	masked := make([]frontend.Variable, size)
	foldedMasked := make([]frontend.Variable, size)
	isCr := make([]frontend.Variable, size)
	isLf := make([]frontend.Variable, size)
	isSp := make([]frontend.Variable, size)
	isWsp := make([]frontend.Variable, size)
	isColon := make([]frontend.Variable, size)
	isDot := make([]frontend.Variable, size)
	crActive := make([]frontend.Variable, size)
	lfActive := make([]frontend.Variable, size)
	wspActive := make([]frontend.Variable, size)
	for i, octet := range octets {
		value := octet.value
		values[i] = value
		masked[i] = api.Mul(active[i], value)
		// bit 5 forced compares letters without case; rule 1 and H4 keep every other octet a name can
		// hold to itself
		foldedMasked[i] = api.Mul(active[i], api.Add(value, api.Mul(api.Sub(1, octet.bits[5]), 32)))
		isCr[i] = api.IsZero(api.Sub(value, octetCr))
		isLf[i] = api.IsZero(api.Sub(value, octetLf))
		isSp[i] = api.IsZero(api.Sub(value, octetSp))
		isTab := api.IsZero(api.Sub(value, octetTab))
		isWsp[i] = api.Add(isSp[i], isTab)
		isColon[i] = api.IsZero(api.Sub(value, octetColon))
		isDot[i] = api.IsZero(api.Sub(value, octetDot))
		isDel := api.IsZero(api.Sub(value, octetDel))
		crActive[i] = api.Mul(active[i], isCr[i])
		lfActive[i] = api.Mul(active[i], isLf[i])
		wspActive[i] = api.Mul(active[i], isWsp[i])

		// H1: HTAB, SP through ~, CR or LF
		bits := octet.bits
		printable := api.Mul(api.Sub(1, bits[7]), api.Sub(api.Add(bits[5], bits[6]), api.Mul(bits[5], bits[6])))
		allowed := api.Add(api.Sub(printable, isDel), isTab, isCr[i], isLf[i])
		api.AssertIsEqual(api.Mul(active[i], api.Sub(1, allowed)), 0)
	}

	// H2: LF exactly after CR, across the boundary by in.pos
	inPosCr := in.posIs(api, scanPosCr)
	inPosLf := in.posIs(api, scanPosLf)
	for i := range size {
		previousCr := inPosCr
		if 0 < i {
			previousCr = isCr[i-1]
		}
		api.AssertIsEqual(api.Mul(active[i], api.Sub(isLf[i], previousCr)), 0)
	}
	// H6: after a single field's line, no continuation
	api.AssertIsEqual(api.Mul(in.single, wspActive[0]), 0)

	// H3 and H4: line and name starts, and a name's octets up to its colon
	lineStart := make([]frontend.Variable, size)
	nameStart := make([]frontend.Variable, size)
	inName := make([]frontend.Variable, size+1)
	inName[0] = in.name
	for i := range size {
		previousLf := inPosLf
		if 0 < i {
			previousLf = lfActive[i-1]
		}
		lineStart[i] = api.Mul(scan.Field[i], previousLf)
		api.AssertIsEqual(api.Mul(lineStart[i], isCr[i]), 0)
		nameStart[i] = api.Mul(lineStart[i], api.Sub(1, isWsp[i]))
		// nor does a name start with a dot, which an MX reading DATA would delete (RFC 5321 §4.5.2),
		// leaving a field no fingerprint here saw
		api.AssertIsEqual(api.Mul(nameStart[i], api.Add(isColon[i], isDot[i])), 0)
		naming := api.Add(inName[i], nameStart[i])
		api.AssertIsEqual(api.Mul(naming, api.Add(wspActive[i], crActive[i])), 0)
		inName[i+1] = api.Mul(naming, api.Sub(1, isColon[i]))
	}

	// H5: each literal at each name start, whole inside the record (full) or running off its end
	// (partial, which only the record's last line can be)
	var full, partial [scanLiteralCount][]frontend.Variable
	for literal, entry := range scanLiterals {
		source := masked
		if entry.folded {
			source = foldedMasked
		}
		full[literal] = make([]frontend.Variable, size)
		partial[literal] = make([]frontend.Variable, size)
		for i := range size {
			started := api.Mul(nameStart[i], matchesLiteralPrefix(api, source, active, i, entry.octets))
			whole := frontend.Variable(0)
			if end := i + len(entry.octets) - 1; end < size {
				whole = api.Mul(started, active[end])
			}
			full[literal][i] = whole
			partial[literal][i] = api.Sub(started, whole)
		}
	}

	out := &circuitScanState{single: 0}
	if scan.first() {
		out.single = checkFirstHeaderRecord(api, shape, scan, octets, masked, isSp, lfActive, wspActive, &full, lastAt)
	} else {
		checkLaterHeaderRecord(api, scan, masked, foldedMasked, in, &full)
	}

	// H7: the state after the record's last octet
	posTerms := make([]frontend.Variable, 0, size)
	nameTerms := make([]frontend.Variable, 0, size)
	for i := range size {
		last := lastAt(i)
		posTerms = append(posTerms, api.Mul(last, api.Add(isCr[i], api.Mul(isLf[i], 2))))
		nameTerms = append(nameTerms, api.Mul(last, inName[i+1]))
	}
	posBits := bitsOf(api, sumWires(api, posTerms), scanPosBits)
	copy(out.pos[:], posBits)
	out.name = sumWires(api, nameTerms)

	// run: the octets from the last line start to the end, when that line is no continuation
	laterLineStart := make([]frontend.Variable, size)
	laterLineStart[size-1] = 0
	for i := size - 2; 0 <= i; i -= 1 {
		laterLineStart[i] = orWires(api, laterLineStart[i+1], lineStart[i+1])
	}
	anyLineStart := orWires(api, laterLineStart[0], lineStart[0])
	runTerms := make([]frontend.Variable, 0, size)
	for i := range size {
		lastNameStart := api.Mul(nameStart[i], api.Sub(1, laterLineStart[i]))
		rest := sumWires(api, active[i:])
		runTerms = append(runTerms, api.Mul(lastNameStart, rest))
	}
	lineRun := sumWires(api, runTerms)
	lineRunBits := bitsOf(api, lineRun, max(scanRunBits+1, big.NewInt(int64(size)).BitLen()))
	more := frontend.Variable(0)
	for _, bit := range lineRunBits[scanRunBits:] {
		more = orWires(api, more, bit)
	}
	low := sumWires(api, func() []frontend.Variable {
		terms := make([]frontend.Variable, 0, scanRunBits)
		for i, bit := range lineRunBits[:scanRunBits] {
			terms = append(terms, api.Mul(bit, 1<<i))
		}
		return terms
	}())
	capped := api.Add(api.Mul(more, scanRunMore), api.Mul(api.Sub(1, more), low))
	// a line that began in an earlier record and is no continuation counts as more
	carried := api.Mul(api.Sub(1, api.IsZero(in.runValue(api))), scanRunMore)
	run := api.Mul(api.Sub(1, out.pos[1]), api.Add(api.Mul(anyLineStart, capped), api.Mul(api.Sub(1, anyLineStart), carried)))
	copy(out.run[:], bitsOf(api, run, scanRunBits))

	// prefix: the last line, a name start, is a literal's beginning running off the record's end
	for literal := range scanLiterals {
		out.prefix[literal] = sumWires(api, partial[literal])
	}
	return out
}

// H8 to H11 over the header block's first record, which the msg shape holds: the single fields, the
// fixed signature's prefix and their literal forms (SPEC.md Z5.4 to Z5.6), every such line whole inside
// the record. Returns out.single: whether a single field's line ends at the record's last octet.
func checkFirstHeaderRecord(api frontend.API, shape *partShape, scan *headerRecordScan, octets []*openOctet, masked []frontend.Variable, isSp []frontend.Variable, lfActive []frontend.Variable, wspActive []frontend.Variable, full *[scanLiteralCount][]frontend.Variable, lastAt func(int) frontend.Variable) frontend.Variable {
	size := len(octets)
	// H8: the block does not start with a continuation
	api.AssertIsEqual(wspActive[0], 0)

	// the one-click field counts only on a BULK message, where it is single
	unsubscribeHits := make([]frontend.Variable, size)
	for i := range size {
		unsubscribeHits[i] = api.Mul(scan.Bulk, full[scanLiteralUnsubscribe][i])
	}
	// H9: each single field and the signature's prefix begins exactly one line of this record
	for literal := range scanLiterals {
		hits := full[literal]
		if literal == scanLiteralUnsubscribe {
			api.AssertIsEqual(sumWires(api, unsubscribeHits), scan.Bulk)
			continue
		}
		api.AssertIsEqual(sumWires(api, hits), 1)
	}

	// H10: each literal form read at its one position; past the record's end it reads 0 and fails
	checkLiteralAt(api, masked, full[scanLiteralMessageId], 0, scan.MessageId)
	checkLiteralAt(api, masked, full[scanLiteralXUrRef], 0, scan.XUrRef)
	checkLiteralAt(api, masked, full[scanLiteralFeedbackId], 0, scan.Feedback)
	checkLiteralAt(api, masked, full[scanLiteralDkim], len(literalDkimPrefix), scan.DkimTags)
	// rule 6: the one-click line is the literal's exact octets, read like the others but against a
	// constant, as a whole word at a time
	unsubscribeLine := []byte(literalUnsubscribePost + literalCrlf)
	for offset := 0; offset < len(unsubscribeLine); offset += wordBytes {
		count := min(wordBytes, len(unsubscribeLine)-offset)
		terms := []frontend.Variable{}
		for i := range size {
			if offset+i < size {
				terms = append(terms, api.Mul(unsubscribeHits[i], wireFingerprint(api, masked, i+offset, count)))
			}
		}
		api.AssertIsEqual(sumWires(api, terms), api.Mul(scan.Bulk, constantFingerprint(unsubscribeLine[offset:offset+count])))
	}

	// H11: no single field's line is continued inside the record, and whether one ends at its last octet
	inField := frontend.Variable(0)
	singleTerms := make([]frontend.Variable, 0, size)
	for i := range size {
		singleField := api.Add(inField, full[scanLiteralFrom][i], full[scanLiteralMessageId][i], full[scanLiteralXUrRef][i], full[scanLiteralFeedbackId][i], unsubscribeHits[i])
		ending := api.Mul(singleField, lfActive[i])
		if i+1 < size {
			api.AssertIsEqual(api.Mul(ending, wspActive[i+1]), 0)
		}
		singleTerms = append(singleTerms, api.Mul(lastAt(i), ending))
		inField = api.Sub(singleField, ending)
		if i%shape.pinInterval == 0 {
			inField = pinWire(api, inField)
		}
	}

	// rule 4's From: "From: ", phrase, <, local, then the literal address, all inside the record
	fromHits := full[scanLiteralFrom]
	inLocal := make([]frontend.Variable, size)
	for i, octet := range octets {
		inLocal[i] = localSetMember(api, octet)
	}
	for i := range size {
		api.AssertIsBoolean(scan.FromAngle[i])
		api.AssertIsBoolean(scan.FromAt[i])
	}
	api.AssertIsEqual(sumWires(api, scan.FromAngle), 1)
	api.AssertIsEqual(sumWires(api, scan.FromAt), 1)
	checkLiteralAt(api, masked, scan.FromAt, 0, scan.Address)
	inPhrase := frontend.Variable(0)
	inAddress := frontend.Variable(0)
	localBytes := frontend.Variable(0)
	prefixLength := len(literalFromPrefix)
	for i := range size {
		phraseStart := frontend.Variable(0)
		if prefixLength <= i {
			phraseStart = fromHits[i-prefixLength]
		}
		api.AssertIsEqual(api.Mul(fromHits[i], api.Sub(wireFingerprint(api, masked, i, prefixLength), constantFingerprint([]byte(literalFromPrefix)))), 0)
		// each region is a running sum of one-hots, kept a bit by these assertions
		inPhrase = api.Sub(api.Add(inPhrase, phraseStart), scan.FromAngle[i])
		api.AssertIsBoolean(inPhrase)
		api.AssertIsEqual(api.Mul(inPhrase, api.Sub(1, api.Add(inLocal[i], isSp[i]))), 0)
		api.AssertIsEqual(api.Mul(scan.FromAngle[i], api.Sub(masked[i], octetLt)), 0)
		// a phrase is followed by SP, and an empty phrase needs none
		if 0 < i {
			api.AssertIsEqual(api.Mul(api.Mul(scan.FromAngle[i], api.Sub(1, phraseStart)), api.Sub(1, isSp[i-1])), 0)
		}
		inAddress = api.Sub(inAddress, scan.FromAt[i])
		api.AssertIsBoolean(inAddress)
		api.AssertIsEqual(api.Mul(inAddress, api.Sub(1, inLocal[i])), 0)
		localBytes = api.Add(localBytes, inAddress)
		inAddress = api.Add(inAddress, scan.FromAngle[i])
		if i%shape.pinInterval == 0 {
			inPhrase = pinWire(api, inPhrase)
			inAddress = pinWire(api, inAddress)
			localBytes = pinWire(api, localBytes)
		}
	}
	// the local part fills 1 to LocalMaxByteCount octets
	assertBelow(api, api.Sub(localBytes, 1), shape.localMaxBytes)
	return sumWires(api, singleTerms)
}

// H12 over a later header record: none of the literals begins a line in it, whole, or crossing in from
// the record before (by in's prefix and run), the one-click field only on a BULK message.
func checkLaterHeaderRecord(api frontend.API, scan *headerRecordScan, masked []frontend.Variable, foldedMasked []frontend.Variable, in *circuitScanState, full *[scanLiteralCount][]frontend.Variable) {
	gate := func(literal int, value frontend.Variable) frontend.Variable {
		if literal == scanLiteralUnsubscribe {
			return api.Mul(scan.Bulk, value)
		}
		return value
	}
	for literal := range scanLiterals {
		api.AssertIsEqual(gate(literal, sumWires(api, full[literal])), 0)
	}
	longest := 0
	for _, entry := range scanLiterals {
		longest = max(longest, len(entry.octets))
	}
	runValue := in.runValue(api)
	runIs := make([]frontend.Variable, longest)
	for r := 1; r < longest; r += 1 {
		runIs[r] = api.IsZero(api.Sub(runValue, r))
	}
	for literal, entry := range scanLiterals {
		source := masked
		if entry.folded {
			source = foldedMasked
		}
		crossings := []frontend.Variable{}
		for r := 1; r < len(entry.octets); r += 1 {
			crossings = append(crossings, api.Mul(runIs[r], matchesConstant(api, source, 0, []byte(entry.octets[r:]))))
		}
		cross := api.Mul(in.prefix[literal], sumWires(api, crossings))
		api.AssertIsEqual(gate(literal, cross), 0)
	}
}

// The public wires of a header record: its blocks and template, Active and Field, and in the first
// record the literal forms. last is the header block's last record, whose final CRLF CRLF is literal
// and outside Field (H13).
func assignHeaderRecordPublic(shape *partShape, statement *partStatement, record *partRecord, scan *headerRecordScan, last bool) error {
	session := statement.session
	preamble := session.preamble
	ciphertext, err := recordCiphertext(session.version, record.raw)
	if err != nil {
		return err
	}
	contentBytes := len(ciphertext)
	if session.version == tlsVersion13 {
		contentBytes -= tlsInnerTypeBytes
	}
	end := literalCrlf + literalCrlf
	if contentBytes < 1 || len(scan.Active) < len(ciphertext) || (last && contentBytes < len(end)) {
		return errors.New("the header record does not fit the shape")
	}
	template := make([]templateOctet, 0, len(ciphertext))
	free := contentBytes
	if last {
		free -= len(end)
	}
	for range free {
		template = append(template, templateOctet{kind: templateFree})
	}
	if last {
		template = append(template, templateOf(end)...)
	}
	if session.version == tlsVersion13 {
		template = append(template, templateOctet{kind: templateLiteral, literal: tlsRecordApplicationData})
	}
	if _, err := assignRecordBlocks(shape, statement, record, template, scan.Blocks); err != nil {
		return err
	}
	for i := range contentBytes {
		scan.Active[i] = 1
		if !last || i < contentBytes-len(literalCrlf) {
			scan.Field[i] = 1
		}
	}
	if preamble.flags&preambleFlagBulk != 0 {
		scan.Bulk = 1
	}
	if !scan.first() {
		return nil
	}
	checks := []struct {
		check   *literalCheck
		literal string
	}{
		{check: scan.MessageId, literal: literalMessageIdPrefix + preamble.messageId + ">" + literalCrlf},
		{check: scan.XUrRef, literal: literalXUrRefPrefix + preamble.xUrRef + literalCrlf},
		{check: scan.Feedback, literal: literalFeedbackPrefix + preamble.feedbackId + literalCrlf},
		{check: scan.Address, literal: "@" + preamble.headerFromDomain + ">" + literalCrlf},
		{check: scan.DkimTags, literal: dkimTags(preamble)},
	}
	for _, entry := range checks {
		if err := assignLiteralCheck(entry.check, []byte(entry.literal)); err != nil {
			return err
		}
	}
	return nil
}

// The private positions in From, if the first record has a From to find. A record without one leaves
// them zero, which the circuit refuses.
func assignHeaderPrivate(scan *headerRecordScan, plaintext []byte) {
	lineStart := 0
	if !bytes.HasPrefix(plaintext, []byte(literalFromPrefix)) {
		index := bytes.Index(plaintext, []byte(literalCrlf+literalFromPrefix))
		if index < 0 {
			return
		}
		lineStart = index + len(literalCrlf)
	}
	lineEnd := bytes.Index(plaintext[lineStart:], []byte(literalCrlf))
	if lineEnd < 0 {
		return
	}
	line := plaintext[lineStart : lineStart+lineEnd]
	angle := bytes.LastIndexByte(line, '<')
	at := bytes.LastIndexByte(line, '@')
	if angle < 0 || at < 0 || lineStart+at >= len(scan.FromAt) {
		return
	}
	scan.FromAngle[lineStart+angle] = 1
	scan.FromAt[lineStart+at] = 1
}

// One DATA body record and what the edge knows of its positions.
type bodyRecordScan struct {
	Blocks []*poolBlock
	// A content octet.
	Active []frontend.Variable `gnark:",public"`
	// On the body's last record alone: its last octet, which must be LF, so the end mark starts a line.
	End []frontend.Variable `gnark:",public"`
}

func newBodyRecordScan(shape *partShape) *bodyRecordScan {
	size := shape.bodyBlocks * shape.blockBytes()
	scan := &bodyRecordScan{Active: make([]frontend.Variable, size), End: make([]frontend.Variable, size)}
	for range shape.bodyBlocks {
		scan.Blocks = append(scan.Blocks, newPoolBlock(shape.blockBytes(), false))
	}
	return scan
}

func zeroBodyRecordScan(scan *bodyRecordScan) {
	for _, block := range scan.Blocks {
		zeroPoolBlock(block)
	}
	for i := range scan.Active {
		scan.Active[i] = 0
		scan.End[i] = 0
	}
}

// Z6 over one DATA body record, DESIGN-DETAILS 3.2.4's B1 to B3, from the state in, returning the state
// it leaves: no bare CR or LF, and no line that is exactly ".", across record boundaries by pos. A part
// that opens no body record, the last of an empty body, leaves in as it was.
func checkBodyRecordCircuit(api frontend.API, stream *circuitKeystream, scan *bodyRecordScan, in *circuitScanState) *circuitScanState {
	octets := openTemplatedBlocks(api, stream, scan.Blocks)
	size := len(octets)
	active := scan.Active
	isCr := make([]frontend.Variable, size)
	isLf := make([]frontend.Variable, size)
	isDot := make([]frontend.Variable, size)
	crActive := make([]frontend.Variable, size)
	lfActive := make([]frontend.Variable, size)
	for i, octet := range octets {
		isCr[i] = api.IsZero(api.Sub(octet.value, octetCr))
		isLf[i] = api.IsZero(api.Sub(octet.value, octetLf))
		isDot[i] = api.IsZero(api.Sub(octet.value, octetDot))
		crActive[i] = api.Mul(active[i], isCr[i])
		lfActive[i] = api.Mul(active[i], isLf[i])
		// the body's last octet is LF
		api.AssertIsEqual(api.Mul(scan.End[i], api.Sub(1, isLf[i])), 0)
	}
	inPosCr := in.posIs(api, scanPosCr)
	inPosLf := in.posIs(api, scanPosLf)
	inPosDot := in.posIs(api, scanPosDot)
	// B2 at the boundary: a "." that began the record before's last line is not followed by CR
	api.AssertIsEqual(api.Mul(inPosDot, crActive[0]), 0)
	// a part with no body octet, an empty body's last, opens the end mark at a line's start
	api.AssertIsEqual(api.Mul(api.Sub(1, active[0]), api.Sub(1, inPosLf)), 0)
	posTerms := make([]frontend.Variable, 0, size+1)
	for i := range size {
		previousCr := inPosCr
		lineStart := inPosLf
		if 0 < i {
			previousCr = isCr[i-1]
			lineStart = lfActive[i-1]
		}
		// B1: LF exactly after CR
		api.AssertIsEqual(api.Mul(active[i], api.Sub(isLf[i], previousCr)), 0)
		// B2: a "." at a line's start is not followed by CR
		dotStart := api.Mul(lineStart, isDot[i])
		if i+1 < size {
			api.AssertIsEqual(api.Mul(dotStart, crActive[i+1]), 0)
		}
		// B3: pos after the last octet
		last := active[i]
		if i+1 < size {
			last = api.Sub(active[i], active[i+1])
		}
		posTerms = append(posTerms, api.Mul(last, api.Add(isCr[i], api.Mul(isLf[i], 2), api.Mul(dotStart, 3))))
	}
	// no octet: pos is as it was
	inPos := api.Add(in.pos[0], api.Mul(in.pos[1], 2))
	posTerms = append(posTerms, api.Mul(api.Sub(1, active[0]), inPos))
	out := newCircuitScanStateConstant(0)
	copy(out.pos[:], bitsOf(api, sumWires(api, posTerms), scanPosBits))
	return out
}

// The public wires of a body record. last is the body's last record, whose last octet is LF.
func assignBodyRecordPublic(shape *partShape, statement *partStatement, record *partRecord, scan *bodyRecordScan, last bool) error {
	session := statement.session
	ciphertext, err := recordCiphertext(session.version, record.raw)
	if err != nil {
		return err
	}
	contentBytes := len(ciphertext)
	if session.version == tlsVersion13 {
		contentBytes -= tlsInnerTypeBytes
	}
	// a hostile sidecar's record can be all tag, which in 1.3 leaves this at -1
	if contentBytes <= 0 {
		return errors.New("empty body record")
	}
	if len(scan.Active) < len(ciphertext) {
		return errors.New("the body record does not fit the shape")
	}
	template := make([]templateOctet, len(ciphertext))
	if session.version == tlsVersion13 {
		template[contentBytes] = templateOctet{kind: templateLiteral, literal: tlsRecordApplicationData}
	}
	if _, err := assignRecordBlocks(shape, statement, record, template, scan.Blocks); err != nil {
		return err
	}
	for i := range contentBytes {
		scan.Active[i] = 1
	}
	if last {
		scan.End[contentBytes-1] = 1
	}
	return nil
}
