package smtpproof

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// Z5 and Z6 in the circuit: the message's framing. The header block's offsets are private, so a
// field cannot be found by a public template. Instead every line start is examined: a field's name
// is matched by a fingerprint at each one, which is what makes "exactly once" a sum, and the matching
// line's whole value is then read at that one position and compared with the public literal.
//
// Fingerprints are linear in the octets and fit a field element, so comparing one costs two
// constraints however long it is. Reading a value costs one product per octet per 31-octet word.

const (
	// Octets a fingerprint or an extracted word holds: the most below the field's 254 bits.
	wordBytes = 31
	// The capacity of a whole literal line, which holds a Message-ID, X-UR-Ref or Feedback-ID.
	literalLineBytes = 124
	// The capacity of From's tail, "@" domain ">" CRLF.
	literalAddressBytes = 93
	// The capacity of the fixed signature's tags.
	literalTagBytes = 93

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

// The header block's blocks and what the edge knows of its positions.
type headerScan struct {
	Blocks []*poolBlock
	// A content octet of the header block.
	Active []frontend.Variable `gnark:",public"`
	// A content octet before the block's final CRLF, where a line must be a field or a continuation.
	Field []frontend.Variable `gnark:",public"`

	MessageId *literalCheck
	XUrRef    *literalCheck
	Feedback  *literalCheck
	Address   *literalCheck
	DkimTags  *literalCheck
	// 1 if BULK is set (Z5.6).
	Bulk frontend.Variable `gnark:",public"`

	// One-hot, private: where From's < and @ are.
	FromAngle []frontend.Variable
	FromAt    []frontend.Variable
}

func newHeaderScan(shape *partShape) *headerScan {
	size := shape.headerBlocks * shape.blockBytes()
	scan := &headerScan{
		Active:    make([]frontend.Variable, size),
		Field:     make([]frontend.Variable, size),
		MessageId: newLiteralCheck(literalLineBytes),
		XUrRef:    newLiteralCheck(literalLineBytes),
		Feedback:  newLiteralCheck(literalLineBytes),
		Address:   newLiteralCheck(literalAddressBytes),
		DkimTags:  newLiteralCheck(literalTagBytes),
		FromAngle: make([]frontend.Variable, size),
		FromAt:    make([]frontend.Variable, size),
	}
	for range shape.headerBlocks {
		scan.Blocks = append(scan.Blocks, newPoolBlock(shape.blockBytes()))
	}
	return scan
}

func zeroPoolBlock(block *poolBlock) {
	block.Counter = 0
	for i := range block.Cipher {
		block.Cipher[i] = 0
		block.Literal[i] = 0
		block.IsLiteral[i] = 0
		block.IsLocal[i] = 0
	}
}

func zeroHeaderScan(scan *headerScan) {
	for _, block := range scan.Blocks {
		zeroPoolBlock(block)
	}
	for i := range scan.Active {
		scan.Active[i] = 0
		scan.Field[i] = 0
		scan.FromAngle[i] = 0
		scan.FromAt[i] = 0
	}
	for _, check := range []*literalCheck{scan.MessageId, scan.XUrRef, scan.Feedback, scan.Address, scan.DkimTags} {
		zeroLiteralCheck(check)
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
	switch len(terms) {
	case 0:
		return 0
	case 1:
		return terms[0]
	}
	return api.Add(terms[0], terms[1], terms[2:]...)
}

// Whether wires from start equal a constant of any length, as 0 or 1.
func matchesConstant(api frontend.API, wires []frontend.Variable, start int, constant []byte) frontend.Variable {
	match := frontend.Variable(1)
	for offset := 0; offset < len(constant); offset += wordBytes {
		end := min(offset+wordBytes, len(constant))
		fingerprint := wireFingerprint(api, wires, start+offset, end-offset)
		equal := api.IsZero(api.Sub(fingerprint, constantFingerprint(constant[offset:end])))
		if _, ok := api.Compiler().ConstantValue(match); ok {
			match = equal
		} else {
			match = api.Mul(match, equal)
		}
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
		word := frontend.Variable(0)
		if 1 < len(terms) {
			word = api.Add(terms[0], terms[1], terms[2:]...)
		} else if len(terms) == 1 {
			word = terms[0]
		}
		bits := bitsOf(api, word, 8*count)
		for j := range count {
			var octet circuitByte
			copy(octet[:], bits[8*j:8*j+8])
			api.AssertIsEqual(api.Mul(check.Used[offset+j], api.Sub(byteValue(api, octet), check.Expected[offset+j])), 0)
		}
	}
}

// Z5 over the header block, in SPEC.md's rule order.
func checkHeaderBlockCircuit(api frontend.API, shape *partShape, stream *circuitKeystream, scan *headerScan) {
	var octets []*openOctet
	for _, block := range scan.Blocks {
		for i, octet := range openBlock(api, stream, block.Counter, block.Cipher) {
			// the record's final CRLF CRLF and, in 1.3, its type octet are template literals (Z3, Z5.2)
			api.AssertIsEqual(api.Mul(block.IsLiteral[i], api.Sub(octet.value, block.Literal[i])), 0)
			octets = append(octets, octet)
		}
	}
	size := len(octets)
	values := make([]frontend.Variable, size)
	folded := make([]frontend.Variable, size)
	isCr := make([]frontend.Variable, size)
	isSp := make([]frontend.Variable, size)
	isTab := make([]frontend.Variable, size)
	isColon := make([]frontend.Variable, size)
	crActive := make([]frontend.Variable, size)
	lfActive := make([]frontend.Variable, size)
	inLocal := make([]frontend.Variable, size)
	for i, octet := range octets {
		value := octet.value
		values[i] = value
		// bit 5 forced, which compares letters without case; the rest of a name compares exactly,
		// since rule 1 and rule 3 keep control octets out of it
		folded[i] = api.Add(value, api.Mul(api.Sub(1, octet.bits[5]), 32))
		isCr[i] = api.IsZero(api.Sub(value, octetCr))
		isLf := api.IsZero(api.Sub(value, octetLf))
		isSp[i] = api.IsZero(api.Sub(value, octetSp))
		isTab[i] = api.IsZero(api.Sub(value, octetTab))
		isColon[i] = api.IsZero(api.Sub(value, octetColon))
		isDel := api.IsZero(api.Sub(value, octetDel))
		crActive[i] = api.Mul(scan.Active[i], isCr[i])
		lfActive[i] = api.Mul(scan.Active[i], isLf)
		inLocal[i] = localSetMember(api, octet)

		// rule 1: HTAB, SP through ~, CR or LF
		bits := octet.bits
		printable := api.Mul(api.Sub(1, bits[7]), api.Sub(api.Add(bits[5], bits[6]), api.Mul(bits[5], bits[6])))
		allowed := api.Add(api.Sub(printable, isDel), isTab[i], isCr[i], isLf)
		api.AssertIsEqual(api.Mul(scan.Active[i], api.Sub(1, allowed)), 0)
	}
	// rule 1: CR exactly before LF
	api.AssertIsEqual(lfActive[0], 0)
	api.AssertIsEqual(crActive[size-1], 0)
	for i := range size - 1 {
		api.AssertIsEqual(crActive[i], lfActive[i+1])
	}

	fromHits := make([]frontend.Variable, size)
	messageIdHits := make([]frontend.Variable, size)
	xUrRefHits := make([]frontend.Variable, size)
	feedbackHits := make([]frontend.Variable, size)
	dkimHits := make([]frontend.Variable, size)
	unsubscribeHits := make([]frontend.Variable, size)
	inName := frontend.Variable(0)
	inField := frontend.Variable(0)
	for i := range size {
		// a line starts at 0 and after every LF; the block's final CRLF is no line (rule 2)
		lineStart := frontend.Variable(1)
		if 0 < i {
			lineStart = lfActive[i-1]
		}
		lineStart = api.Mul(lineStart, scan.Field[i])
		isWsp := api.Add(isSp[i], isTab[i])
		// rule 2: no empty line before the end
		api.AssertIsEqual(api.Mul(lineStart, isCr[i]), 0)
		// rule 3: a line is a continuation, but never the first, or a name directly before a colon
		if i == 0 {
			api.AssertIsEqual(isWsp, 0)
		}
		nameStart := api.Mul(lineStart, api.Sub(1, isWsp))
		// nor does a name start with a dot, which an MX reading DATA would delete (RFC 5321 §4.5.2),
		// leaving a field no fingerprint below saw
		api.AssertIsEqual(api.Mul(nameStart, api.Add(isColon[i], api.IsZero(api.Sub(values[i], octetDot)))), 0)
		naming := api.Add(inName, nameStart)
		api.AssertIsEqual(api.Mul(naming, api.Add(isWsp, crActive[i])), 0)
		inName = api.Mul(naming, api.Sub(1, isColon[i]))

		// rule 4: each single field, by a fingerprint of its name at each line start
		match := func(name string) frontend.Variable {
			return api.Mul(nameStart, matchesConstant(api, folded, i, []byte(name)))
		}
		fromHits[i] = match("from:")
		messageIdHits[i] = match("message-id:")
		xUrRefHits[i] = match("x-ur-ref:")
		feedbackHits[i] = match("feedback-id:")
		// rules 5 and 6: exact octets, not folded
		dkimHits[i] = api.Mul(nameStart, matchesConstant(api, values, i, []byte(literalDkimPrefix)))
		unsubscribeHits[i] = api.Mul(nameStart, matchesConstant(api, values, i, []byte(literalUnsubscribePost+literalCrlf)))

		// rule 4: none of the single fields is continued
		singleField := api.Add(inField, fromHits[i], messageIdHits[i], xUrRefHits[i], feedbackHits[i])
		ending := api.Mul(singleField, lfActive[i])
		if i+1 < size {
			api.AssertIsEqual(api.Mul(ending, api.Add(isSp[i+1], isTab[i+1])), 0)
		}
		inField = api.Sub(singleField, ending)
		if i%pinInterval == 0 {
			inField = pinWire(api, inField)
		}
	}
	sum := func(wires []frontend.Variable) frontend.Variable {
		return api.Add(wires[0], wires[1], wires[2:]...)
	}
	for _, hits := range [][]frontend.Variable{fromHits, messageIdHits, xUrRefHits, feedbackHits, dkimHits} {
		api.AssertIsEqual(sum(hits), 1)
	}
	api.AssertIsEqual(api.Mul(scan.Bulk, api.Sub(sum(unsubscribeHits), 1)), 0)

	// rule 4's literal forms, each read at its one position
	checkLiteralAt(api, values, messageIdHits, 0, scan.MessageId)
	checkLiteralAt(api, values, xUrRefHits, 0, scan.XUrRef)
	checkLiteralAt(api, values, feedbackHits, 0, scan.Feedback)
	checkLiteralAt(api, values, dkimHits, len(literalDkimPrefix), scan.DkimTags)

	// rule 4's From: "From: ", phrase, <, local, then the literal address
	for i := range size {
		api.AssertIsBoolean(scan.FromAngle[i])
		api.AssertIsBoolean(scan.FromAt[i])
	}
	api.AssertIsEqual(sum(scan.FromAngle), 1)
	api.AssertIsEqual(sum(scan.FromAt), 1)
	checkLiteralAt(api, values, scan.FromAt, 0, scan.Address)
	inPhrase := frontend.Variable(0)
	inAddress := frontend.Variable(0)
	localBytes := frontend.Variable(0)
	prefixLength := len(literalFromPrefix)
	for i := range size {
		phraseStart := frontend.Variable(0)
		if prefixLength <= i {
			phraseStart = fromHits[i-prefixLength]
		}
		api.AssertIsEqual(api.Mul(fromHits[i], api.Sub(wireFingerprint(api, values, i, prefixLength), constantFingerprint([]byte(literalFromPrefix)))), 0)
		// each region is a running sum of one-hots, kept a bit by these assertions
		inPhrase = api.Sub(api.Add(inPhrase, phraseStart), scan.FromAngle[i])
		api.AssertIsBoolean(inPhrase)
		api.AssertIsEqual(api.Mul(inPhrase, api.Sub(1, api.Add(inLocal[i], isSp[i]))), 0)
		api.AssertIsEqual(api.Mul(scan.FromAngle[i], api.Sub(values[i], octetLt)), 0)
		// a phrase is followed by SP, and an empty phrase needs none
		if 0 < i {
			api.AssertIsEqual(api.Mul(api.Mul(scan.FromAngle[i], api.Sub(1, phraseStart)), api.Sub(1, isSp[i-1])), 0)
		}
		inAddress = api.Sub(inAddress, scan.FromAt[i])
		api.AssertIsBoolean(inAddress)
		api.AssertIsEqual(api.Mul(inAddress, api.Sub(1, inLocal[i])), 0)
		localBytes = api.Add(localBytes, inAddress)
		inAddress = api.Add(inAddress, scan.FromAngle[i])
		if i%pinInterval == 0 {
			inPhrase = pinWire(api, inPhrase)
			inAddress = pinWire(api, inAddress)
			localBytes = pinWire(api, localBytes)
		}
	}
	// the local part fills 1 to 64 octets
	bitsOf(api, api.Sub(localBytes, 1), 6)
}

// The public wires of the header block record.
func assignHeaderPublic(shape *partShape, statement *partStatement, record *partRecord, scan *headerScan) error {
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
	if contentBytes < len(end) || len(scan.Active) < len(ciphertext) {
		return errors.New("the header block does not fit the shape")
	}
	template := make([]templateOctet, 0, len(ciphertext))
	for range contentBytes - len(end) {
		template = append(template, templateOctet{kind: templateFree})
	}
	template = append(template, templateOf(end)...)
	if session.version == tlsVersion13 {
		template = append(template, templateOctet{kind: templateLiteral, literal: tlsRecordApplicationData})
	}
	if _, err := assignRecordBlocks(shape, statement, record, template, scan.Blocks); err != nil {
		return err
	}
	for i := range contentBytes {
		scan.Active[i] = 1
		if i < contentBytes-len(literalCrlf) {
			scan.Field[i] = 1
		}
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
	if preamble.flags&preambleFlagBulk != 0 {
		scan.Bulk = 1
	}
	return nil
}

// The private positions in From, if the block has a From to find. A block without one leaves them
// zero, which the circuit refuses.
func assignHeaderPrivate(scan *headerScan, preamble *sessionPreamble, plaintext []byte) {
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

// A block of body record octets, and what the edge knows of its positions.
type bodyBlock struct {
	Block *poolBlock
	// A content octet.
	Active []frontend.Variable `gnark:",public"`
	// The first content octet of a record, which is always a line start (Z6).
	Start []frontend.Variable `gnark:",public"`
	// The last content octet of a record, which must be LF.
	End []frontend.Variable `gnark:",public"`
}

func newBodyBlock(blockBytes int) *bodyBlock {
	return &bodyBlock{
		Block:  newPoolBlock(blockBytes),
		Active: make([]frontend.Variable, blockBytes),
		Start:  make([]frontend.Variable, blockBytes),
		End:    make([]frontend.Variable, blockBytes),
	}
}

func zeroBodyBlock(block *bodyBlock) {
	zeroPoolBlock(block.Block)
	for i := range block.Active {
		block.Active[i] = 0
		block.Start[i] = 0
		block.End[i] = 0
	}
}

// Z6 over DATA's body records: whole lines, no bare CR or LF, no line that is exactly ".".
func checkBody(api frontend.API, stream *circuitKeystream, blocks []*bodyBlock) {
	var crActive, lfActive, isDot, starts, ends []frontend.Variable
	for _, block := range blocks {
		for i, octet := range openBlock(api, stream, block.Block.Counter, block.Block.Cipher) {
			// Z3: a 1.3 record's final octet
			api.AssertIsEqual(api.Mul(block.Block.IsLiteral[i], api.Sub(octet.value, block.Block.Literal[i])), 0)
			crActive = append(crActive, api.Mul(block.Active[i], api.IsZero(api.Sub(octet.value, octetCr))))
			lfActive = append(lfActive, api.Mul(block.Active[i], api.IsZero(api.Sub(octet.value, octetLf))))
			isDot = append(isDot, api.IsZero(api.Sub(octet.value, octetDot)))
			starts = append(starts, block.Start[i])
			ends = append(ends, block.End[i])
		}
	}
	size := len(crActive)
	api.AssertIsEqual(lfActive[0], 0)
	api.AssertIsEqual(crActive[size-1], 0)
	for i := range size {
		if i+1 < size {
			api.AssertIsEqual(crActive[i], lfActive[i+1])
		}
		api.AssertIsEqual(api.Mul(ends[i], api.Sub(1, lfActive[i])), 0)
		if i+1 < size {
			lineStart := starts[i]
			if 0 < i {
				lineStart = api.Add(lineStart, lfActive[i-1])
			}
			api.AssertIsEqual(api.Mul(api.Mul(lineStart, isDot[i]), crActive[i+1]), 0)
		}
	}
}

// The public wires of one body record, placed from the given slot on.
func assignBodyRecord(shape *partShape, statement *partStatement, record *partRecord, slots []*bodyBlock) (int, error) {
	session := statement.session
	ciphertext, err := recordCiphertext(session.version, record.raw)
	if err != nil {
		return 0, err
	}
	contentBytes := len(ciphertext)
	template := make([]templateOctet, len(ciphertext))
	if session.version == tlsVersion13 {
		contentBytes -= tlsInnerTypeBytes
		template[contentBytes] = templateOctet{kind: templateLiteral, literal: tlsRecordApplicationData}
	}
	if contentBytes == 0 {
		return 0, errors.New("empty body record")
	}
	blocks := make([]*poolBlock, len(slots))
	for i, slot := range slots {
		blocks[i] = slot.Block
	}
	used, err := assignRecordBlocks(shape, statement, record, template, blocks)
	if err != nil {
		return 0, err
	}
	blockBytes := shape.blockBytes()
	for i := range contentBytes {
		slots[i/blockBytes].Active[i%blockBytes] = 1
	}
	slots[0].Start[0] = 1
	slots[(contentBytes-1)/blockBytes].End[(contentBytes-1)%blockBytes] = 1
	return used, nil
}
