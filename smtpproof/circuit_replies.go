package smtpproof

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// Z7-Z9 in the circuit: the MX's replies, read under its own key, which never leaves the circuit
// (D-SMTP-22). This is why a malicious sidecar's control flow is no evidence of the MX's state, and
// what the proof puts in its place (SPEC.md 9.4).
//
// The replies stay private, so unlike a command's their offsets are not public and no template can
// serve. They are parsed by a one-hot state machine, one step per octet of the stream. Positions
// that are not content, a record's type octet or a block's unused tail, leave it unchanged. A ticket's
// octets do too, by a private flag, since which records are tickets is not public (Z7).

const (
	replyLf   = 10
	replyCr   = 13
	replySp   = 32
	replyDash = 45
	// The octets of a keyword window: CR LF 2 5 0 sep CHUNKING CR LF.
	replyWindowBytes = 16
	replySepOffset   = 5
	replyWordOffset  = 6
	// Octets between pinning a scanner's running sums to single wires.
	pinInterval = 32
)

// The octet of a reply stream as a wire value and its bits.
type replyOctet struct {
	value    frontend.Variable
	bits     circuitByte
	active   frontend.Variable
	sepOk    frontend.Variable
	windowOk frontend.Variable
}

// isDigit from an octet's bits: high nibble 3 and low nibble at most 9.
func replyIsDigit(api frontend.API, bits circuitByte) frontend.Variable {
	highIs3 := api.Mul(api.Mul(bits[4], bits[5]), api.Mul(api.Sub(1, bits[6]), api.Sub(1, bits[7])))
	// low nibble 10 and up: bit 3 with bit 1 or bit 2
	lowOver := api.Mul(bits[3], api.Sub(api.Add(bits[1], bits[2]), api.Mul(bits[1], bits[2])))
	return api.Mul(highIs3, api.Sub(1, lowOver))
}

func replyEquals(api frontend.API, value frontend.Variable, octet int) frontend.Variable {
	return api.IsZero(api.Sub(value, octet))
}

// The literal a keyword window must equal, with the separator's position left zero.
func replyWindowFingerprint() *big.Int {
	window := []byte("\r\n250\x00" + keywordChunking + "\r\n")
	fingerprint := new(big.Int)
	for i := len(window) - 1; 0 <= i; i -= 1 {
		fingerprint.Lsh(fingerprint, 8)
		fingerprint.Add(fingerprint, big.NewInt(int64(window[i])))
	}
	return fingerprint
}

// Decrypts server blocks, checks each record's framing (Z7) and parses the reply stream (Z8, Z9).
func checkReplies(api frontend.API, shape *partShape, stream *circuitKeystream, circuit *partCircuit) {
	var octets []*replyOctet
	previousTicket := frontend.Variable(0)
	for _, block := range circuit.Server {
		api.AssertIsBoolean(block.Ticket)
		if shape.version == tlsVersion12 {
			// 1.2 offers no ticket here, and its records carry their type in the clear (E1)
			api.AssertIsEqual(block.Ticket, 0)
		}
		// a record's blocks share its kind
		api.AssertIsEqual(api.Mul(block.Continues, api.Sub(block.Ticket, previousTicket)), 0)
		previousTicket = block.Ticket
		keystream := stream.block(api, block.Counter)
		for i := range block.Cipher {
			cipherBits := bitsOf(api, block.Cipher[i], 8)
			octet := &replyOctet{}
			for bit := range octet.bits {
				octet.bits[bit] = bitXor(api, cipherBits[bit], keystream[i][bit])
			}
			octet.value = byteValue(api, octet.bits)
			// Z7: the inner type is application_data, or handshake for a ticket
			api.AssertIsEqual(api.Mul(block.TypeOctet[i], api.Add(api.Sub(octet.value, tlsRecordApplicationData), block.Ticket)), 0)
			// Z7: a ticket's record starts with NewSessionTicket, so a KeyUpdate cannot pass as one
			firstOfTicket := api.Mul(block.FirstOctet[i], block.Ticket)
			api.AssertIsEqual(api.Mul(firstOfTicket, api.Sub(octet.value, tlsHandshakeNewSessionTicket)), 0)
			octet.active = api.Mul(block.Active[i], api.Sub(1, block.Ticket))
			octet.windowOk = block.WindowActive[i]
			octets = append(octets, octet)
		}
	}

	// one-hot: at digit 1, 2, 3, the separator, the text, or the LF after a CR
	var state [6]frontend.Variable
	state[0] = 1
	for i := 1; i < len(state); i++ {
		state[i] = 0
	}
	var code [3]frontend.Variable
	for i := range code {
		code[i] = 0
	}
	finalLine := frontend.Variable(0)
	replies := frontend.Variable(0)
	for position, octet := range octets {
		// a bound on how far these sums run before a constraint must carry all their terms
		if position%pinInterval == 0 {
			for i := range state {
				state[i] = pinWire(api, state[i])
			}
			for i := range code {
				code[i] = pinWire(api, code[i])
			}
			finalLine = pinWire(api, finalLine)
			replies = pinWire(api, replies)
		}
		value := octet.value
		isCr := replyEquals(api, value, replyCr)
		isLf := replyEquals(api, value, replyLf)
		isDash := replyEquals(api, value, replyDash)
		isSp := replyEquals(api, value, replySp)
		isDigit := replyIsDigit(api, octet.bits)
		octet.sepOk = api.Add(isDash, isSp)

		var stepped [6]frontend.Variable
		for i := range stepped {
			stepped[i] = api.Mul(octet.active, state[i])
		}
		// what each state accepts
		api.AssertIsEqual(api.Mul(api.Add(stepped[0], stepped[1], stepped[2]), api.Sub(1, isDigit)), 0)
		api.AssertIsEqual(api.Mul(stepped[3], api.Sub(1, api.Add(isDash, isSp, isCr))), 0)
		api.AssertIsEqual(api.Mul(stepped[4], isLf), 0)
		api.AssertIsEqual(api.Mul(stepped[5], api.Sub(1, isLf)), 0)

		// the line's code, and whether it is the reply's last line
		code[0] = api.Add(code[0], api.Mul(stepped[0], api.Sub(value, code[0])))
		code[1] = api.Add(code[1], api.Mul(stepped[1], api.Sub(value, code[1])))
		code[2] = api.Add(code[2], api.Mul(stepped[2], api.Sub(value, code[2])))
		finalLine = api.Add(finalLine, api.Mul(stepped[3], api.Sub(api.Add(isSp, isCr), finalLine)))

		// a line ends at the LF in state 5
		ended := stepped[5]
		replyEnded := api.Mul(ended, finalLine)
		switch shape.kind {
		case partKindEnvelope:
			// every line of the EHLO reply is coded 250 (Z8)
			api.AssertIsEqual(api.Mul(ended, api.Sub(code[0], '2')), 0)
			api.AssertIsEqual(api.Mul(ended, api.Sub(code[1], '5')), 0)
			api.AssertIsEqual(api.Mul(ended, api.Sub(code[2], '0')), 0)
		case partKindMessage:
			// each reply is 2xx, but in DATA mode the last is 354 (Z8)
			isLast := api.IsZero(api.Sub(api.Add(replies, 1), circuit.ExpectedReplies))
			wants354 := api.Mul(isLast, circuit.DataMode)
			api.AssertIsEqual(api.Mul(replyEnded, api.Sub(code[0], api.Add('2', wants354))), 0)
			ended354 := api.Mul(replyEnded, wants354)
			api.AssertIsEqual(api.Mul(ended354, api.Sub(code[1], '5')), 0)
			api.AssertIsEqual(api.Mul(ended354, api.Sub(code[2], '4')), 0)
		}
		replies = api.Add(replies, replyEnded)

		toText := api.Mul(api.Add(stepped[3], stepped[4]), isCr)
		next := [6]frontend.Variable{
			api.Add(api.Sub(state[0], stepped[0]), stepped[5]),
			api.Add(api.Sub(state[1], stepped[1]), stepped[0]),
			api.Add(api.Sub(state[2], stepped[2]), stepped[1]),
			api.Add(api.Sub(state[3], stepped[3]), stepped[2]),
			api.Sub(api.Add(api.Sub(state[4], stepped[4]), stepped[3], stepped[4]), toText),
			api.Add(api.Sub(state[5], stepped[5]), toText),
		}
		state = next
	}
	// the stream ends between lines, with exactly the replies the part expects
	api.AssertIsEqual(state[0], 1)
	api.AssertIsEqual(replies, circuit.ExpectedReplies)

	// Z9: a whole line that is CHUNKING, and never the first, since CR LF precedes it. Letters compare
	// without case by forcing bit 5, which is exact for letters; the rest compare exactly.
	hits := frontend.Variable(0)
	want := replyWindowFingerprint()
	for i := 0; i+replyWindowBytes <= len(octets); i++ {
		terms := make([]frontend.Variable, 0, replyWindowBytes)
		for j := range replyWindowBytes {
			if j == replySepOffset {
				continue
			}
			weight := new(big.Int).Lsh(big.NewInt(1), uint(8*j))
			value := octets[i+j].value
			if replyWordOffset <= j && j < replyWordOffset+len(keywordChunking) {
				value = api.Add(value, api.Mul(api.Sub(1, octets[i+j].bits[5]), 32))
			}
			terms = append(terms, api.Mul(value, weight))
		}
		matched := api.IsZero(api.Sub(api.Add(terms[0], terms[1], terms[2:]...), want))
		hit := api.Mul(api.Mul(matched, octets[i+replySepOffset].sepOk), octets[i].windowOk)
		hits = api.Add(hits, hit)
	}
	api.AssertIsEqual(api.Mul(circuit.RequireChunking, api.IsZero(hits)), 0)
}

// The public wires of every server record the part covers.
func assignServerRecords(shape *partShape, statement *partStatement, circuit *partCircuit) error {
	blockBytes := shape.blockBytes()
	version := statement.session.version
	slot := 0
	type flatOctet struct {
		block  *serverBlock
		offset int
		// Which record this octet's content belongs to, or -1 for a non-content position.
		record int
	}
	var flat []flatOctet
	for index, record := range statement.serverRecords {
		ciphertext, err := recordCiphertext(version, record.raw)
		if err != nil {
			return err
		}
		if len(ciphertext) == 0 {
			return errors.New("empty server record")
		}
		counterHigh := record.seq
		if version == tlsVersion12 {
			counterHigh = 0
			for _, octet := range record.raw[tlsRecordHeaderBytes : tlsRecordHeaderBytes+tlsExplicitNonceBytes] {
				counterHigh = counterHigh<<8 | uint64(octet)
			}
		}
		contentBytes := len(ciphertext)
		if version == tlsVersion13 {
			contentBytes -= tlsInnerTypeBytes
		}
		for offset := 0; offset < len(ciphertext); offset += blockBytes {
			if slot == len(circuit.Server) {
				return errors.New("records do not fit the shape's blocks")
			}
			block := circuit.Server[slot]
			counter := new(big.Int).SetUint64(counterHigh)
			counter.Lsh(counter, 32)
			counter.Add(counter, new(big.Int).SetUint64(shape.firstCounter()+uint64(offset/blockBytes)))
			block.Counter = counter
			if 0 < offset {
				block.Continues = 1
			}
			for i := range blockBytes {
				position := offset + i
				owner := -1
				if position < len(ciphertext) {
					block.Cipher[i] = ciphertext[position]
					if position < contentBytes {
						block.Active[i] = 1
						owner = index
					}
					if version == tlsVersion13 && position == len(ciphertext)-1 {
						block.TypeOctet[i] = 1
					}
					if position == 0 {
						block.FirstOctet[i] = 1
					}
				}
				flat = append(flat, flatOctet{block: block, offset: i, record: owner})
			}
			slot += 1
		}
	}
	for start := 0; start+replyWindowBytes <= len(flat); start++ {
		whole := flat[start].record != -1
		for j := 1; j < replyWindowBytes && whole; j++ {
			whole = flat[start+j].record == flat[start].record
		}
		if whole {
			flat[start].block.WindowActive[flat[start].offset] = 1
		}
	}
	return nil
}
