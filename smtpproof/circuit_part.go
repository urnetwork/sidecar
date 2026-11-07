package smtpproof

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// The circuit of one part (SPEC.md sections 5 and 7): Z1, then a pool of keystream blocks.
//
// A record's offsets are functions of public lengths, so the circuit holds no grammar. The edge
// computes a position template for every opened octet and the circuit only compares (Z2-Z4). Nothing
// here depends on how records divide among blocks: a block carries its own public counter, so one
// shape serves any mix of commands that fits it.
//
// Public wires need no booleanity constraints: the verifier computes them, and they are a fixed
// function of the statement (partAssignment). A dishonest prover cannot change them.

// Which part a shape proves.
type partKind uint8

const (
	partKindEhlo partKind = iota + 1
	partKindEnvelope
	// π3: the header block, in either mode.
	partKindMessage
	// A later DATA part.
	partKindBody
)

// A compiled circuit's fixed dimensions. A statement fits a shape if its records fit its blocks.
type partShape struct {
	kind         partKind
	version      uint16
	suite        uint16
	clientBlocks int
	// Server keystream blocks, which hold the replies the part covers (Z7, Z8).
	serverBlocks int
	// Keystream blocks of the header block, which Z5 scans, and of body records, which Z6 scans.
	headerBlocks int
	bodyBlocks   int
	// Whether the pool's template can hold a local part. π1's cannot, which saves a table per octet.
	localOctets bool
	// Leaves Z1 out, so tests can run every other check quickly over keys given as a witness.
	// partShapes never holds such a shape, and TestProductionShapesProveZ1 keeps it that way.
	withoutKeySchedule bool
}

// The octets one keystream block covers.
func (self *partShape) blockBytes() int {
	if self.suite == tlsSuiteChacha20Poly1305Sha256 {
		return 64
	}
	return 16
}

func (self *partShape) keyBytes() int {
	return tlsKeyBytes(self.suite)
}

// The suite's first keystream block index: AES-GCM's counter starts at 2 for data, ChaCha20's at 1.
func (self *partShape) firstCounter() uint64 {
	if self.suite == tlsSuiteChacha20Poly1305Sha256 {
		return 1
	}
	return 2
}

// One keystream block of the pool, and the template of the octets it covers.
type poolBlock struct {
	// seq (1.3) or the explicit nonce (1.2) above, the block counter below: 96 bits.
	Counter frontend.Variable `gnark:",public"`
	// Ciphertext octets, then what the template wants of each.
	Cipher    []frontend.Variable `gnark:",public"`
	Literal   []frontend.Variable `gnark:",public"`
	IsLiteral []frontend.Variable `gnark:",public"`
	IsLocal   []frontend.Variable `gnark:",public"`
}

// One keystream block of server records, with what the edge knows of each position from lengths.
type serverBlock struct {
	Counter frontend.Variable   `gnark:",public"`
	Cipher  []frontend.Variable `gnark:",public"`
	// A content octet, as opposed to a record's type octet or the unused tail of its last block.
	Active []frontend.Variable `gnark:",public"`
	// 1.3: the record's final octet, its inner type.
	TypeOctet []frontend.Variable `gnark:",public"`
	// The record's first octet.
	FirstOctet []frontend.Variable `gnark:",public"`
	// The 16 octets from here are all content of one record, so a keyword can match at it.
	WindowActive []frontend.Variable `gnark:",public"`
	// This block continues the previous block's record.
	Continues frontend.Variable `gnark:",public"`
	// Whether this block's record is a ticket. Private: §2.8 smtp-2 lists no such value (Z7).
	Ticket frontend.Variable
}

// SF as relayed: its explicit nonce, in the counter's high bits, and its 16 ciphertext octets.
type serverFinishedBlock struct {
	Counter frontend.Variable   `gnark:",public"`
	Cipher  []frontend.Variable `gnark:",public"`
}

// The circuit. Sized by its shape, which every instance of a compiled circuit shares.
type partCircuit struct {
	shape *partShape

	// 1.3: H_shts, H_sh, H_sf as bits.
	ShtsHash     []frontend.Variable `gnark:",public"`
	HelloHash    []frontend.Variable `gnark:",public"`
	FinishedHash []frontend.Variable `gnark:",public"`
	Client       []*poolBlock
	Server       []*serverBlock
	Header       *headerScan
	Body         []*bodyBlock
	// How many replies the part's server records must hold in all (Z8).
	ExpectedReplies frontend.Variable `gnark:",public"`
	// 1 if the EHLO reply must offer CHUNKING (Z9).
	RequireChunking frontend.Variable `gnark:",public"`
	// 1 in DATA mode, where the last reply π3 covers is 354 (Z8).
	DataMode frontend.Variable `gnark:",public"`

	// 1.2: Z1's public inputs, and SF as the record the edge relayed.
	ClientRandom       []frontend.Variable `gnark:",public"`
	ServerRandom       []frontend.Variable `gnark:",public"`
	ClientFinishedHash []frontend.Variable `gnark:",public"`
	Chaining           []frontend.Variable `gnark:",public"`
	ResumeBase         []frontend.Variable `gnark:",public"`
	ResumeShift        []frontend.Variable `gnark:",public"`
	ResumeTwoBlocks    frontend.Variable   `gnark:",public"`
	ServerFinished     *serverFinishedBlock

	// 1.3: HS, in bits.
	HandshakeSecret []frontend.Variable
	// 1.2: the master secret, in bits.
	MasterSecret []frontend.Variable
	// Only on a test shape that leaves Z1 out: the keys themselves.
	ClientKey []frontend.Variable
	ClientIv  []frontend.Variable
	ServerKey []frontend.Variable
	ServerIv  []frontend.Variable
}

func newPoolBlock(blockBytes int) *poolBlock {
	return &poolBlock{
		Cipher:    make([]frontend.Variable, blockBytes),
		Literal:   make([]frontend.Variable, blockBytes),
		IsLiteral: make([]frontend.Variable, blockBytes),
		IsLocal:   make([]frontend.Variable, blockBytes),
	}
}

func newPartCircuit(shape *partShape) *partCircuit {
	circuit := &partCircuit{shape: shape}
	if shape.withoutKeySchedule {
		circuit.ClientKey = make([]frontend.Variable, 8*shape.keyBytes())
		circuit.ClientIv = make([]frontend.Variable, 8*tlsIv13Bytes)
		circuit.ServerKey = make([]frontend.Variable, 8*shape.keyBytes())
		circuit.ServerIv = make([]frontend.Variable, 8*tlsIv13Bytes)
	}
	if shape.version == tlsVersion13 {
		circuit.ShtsHash = make([]frontend.Variable, 8*tlsSecretBytes)
		circuit.HelloHash = make([]frontend.Variable, 8*tlsSecretBytes)
		circuit.FinishedHash = make([]frontend.Variable, 8*tlsSecretBytes)
		circuit.HandshakeSecret = make([]frontend.Variable, 8*tlsSecretBytes)
	} else {
		circuit.ClientRandom = make([]frontend.Variable, 8*tlsRandomBytes)
		circuit.ServerRandom = make([]frontend.Variable, 8*tlsRandomBytes)
		circuit.ClientFinishedHash = make([]frontend.Variable, 8*tlsSecretBytes)
		circuit.Chaining = make([]frontend.Variable, 8*tlsSecretBytes)
		circuit.ResumeBase = make([]frontend.Variable, 8*2*sha256BlockBytes)
		circuit.ResumeShift = make([]frontend.Variable, 6)
		circuit.ServerFinished = &serverFinishedBlock{Cipher: make([]frontend.Variable, shape.blockBytes())}
		circuit.MasterSecret = make([]frontend.Variable, 8*tlsMasterSecretBytes)
	}
	for range shape.clientBlocks {
		circuit.Client = append(circuit.Client, newPoolBlock(shape.blockBytes()))
	}
	for range shape.serverBlocks {
		circuit.Server = append(circuit.Server, newServerBlock(shape.blockBytes()))
	}
	if 0 < shape.headerBlocks {
		circuit.Header = newHeaderScan(shape)
	}
	for range shape.bodyBlocks {
		circuit.Body = append(circuit.Body, newBodyBlock(shape.blockBytes()))
	}
	return circuit
}

func newServerBlock(blockBytes int) *serverBlock {
	return &serverBlock{
		Cipher:       make([]frontend.Variable, blockBytes),
		Active:       make([]frontend.Variable, blockBytes),
		TypeOctet:    make([]frontend.Variable, blockBytes),
		FirstOctet:   make([]frontend.Variable, blockBytes),
		WindowActive: make([]frontend.Variable, blockBytes),
	}
}

// Public bit wires as octets. They need no constraint: the verifier computed them.
func publicBytes(bits []frontend.Variable) []circuitByte {
	octets := make([]circuitByte, len(bits)/8)
	for i := range octets {
		copy(octets[i][:], bits[8*i:8*i+8])
	}
	return octets
}

// Private bit wires as octets, each constrained boolean here, once.
func privateBytes(api frontend.API, bits []frontend.Variable) []circuitByte {
	for _, bit := range bits {
		api.AssertIsBoolean(bit)
	}
	return publicBytes(bits)
}

// A direction's keystream source: key material expanded once, then one call per block.
type circuitKeystream struct {
	shape     *partShape
	key       []circuitByte
	iv        []circuitByte
	roundKeys [11][16]circuitByte
}

func newCircuitKeystream(api frontend.API, shape *partShape, key []circuitByte, iv []circuitByte) *circuitKeystream {
	stream := &circuitKeystream{shape: shape, key: key, iv: iv}
	if shape.suite != tlsSuiteChacha20Poly1305Sha256 {
		stream.roundKeys = aesExpandKey(api, key)
	}
	return stream
}

// One block of keystream at a public counter wire (SPEC.md Z2). The nonce is the IV XOR the
// counter's upper 64 bits: 1.3's seq, or in 1.2, whose IV holds only the salt, the explicit nonce.
func (self *circuitKeystream) block(api frontend.API, counter frontend.Variable) []circuitByte {
	counterBytes := bytesOfWire(api, counter, 12)
	nonce := make([]circuitByte, tlsIv13Bytes)
	for i := range nonce {
		for bit := range nonce[i] {
			high := frontend.Variable(uint(0))
			if 4 <= i {
				high = counterBytes[i-4][bit]
			}
			nonce[i][bit] = bitXor(api, self.iv[i][bit], high)
		}
	}
	blockCounter := counterBytes[8:]
	if self.shape.suite == tlsSuiteChacha20Poly1305Sha256 {
		var word circuitWord
		for octet := range 4 {
			copy(word[8*octet:8*octet+8], blockCounter[3-octet][:])
		}
		return chachaBlock(api, self.key, word, nonce)
	}
	return aesEncrypt(api, &self.roundKeys, append(append([]circuitByte{}, nonce...), blockCounter...))
}

// The local part's octets as table coefficients (SPEC.md 4.2).
var localSetCoefficients = newNibbleCoefficients(func(index int) int64 {
	if localOctet(byte(index)) {
		return 1
	}
	return 0
})

// One opened octet.
type openOctet struct {
	value frontend.Variable
	bits  circuitByte
}

// Opens a block's octets: Z2's XOR of ciphertext and keystream.
func openBlock(api frontend.API, stream *circuitKeystream, counter frontend.Variable, cipher []frontend.Variable) []*openOctet {
	keystream := stream.block(api, counter)
	octets := make([]*openOctet, len(cipher))
	for i := range cipher {
		cipherBits := bitsOf(api, cipher[i], 8)
		octet := &openOctet{}
		for bit := range octet.bits {
			octet.bits[bit] = bitXor(api, cipherBits[bit], keystream[i][bit])
		}
		octet.value = byteValue(api, octet.bits)
		octets[i] = octet
	}
	return octets
}

// Whether an octet is in section 4.2's local set, as 0 or 1: 37 constraints.
func localSetMember(api frontend.API, octet *openOctet) frontend.Variable {
	low := nibbleMonomials(api, octet.bits[:4])
	high := nibbleMonomials(api, octet.bits[4:])
	return nibbleEvaluate(api, localSetCoefficients, &high, &low)
}

// Checks a pool of blocks against their templates: Z2's XOR, then Z3 and Z4 by comparison. A
// template is all a pool block is for, so nothing is returned.
func checkPool(api frontend.API, shape *partShape, stream *circuitKeystream, blocks []*poolBlock) {
	for _, block := range blocks {
		for i, octet := range openBlock(api, stream, block.Counter, block.Cipher) {
			api.AssertIsEqual(api.Mul(block.IsLiteral[i], api.Sub(octet.value, block.Literal[i])), 0)
			if shape.localOctets {
				api.AssertIsEqual(api.Mul(block.IsLocal[i], api.Sub(1, localSetMember(api, octet))), 0)
			}
		}
	}
}

// Whether a part needs the server direction: everything but π1 (SPEC.md section 4.3).
func (self *partShape) needsServerKeys() bool {
	return 0 < self.serverBlocks
}

func (self *partCircuit) Define(api frontend.API) error {
	shape := self.shape
	var keys *circuitKeys
	switch {
	case shape.withoutKeySchedule:
		keys = &circuitKeys{
			clientKey: privateBytes(api, self.ClientKey),
			clientIv:  privateBytes(api, self.ClientIv),
			serverKey: privateBytes(api, self.ServerKey),
			serverIv:  privateBytes(api, self.ServerIv),
		}
	case shape.version == tlsVersion13:
		keys = tls13CircuitKeys(api, privateBytes(api, self.HandshakeSecret), publicBytes(self.ShtsHash),
			publicBytes(self.HelloHash), publicBytes(self.FinishedHash), shape.keyBytes(), shape.needsServerKeys())
	default:
		var chaining circuitHashState
		for i := range chaining {
			copy(chaining[i][:], self.Chaining[32*i:32*i+32])
		}
		var serverFinished []circuitByte
		keys, serverFinished = tls12CircuitKeys(api, privateBytes(api, self.MasterSecret), &circuitInputs12{
			clientRandom:       publicBytes(self.ClientRandom),
			serverRandom:       publicBytes(self.ServerRandom),
			clientFinishedHash: publicBytes(self.ClientFinishedHash),
			chaining:           chaining,
			resumeBase:         publicBytes(self.ResumeBase),
			resumeShift:        self.ResumeShift,
			resumeTwoBlocks:    self.ResumeTwoBlocks,
		})
		// SF, opened under the server key this secret gives, is the verify_data it gives the handshake
		opened := openBlock(api, newCircuitKeystream(api, shape, keys.serverKey, keys.serverIv), self.ServerFinished.Counter, self.ServerFinished.Cipher)
		for i, octet := range opened {
			assertBytesEqual(api, []circuitByte{octet.bits}, serverFinished[i:i+1])
		}
	}
	clientStream := newCircuitKeystream(api, shape, keys.clientKey, keys.clientIv)
	checkPool(api, shape, clientStream, self.Client)
	if self.Header != nil {
		checkHeaderBlockCircuit(api, shape, clientStream, self.Header)
	}
	if 0 < len(self.Body) {
		checkBody(api, clientStream, self.Body)
	}
	if shape.needsServerKeys() {
		checkReplies(api, shape, newCircuitKeystream(api, shape, keys.serverKey, keys.serverIv), self)
	} else {
		// no reply here; these public wires are still part of the statement
		api.AssertIsEqual(self.ExpectedReplies, 0)
		api.AssertIsEqual(self.RequireChunking, 0)
		api.AssertIsEqual(self.DataMode, 0)
	}
	return nil
}

// Bits of octets, least significant first, as wire values.
func assignBits(values []byte) []frontend.Variable {
	bits := make([]frontend.Variable, 0, 8*len(values))
	for _, value := range values {
		for i := range 8 {
			bits = append(bits, (value>>i)&1)
		}
	}
	return bits
}

// The public wires of one record's blocks: ciphertext, counters and template, placed from slot on.
// Prover and verifier both call this over the statement alone, so they cannot disagree.
func assignRecordBlocks(shape *partShape, statement *partStatement, record *partRecord, template []templateOctet, slots []*poolBlock) (int, error) {
	ciphertext, err := recordCiphertext(statement.session.version, record.raw)
	if err != nil {
		return 0, err
	}
	if len(ciphertext) != len(template) {
		return 0, errors.New("record does not fit its template")
	}
	counterHigh := record.seq
	if statement.session.version == tlsVersion12 {
		nonce := record.raw[tlsRecordHeaderBytes : tlsRecordHeaderBytes+tlsExplicitNonceBytes]
		counterHigh = 0
		for _, octet := range nonce {
			counterHigh = counterHigh<<8 | uint64(octet)
		}
	}
	blockBytes := shape.blockBytes()
	used := 0
	for offset := 0; offset < len(ciphertext); offset += blockBytes {
		if used == len(slots) {
			return 0, errors.New("records do not fit the shape's blocks")
		}
		slot := slots[used]
		counter := new(big.Int).SetUint64(counterHigh)
		counter.Lsh(counter, 32)
		counter.Add(counter, new(big.Int).SetUint64(shape.firstCounter()+uint64(used)))
		slot.Counter = counter
		for i := range blockBytes {
			if offset+i < len(ciphertext) {
				position := template[offset+i]
				slot.Cipher[i] = ciphertext[offset+i]
				slot.Literal[i] = position.literal
				slot.IsLiteral[i] = 0
				slot.IsLocal[i] = 0
				switch position.kind {
				case templateLiteral:
					slot.IsLiteral[i] = 1
				case templateLocal:
					// a shape without the local table would ignore this wire, and pass any octet
					if !shape.localOctets {
						return 0, errors.New("this shape does not check local octets")
					}
					slot.IsLocal[i] = 1
				}
			}
		}
		used += 1
	}
	return used, nil
}

// A public assignment with everything zero, which an unused block keeps.
func newZeroAssignment(shape *partShape) *partCircuit {
	circuit := newPartCircuit(shape)
	zero := func(wires []frontend.Variable) {
		for i := range wires {
			wires[i] = 0
		}
	}
	for _, block := range circuit.Client {
		block.Counter = 0
		zero(block.Cipher)
		zero(block.Literal)
		zero(block.IsLiteral)
		zero(block.IsLocal)
	}
	for _, block := range circuit.Server {
		block.Counter = 0
		block.Continues = 0
		block.Ticket = 0
		zero(block.Cipher)
		zero(block.Active)
		zero(block.TypeOctet)
		zero(block.FirstOctet)
		zero(block.WindowActive)
	}
	if circuit.Header != nil {
		zeroHeaderScan(circuit.Header)
	}
	for _, block := range circuit.Body {
		zeroBodyBlock(block)
	}
	circuit.ExpectedReplies = 0
	circuit.RequireChunking = 0
	circuit.DataMode = 0
	zero(circuit.ServerKey)
	zero(circuit.ServerIv)
	zero(circuit.ShtsHash)
	zero(circuit.HelloHash)
	zero(circuit.FinishedHash)
	zero(circuit.HandshakeSecret)
	zero(circuit.MasterSecret)
	zero(circuit.ClientRandom)
	zero(circuit.ServerRandom)
	zero(circuit.ClientFinishedHash)
	zero(circuit.Chaining)
	zero(circuit.ResumeBase)
	zero(circuit.ResumeShift)
	circuit.ResumeTwoBlocks = 0
	if circuit.ServerFinished != nil {
		circuit.ServerFinished.Counter = 0
		zero(circuit.ServerFinished.Cipher)
	}
	zero(circuit.ClientKey)
	zero(circuit.ClientIv)
	return circuit
}

// The template of one opened command record, Z3's final octet included.
func clientRecordTemplate(session *sessionStatement, role recordRole, record *partRecord) ([]templateOctet, error) {
	ciphertext, err := recordCiphertext(session.version, record.raw)
	if err != nil {
		return nil, err
	}
	contentBytes := len(ciphertext)
	if session.version == tlsVersion13 {
		contentBytes -= tlsInnerTypeBytes
	}
	template, err := commandTemplate(role, session.preamble, contentBytes)
	if err != nil {
		return nil, err
	}
	if template == nil {
		return nil, fmt.Errorf("role %d has no template", role)
	}
	if session.version == tlsVersion13 {
		template = append(template, templateOctet{kind: templateLiteral, literal: tlsRecordApplicationData})
	}
	return template, nil
}

// The public side of an assignment, from the statement alone.
func partAssignment(shape *partShape, statement *partStatement) (*partCircuit, error) {
	session := statement.session
	circuit := newZeroAssignment(shape)
	if session.version == tlsVersion13 {
		circuit.ShtsHash = assignBits(session.shtsHash)
		circuit.HelloHash = assignBits(session.helloHash)
		circuit.FinishedHash = assignBits(session.finishedHash)
	} else if err := assignHandshake12(shape, statement, circuit); err != nil {
		return nil, err
	}
	roles, err := partRoles(statement)
	if err != nil {
		return nil, err
	}
	slot := 0
	bodySlot := 0
	for i, role := range roles {
		record := statement.clientRecords[i]
		switch role {
		case recordRoleHeaderBlock:
			if circuit.Header == nil {
				return nil, errors.New("this shape has no header block")
			}
			if err := assignHeaderPublic(shape, statement, record, circuit.Header); err != nil {
				return nil, err
			}
		case recordRoleBody:
			used, err := assignBodyRecord(shape, statement, record, circuit.Body[bodySlot:])
			if err != nil {
				return nil, err
			}
			bodySlot += used
		default:
			template, err := clientRecordTemplate(session, role, record)
			if err != nil {
				return nil, err
			}
			used, err := assignRecordBlocks(shape, statement, record, template, circuit.Client[slot:])
			if err != nil {
				return nil, err
			}
			slot += used
		}
	}
	if err := assignServerRecords(shape, statement, circuit); err != nil {
		return nil, err
	}
	switch {
	case statement.index == 2:
		circuit.ExpectedReplies = 1
		if statement.mode == partModeBdat {
			circuit.RequireChunking = 1
		}
	case statement.index == 3:
		replies := 1 + int(session.preamble.recipientCount)
		if statement.mode == partModeData {
			replies += 1
			circuit.DataMode = 1
		}
		circuit.ExpectedReplies = replies
	}
	return circuit, nil
}

// Z1's public wires for TLS 1.2.
func assignHandshake12(shape *partShape, statement *partStatement, circuit *partCircuit) error {
	session := statement.session
	state := session.preFinishedState
	circuit.ClientRandom = assignBits(session.clientRandom)
	circuit.ServerRandom = assignBits(session.serverRandom)
	clientHash, err := state.finish(nil)
	if err != nil {
		return err
	}
	circuit.ClientFinishedHash = assignBits(clientHash)
	for i, word := range state.chaining {
		for bit := range 32 {
			circuit.Chaining[32*i+bit] = (word >> bit) & 1
		}
	}
	// the tail, a gap for the 16-octet client Finished, then SHA-256's padding
	const clientFinishedBytes = 4 + tlsVerifyData12Bytes
	tailBytes := len(state.tail)
	padded := make([]byte, 0, 2*sha256BlockBytes)
	padded = append(padded, state.tail...)
	padded = append(padded, make([]byte, clientFinishedBytes)...)
	padded = append(padded, 0x80)
	twoBlocks := sha256BlockBytes-8 < len(padded)
	for len(padded)%sha256BlockBytes != sha256BlockBytes-8 {
		padded = append(padded, 0)
	}
	padded = binary.BigEndian.AppendUint64(padded, (state.length+clientFinishedBytes)*8)
	padded = append(padded, make([]byte, 2*sha256BlockBytes-len(padded))...)
	circuit.ResumeBase = assignBits(padded)
	for bit := range circuit.ResumeShift {
		circuit.ResumeShift[bit] = (tailBytes >> bit) & 1
	}
	circuit.ResumeTwoBlocks = 0
	if twoBlocks {
		circuit.ResumeTwoBlocks = 1
	}
	// SF's opened octets, as a one-block record with no template of its own
	record := &partRecord{raw: session.serverFinishedRecord}
	template := make([]templateOctet, 4+tlsVerifyData12Bytes)
	block := newPoolBlock(shape.blockBytes())
	if _, err := assignRecordBlocks(shape, statement, record, template, []*poolBlock{block}); err != nil {
		return err
	}
	circuit.ServerFinished.Counter = block.Counter
	copy(circuit.ServerFinished.Cipher, block.Cipher)
	return nil
}

// The private side, added to a public assignment. A shape that needs no server keys still has wires
// for them, which stay zero.
func assignWitness(circuit *partCircuit, statement *partStatement, witness *partWitness) {
	if statement.session.version == tlsVersion13 {
		circuit.HandshakeSecret = assignBits(witness.handshakeSecret)
	} else {
		circuit.MasterSecret = assignBits(witness.masterSecret)
	}
	if circuit.shape.withoutKeySchedule {
		// the IV wires hold 12 octets; a 1.2 salt fills the first 4
		padded := func(iv []byte) []frontend.Variable {
			return assignBits(append(bytes.Clone(iv), make([]byte, tlsIv13Bytes-len(iv))...))
		}
		circuit.ClientKey = assignBits(witness.clientKey)
		circuit.ClientIv = padded(witness.clientIv)
		// a test shape's wires exist whether or not it opens a server record
		if 0 < len(witness.serverKey) {
			circuit.ServerKey = assignBits(witness.serverKey)
			circuit.ServerIv = padded(witness.serverIv)
		}
	}
	if circuit.Header != nil {
		roles, err := partRoles(statement)
		if err == nil {
			for i, role := range roles {
				if role == recordRoleHeaderBlock && i < len(witness.clientPlaintexts) {
					assignHeaderPrivate(circuit.Header, statement.session.preamble, witness.clientPlaintexts[i])
				}
			}
		}
	}
	// each block of a ticket's record carries the record's private kind
	slot := 0
	for _, plaintext := range witness.serverPlaintexts {
		ticket := 0
		if statement.session.version == tlsVersion13 && 0 < len(plaintext) && plaintext[len(plaintext)-1] == tlsRecordHandshake {
			ticket = 1
		}
		blockCount := (len(plaintext) + circuit.shape.blockBytes() - 1) / circuit.shape.blockBytes()
		for range blockCount {
			if slot < len(circuit.Server) {
				circuit.Server[slot].Ticket = ticket
			}
			slot += 1
		}
	}
}
