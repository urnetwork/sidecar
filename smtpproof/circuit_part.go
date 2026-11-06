package smtpproof

import (
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
)

// A compiled circuit's fixed dimensions. A statement fits a shape if its records fit its blocks.
type partShape struct {
	kind         partKind
	version      uint16
	suite        uint16
	clientBlocks int
	// Server keystream blocks, which hold the replies the part covers (Z7, Z8).
	serverBlocks int
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

// The circuit. Sized by its shape, which every instance of a compiled circuit shares.
type partCircuit struct {
	shape *partShape

	// 1.3: H_shts, H_sh, H_sf as bits.
	ShtsHash     []frontend.Variable `gnark:",public"`
	HelloHash    []frontend.Variable `gnark:",public"`
	FinishedHash []frontend.Variable `gnark:",public"`
	Client       []*poolBlock
	Server       []*serverBlock
	// How many replies the part's server records must hold in all (Z8).
	ExpectedReplies frontend.Variable `gnark:",public"`
	// 1 if the EHLO reply must offer CHUNKING (Z9).
	RequireChunking frontend.Variable `gnark:",public"`

	// 1.3: HS, in bits.
	HandshakeSecret []frontend.Variable
	// When a test shape leaves Z1 out, the keys themselves.
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
	circuit := &partCircuit{
		shape:           shape,
		ShtsHash:        make([]frontend.Variable, 8*tlsSecretBytes),
		HelloHash:       make([]frontend.Variable, 8*tlsSecretBytes),
		FinishedHash:    make([]frontend.Variable, 8*tlsSecretBytes),
		HandshakeSecret: make([]frontend.Variable, 8*tlsSecretBytes),
		ClientKey:       make([]frontend.Variable, 8*shape.keyBytes()),
		ClientIv:        make([]frontend.Variable, 8*tlsIv13Bytes),
		ServerKey:       make([]frontend.Variable, 8*shape.keyBytes()),
		ServerIv:        make([]frontend.Variable, 8*tlsIv13Bytes),
	}
	for range shape.clientBlocks {
		circuit.Client = append(circuit.Client, newPoolBlock(shape.blockBytes()))
	}
	for range shape.serverBlocks {
		circuit.Server = append(circuit.Server, newServerBlock(shape.blockBytes()))
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

// Checks a pool of blocks against their templates: Z2's XOR, then Z3 and Z4 by comparison. Returns
// nothing: a template is all a pool block is for.
func checkPool(api frontend.API, shape *partShape, stream *circuitKeystream, blocks []*poolBlock) {
	for _, block := range blocks {
		keystream := stream.block(api, block.Counter)
		for i := range block.Cipher {
			cipherBits := bitsOf(api, block.Cipher[i], 8)
			var plaintext circuitByte
			for bit := range plaintext {
				plaintext[bit] = bitXor(api, cipherBits[bit], keystream[i][bit])
			}
			value := byteValue(api, plaintext)
			api.AssertIsEqual(api.Mul(block.IsLiteral[i], api.Sub(value, block.Literal[i])), 0)
			if shape.localOctets {
				low := nibbleMonomials(api, plaintext[:4])
				high := nibbleMonomials(api, plaintext[4:])
				inSet := nibbleEvaluate(api, localSetCoefficients, &high, &low)
				api.AssertIsEqual(api.Mul(block.IsLocal[i], api.Sub(1, inSet)), 0)
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
	assertBooleans := func(sets ...[]frontend.Variable) {
		for _, bits := range sets {
			for _, bit := range bits {
				api.AssertIsBoolean(bit)
			}
		}
	}
	var keys *circuitKeys
	if shape.withoutKeySchedule {
		keys = &circuitKeys{
			clientKey: privateBytes(api, self.ClientKey),
			clientIv:  privateBytes(api, self.ClientIv),
			serverKey: privateBytes(api, self.ServerKey),
			serverIv:  privateBytes(api, self.ServerIv),
		}
		// wires this test shape leaves unused still need a constraint each, or compiling refuses them
		assertBooleans(self.HandshakeSecret, self.ShtsHash, self.HelloHash, self.FinishedHash)
	} else {
		keys = tls13CircuitKeys(api, privateBytes(api, self.HandshakeSecret), publicBytes(self.ShtsHash),
			publicBytes(self.HelloHash), publicBytes(self.FinishedHash), shape.keyBytes(), shape.needsServerKeys())
		assertBooleans(self.ClientKey, self.ClientIv, self.ServerKey, self.ServerIv)
	}
	checkPool(api, shape, newCircuitKeystream(api, shape, keys.clientKey, keys.clientIv), self.Client)
	if shape.needsServerKeys() {
		checkReplies(api, shape, newCircuitKeystream(api, shape, keys.serverKey, keys.serverIv), self)
	} else {
		// π1 covers no reply; these public wires are still part of its statement
		api.AssertIsEqual(self.ExpectedReplies, 0)
		api.AssertIsEqual(self.RequireChunking, 0)
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
	circuit.ExpectedReplies = 0
	circuit.RequireChunking = 0
	zero(circuit.ServerKey)
	zero(circuit.ServerIv)
	zero(circuit.ShtsHash)
	zero(circuit.HelloHash)
	zero(circuit.FinishedHash)
	zero(circuit.HandshakeSecret)
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
	circuit.ShtsHash = assignBits(session.shtsHash)
	circuit.HelloHash = assignBits(session.helloHash)
	circuit.FinishedHash = assignBits(session.finishedHash)
	roles, err := partRoles(statement)
	if err != nil {
		return nil, err
	}
	slot := 0
	for i, role := range roles {
		template, err := clientRecordTemplate(session, role, statement.clientRecords[i])
		if err != nil {
			return nil, err
		}
		used, err := assignRecordBlocks(shape, statement, statement.clientRecords[i], template, circuit.Client[slot:])
		if err != nil {
			return nil, err
		}
		slot += used
	}
	if err := assignServerRecords(shape, statement, circuit); err != nil {
		return nil, err
	}
	switch statement.index {
	case 2:
		circuit.ExpectedReplies = 1
		if statement.mode == partModeBdat {
			circuit.RequireChunking = 1
		}
	}
	return circuit, nil
}

// The private side, added to a public assignment. A shape that needs no server keys still has wires
// for them, which stay zero.
func assignWitness(circuit *partCircuit, statement *partStatement, witness *partWitness) {
	circuit.HandshakeSecret = assignBits(witness.handshakeSecret)
	circuit.ClientKey = assignBits(witness.clientKey)
	circuit.ClientIv = assignBits(witness.clientIv)
	if circuit.shape.needsServerKeys() {
		circuit.ServerKey = assignBits(witness.serverKey)
		circuit.ServerIv = assignBits(witness.serverIv)
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
