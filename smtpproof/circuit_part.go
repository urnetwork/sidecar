package smtpproof

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// The circuit of one part (SPEC.md sections 5 and 7; DESIGN-DETAILS 3.2.3 and 3.2.6): Z1 in the key part,
// the opening of its commitment everywhere else, then a pool of keystream blocks of the part's kind.
//
// Z1 runs in two steps. The key part, part 1, derives both directions' keys and IVs from the private
// handshake secret (1.3) or master secret (1.2) under the edge's handshake inputs, and asserts that the
// public KeyCommitment C commits to exactly those wires under a private blind. Every later part takes the
// keys, IVs and blind as private wires, asserts that they open the same C, which the edge supplies from
// the key part and never from the part itself, and runs its keystreams from them.
//
// A part opens records of one kind (DESIGN-DETAILS 3.2.5): the key part EHLO; an env part a group of
// envelope commands, or none, with the replies the server records it covers hold; the msg part BDAT's
// command and the header block's first record, with the envelope's last replies; a hdr part one later
// header record; a body part one DATA body record. QUIT rides the last part, and DATA's end mark a body
// part. A scan crossing records takes its state from the gate's carry and publishes the state it leaves.
//
// A record's offsets are functions of public lengths, so the circuit holds no command grammar: the edge
// computes a position template for every opened command octet and the circuit only compares (Z2-Z4).
// A block carries its own public counter, so one shape serves any mix of records that fits it. Nothing
// but the key shape depends on the TLS version: a family's circuits serve 1.3 and 1.2 alike, the
// differences being public wires the edge assigns (3.2.3).
//
// Public wires need no booleanity constraints: the verifier computes them, and they are a fixed function
// of the statement (partAssignment). A dishonest prover cannot change them.

// Which part a shape proves.
type partKind uint8

const (
	// Part 1, the key part: Z1 and the EHLO record.
	partKindKey partKind = iota + 1
	// A group of envelope commands, or none, and the replies to what came before.
	partKindEnvelope
	// BDAT's command (BDAT mode) and the header block's first record, with the envelope's last replies.
	partKindMessage
	// One later header record.
	partKindHeader
	// One DATA body record, and on the last part the end mark.
	partKindBody
)

// A compiled circuit's fixed dimensions. A statement fits a shape if its records fit its blocks.
type partShape struct {
	kind   partKind
	family ShapeFamily
	// A key shape's TLS version. 0 on every other kind, whose circuit serves both.
	version uint16
	// Command records, and BDAT's command, QUIT and the end mark.
	clientBlocks int
	// Server keystream blocks, which hold the replies the part covers (Z7, Z8).
	serverBlocks int
	// The header block's first record (msg), a later one (hdr), a DATA body record (body).
	headBlocks int
	restBlocks int
	bodyBlocks int
	// Whether the client pool's template can hold a local part. Only an env pool can, which saves the
	// table per octet everywhere else.
	localOctets bool
	// ProofSettings' values the circuit is sized or bounded by: the literal forms' capacities, the
	// interval between pinned sums, and RFC 5321's local part.
	literalLineBytes    int
	literalAddressBytes int
	literalTagBytes     int
	pinInterval         int
	localMaxBytes       int
	// Leaves Z1's derivation out of a key part, so tests can run every other check quickly over keys given
	// as a witness, opened against C as a later part's are. No catalog shape is such a shape, and
	// TestProductionShapesProveZ1 keeps it that way.
	withoutKeySchedule bool
}

// The circuit shape of a catalog entry, under the settings it belongs to.
func newPartShape(proof *ProofSettings, entry *ShapeSettings) *partShape {
	shape := &partShape{
		family:              entry.Family,
		version:             entry.Version,
		clientBlocks:        entry.ClientBlocks,
		serverBlocks:        entry.ServerBlocks,
		headBlocks:          entry.HeadBlocks,
		restBlocks:          entry.RestBlocks,
		bodyBlocks:          entry.BodyBlocks,
		localOctets:         entry.Locals,
		literalLineBytes:    proof.LiteralLineMaxByteCount,
		literalAddressBytes: proof.LiteralAddressMaxByteCount,
		literalTagBytes:     proof.LiteralTagMaxByteCount,
		pinInterval:         proof.ScanPinInterval,
		localMaxBytes:       proof.LocalMaxByteCount,
	}
	switch entry.Kind {
	case ShapeKindKey:
		shape.kind = partKindKey
	case ShapeKindEnvelope:
		shape.kind = partKindEnvelope
	case ShapeKindMessage:
		shape.kind = partKindMessage
	case ShapeKindHeader:
		shape.kind = partKindHeader
	case ShapeKindBody:
		shape.kind = partKindBody
	}
	return shape
}

// The catalog entry a shape is, which names it.
func (self *partShape) entry() *ShapeSettings {
	entry := &ShapeSettings{
		Family:       self.family,
		Version:      self.version,
		ClientBlocks: self.clientBlocks,
		ServerBlocks: self.serverBlocks,
		HeadBlocks:   self.headBlocks,
		RestBlocks:   self.restBlocks,
		BodyBlocks:   self.bodyBlocks,
		Locals:       self.localOctets,
	}
	switch self.kind {
	case partKindKey:
		entry.Kind = ShapeKindKey
	case partKindEnvelope:
		entry.Kind = ShapeKindEnvelope
	case partKindMessage:
		entry.Kind = ShapeKindMessage
	case partKindHeader:
		entry.Kind = ShapeKindHeader
	case partKindBody:
		entry.Kind = ShapeKindBody
	}
	return entry
}

// Whether the circuit derives the keys from the handshake (Z1's first step), rather than taking them as
// private wires that open C (its second).
func (self *partShape) derivesKeys() bool {
	return self.kind == partKindKey && !self.withoutKeySchedule
}

// The octets one keystream block covers.
func (self *partShape) blockBytes() int {
	if self.family == ShapeFamilyChacha20 {
		return 64
	}
	return 16
}

func (self *partShape) keyBytes() int {
	if self.family == ShapeFamilyChacha20 {
		return tlsChachaKeyBytes
	}
	return tlsAes128KeyBytes
}

// The family's first keystream block index: AES-GCM's counter starts at 2 for data, ChaCha20's at 1.
func (self *partShape) firstCounter() uint64 {
	if self.family == ShapeFamilyChacha20 {
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
	// Only on a block that can hold a local part, an env shape's client blocks: a public wire no
	// constraint reads would verify at any value (SPEC.md 5.1).
	IsLocal []frontend.Variable `gnark:",public"`
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
	// The 16 octets from here are all content of one record, so a keyword can match at it unless that
	// record is a ticket.
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

// The circuit. Sized by its shape, which every instance of a compiled circuit shares. A wire a shape does
// not use is an empty slice or a nil pointer, which gnark counts as none.
type partCircuit struct {
	shape *partShape

	// The key part's alone. 1.3: H_shts, H_sh, H_sf as bits.
	ShtsHash     []frontend.Variable `gnark:",public"`
	HelloHash    []frontend.Variable `gnark:",public"`
	FinishedHash []frontend.Variable `gnark:",public"`
	// The key part's alone. 1.2: Z1's public inputs, and SF as the record the edge relayed.
	ClientRandom       []frontend.Variable `gnark:",public"`
	ServerRandom       []frontend.Variable `gnark:",public"`
	ClientFinishedHash []frontend.Variable `gnark:",public"`
	Chaining           []frontend.Variable `gnark:",public"`
	ResumeBase         []frontend.Variable `gnark:",public"`
	ResumeShift        []frontend.Variable `gnark:",public"`
	// One wire.
	ResumeTwoBlocks []frontend.Variable `gnark:",public"`
	ServerFinished  *serverFinishedBlock
	// C, x then y: what the key part publishes, and what the edge supplies to every later part
	// (DESIGN-DETAILS 3.2.2).
	KeyCommitment []frontend.Variable `gnark:",public"`
	Client        []*poolBlock
	Server        []*serverBlock
	// msg: the header block's first record. hdr: a later one.
	Head *headerRecordScan
	Rest *headerRecordScan
	// body: one DATA body record.
	Body *bodyRecordScan
	// hdr and body: the gate's carry, x then y, which the part opens to the state it starts from.
	CarryIn []frontend.Variable `gnark:",public"`
	// msg, hdr and body: the part's own carry, of the state it leaves.
	CarryOut []frontend.Variable `gnark:",public"`
	// env and msg: the replies' count and the rules they are read by.
	Flags *replyFlags

	// The key part: HS (1.3) or the master secret (1.2), in bits.
	HandshakeSecret []frontend.Variable
	MasterSecret    []frontend.Variable
	// Every later part, and a test's key part without Z1's derivation: the keys and IVs, in bits. An IV
	// is 12 octets, a 1.2 salt followed by 8 zero octets as the key part committed it.
	ClientKey []frontend.Variable
	ClientIv  []frontend.Variable
	ServerKey []frontend.Variable
	ServerIv  []frontend.Variable
	// rho, C's blind, in 251 bits.
	KeyBlind []frontend.Variable
	// hdr: the state CarryIn opens to, its scanUsedBits bits; body: its pos bits, the rest being zero.
	CarryInState []frontend.Variable
	// The blinds of CarryIn and CarryOut, 251 bits each.
	CarryInBlind  []frontend.Variable
	CarryOutBlind []frontend.Variable
}

func newPoolBlock(blockBytes int, local bool) *poolBlock {
	block := &poolBlock{
		Cipher:    make([]frontend.Variable, blockBytes),
		Literal:   make([]frontend.Variable, blockBytes),
		IsLiteral: make([]frontend.Variable, blockBytes),
	}
	if local {
		block.IsLocal = make([]frontend.Variable, blockBytes)
	}
	return block
}

func newPartCircuit(shape *partShape) *partCircuit {
	circuit := &partCircuit{shape: shape}
	circuit.KeyCommitment = make([]frontend.Variable, 2)
	circuit.KeyBlind = make([]frontend.Variable, commitBlindBits)
	if !shape.derivesKeys() {
		circuit.ClientKey = make([]frontend.Variable, 8*shape.keyBytes())
		circuit.ClientIv = make([]frontend.Variable, 8*tlsIv13Bytes)
		circuit.ServerKey = make([]frontend.Variable, 8*shape.keyBytes())
		circuit.ServerIv = make([]frontend.Variable, 8*tlsIv13Bytes)
	}
	switch {
	case !shape.derivesKeys():
	case shape.version == tlsVersion13:
		circuit.ShtsHash = make([]frontend.Variable, 8*tlsSecretBytes)
		circuit.HelloHash = make([]frontend.Variable, 8*tlsSecretBytes)
		circuit.FinishedHash = make([]frontend.Variable, 8*tlsSecretBytes)
		circuit.HandshakeSecret = make([]frontend.Variable, 8*tlsSecretBytes)
	default:
		circuit.ClientRandom = make([]frontend.Variable, 8*tlsRandomBytes)
		circuit.ServerRandom = make([]frontend.Variable, 8*tlsRandomBytes)
		circuit.ClientFinishedHash = make([]frontend.Variable, 8*tlsSecretBytes)
		circuit.Chaining = make([]frontend.Variable, 8*tlsSecretBytes)
		circuit.ResumeBase = make([]frontend.Variable, 8*2*sha256BlockBytes)
		circuit.ResumeShift = make([]frontend.Variable, 6)
		circuit.ResumeTwoBlocks = make([]frontend.Variable, 1)
		circuit.ServerFinished = &serverFinishedBlock{Cipher: make([]frontend.Variable, shape.blockBytes())}
		circuit.MasterSecret = make([]frontend.Variable, 8*tlsMasterSecretBytes)
	}
	for range shape.clientBlocks {
		circuit.Client = append(circuit.Client, newPoolBlock(shape.blockBytes(), shape.localOctets))
	}
	for range shape.serverBlocks {
		circuit.Server = append(circuit.Server, newServerBlock(shape.blockBytes()))
	}
	if 0 < shape.serverBlocks {
		circuit.Flags = &replyFlags{}
	}
	if 0 < shape.headBlocks {
		circuit.Head = newHeaderRecordScan(shape, shape.headBlocks, true)
	}
	if 0 < shape.restBlocks {
		circuit.Rest = newHeaderRecordScan(shape, shape.restBlocks, false)
		circuit.CarryInState = make([]frontend.Variable, scanUsedBits)
	}
	if 0 < shape.bodyBlocks {
		circuit.Body = newBodyRecordScan(shape)
		circuit.CarryInState = make([]frontend.Variable, scanPosBits)
	}
	if circuit.Rest != nil || circuit.Body != nil {
		circuit.CarryIn = make([]frontend.Variable, 2)
		circuit.CarryInBlind = make([]frontend.Variable, commitBlindBits)
	}
	if circuit.Head != nil || circuit.Rest != nil || circuit.Body != nil {
		circuit.CarryOut = make([]frontend.Variable, 2)
		circuit.CarryOutBlind = make([]frontend.Variable, commitBlindBits)
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
	if shape.family != ShapeFamilyChacha20 {
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
	if self.shape.family == ShapeFamilyChacha20 {
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

func (self *partCircuit) Define(api frontend.API) error {
	shape := self.shape
	var keys *circuitKeys
	switch {
	case !shape.derivesKeys():
		keys = &circuitKeys{
			clientKey: privateBytes(api, self.ClientKey),
			clientIv:  privateBytes(api, self.ClientIv),
			serverKey: privateBytes(api, self.ServerKey),
			serverIv:  privateBytes(api, self.ServerIv),
		}
	case shape.version == tlsVersion13:
		// the key part derives both directions always, since C commits to both
		keys = tls13CircuitKeys(api, privateBytes(api, self.HandshakeSecret), publicBytes(self.ShtsHash),
			publicBytes(self.HelloHash), publicBytes(self.FinishedHash), shape.keyBytes(), true)
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
			resumeTwoBlocks:    self.ResumeTwoBlocks[0],
		})
		// SF, opened under the server key this secret gives, is the verify_data it gives the handshake
		opened := openBlock(api, newCircuitKeystream(api, shape, keys.serverKey, keys.serverIv), self.ServerFinished.Counter, self.ServerFinished.Cipher)
		for i, octet := range opened {
			assertBytesEqual(api, []circuitByte{octet.bits}, serverFinished[i:i+1])
		}
	}
	// Z1's commitment: the key part's derived wires, or a later part's private ones, under rho open C
	keyGenerators, _ := commitGeneratorSets()
	assertCommitment(api, keyGenerators, commitCircuitBits(keys.clientKey, keys.clientIv, keys.serverKey, keys.serverIv), privateBlindBits(api, self.KeyBlind), self.KeyCommitment)
	clientStream := newCircuitKeystream(api, shape, keys.clientKey, keys.clientIv)
	checkPool(api, shape, clientStream, self.Client)
	switch {
	case self.Head != nil:
		// header record 1 starts from the start state, a constant inside the circuit
		out := checkHeaderRecordCircuit(api, shape, clientStream, self.Head, newCircuitScanStateConstant(scanStart))
		assertCarry(api, out, privateBlindBits(api, self.CarryOutBlind), self.CarryOut)
	case self.Rest != nil:
		in := newCircuitScanStateWires(api, self.CarryInState)
		assertCarry(api, in, privateBlindBits(api, self.CarryInBlind), self.CarryIn)
		out := checkHeaderRecordCircuit(api, shape, clientStream, self.Rest, in)
		assertCarry(api, out, privateBlindBits(api, self.CarryOutBlind), self.CarryOut)
	case self.Body != nil:
		in := newCircuitScanStatePos(api, self.CarryInState)
		assertCarry(api, in, privateBlindBits(api, self.CarryInBlind), self.CarryIn)
		out := checkBodyRecordCircuit(api, clientStream, self.Body, in)
		assertCarry(api, out, privateBlindBits(api, self.CarryOutBlind), self.CarryOut)
	}
	if self.Flags != nil {
		checkReplies(api, shape, newCircuitKeystream(api, shape, keys.serverKey, keys.serverIv), self)
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
				if slot.IsLocal != nil {
					slot.IsLocal[i] = 0
				}
				switch position.kind {
				case templateLiteral:
					slot.IsLiteral[i] = 1
				case templateLocal:
					// a block without the local table has no wire for this, and would pass any octet
					if !shape.localOctets || slot.IsLocal == nil {
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

// An assignment with everything zero, which an unused block keeps.
func newZeroAssignment(shape *partShape) *partCircuit {
	circuit := newPartCircuit(shape)
	zero := func(wires []frontend.Variable) {
		for i := range wires {
			wires[i] = 0
		}
	}
	for _, block := range circuit.Client {
		zeroPoolBlock(block)
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
	for _, scan := range []*headerRecordScan{circuit.Head, circuit.Rest} {
		if scan != nil {
			zeroHeaderRecordScan(scan)
		}
	}
	if circuit.Body != nil {
		zeroBodyRecordScan(circuit.Body)
	}
	if circuit.Flags != nil {
		circuit.Flags.ReplyCount = 0
		circuit.Flags.EhloRule = 0
		circuit.Flags.RequireChunking = 0
		circuit.Flags.Last354 = 0
		circuit.Flags.Tls13 = 0
	}
	if circuit.ServerFinished != nil {
		circuit.ServerFinished.Counter = 0
		zero(circuit.ServerFinished.Cipher)
	}
	for _, wires := range [][]frontend.Variable{
		circuit.ShtsHash, circuit.HelloHash, circuit.FinishedHash, circuit.ClientRandom, circuit.ServerRandom,
		circuit.ClientFinishedHash, circuit.Chaining, circuit.ResumeBase, circuit.ResumeShift, circuit.ResumeTwoBlocks,
		circuit.KeyCommitment, circuit.CarryIn, circuit.CarryOut, circuit.HandshakeSecret, circuit.MasterSecret,
		circuit.ClientKey, circuit.ClientIv, circuit.ServerKey, circuit.ServerIv, circuit.KeyBlind,
		circuit.CarryInState, circuit.CarryInBlind, circuit.CarryOutBlind,
	} {
		zero(wires)
	}
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

// The public side of an assignment, from the statement alone. It fails for a statement the shape does
// not hold: another kind or family, more records than its blocks, a server record where it has none.
func partAssignment(shape *partShape, statement *partStatement) (*partCircuit, error) {
	session := statement.session
	if suiteFamily(session.suite) != shape.family {
		return nil, errors.New("a shape of another family")
	}
	if shape.kind == partKindKey && shape.version != session.version {
		return nil, errors.New("a key shape of another version")
	}
	roles, err := partRoles(statement)
	if err != nil {
		return nil, err
	}
	kind, err := partKindOf(statement, roles)
	if err != nil {
		return nil, err
	}
	if kind != shape.kind {
		return nil, fmt.Errorf("a part of kind %d under a shape of kind %d", kind, shape.kind)
	}
	circuit := newZeroAssignment(shape)
	switch {
	case !shape.derivesKeys():
	case session.version == tlsVersion13:
		circuit.ShtsHash = assignBits(session.shtsHash)
		circuit.HelloHash = assignBits(session.helloHash)
		circuit.FinishedHash = assignBits(session.finishedHash)
	default:
		if err := assignHandshake12(shape, statement, circuit); err != nil {
			return nil, err
		}
	}
	// the statement's C: the key part's own, or the one the edge kept from it
	if circuit.KeyCommitment, err = assignCommitment(statement.keyCommitment); err != nil {
		return nil, err
	}
	slot := 0
	for i, role := range roles {
		record := statement.clientRecords[i]
		switch role {
		case recordRoleHeaderBlock:
			ordinal := headerOrdinal(statement, record.seq)
			scan := circuit.Rest
			if ordinal == 1 {
				scan = circuit.Head
			}
			if scan == nil {
				return nil, errors.New("this shape holds no such header record")
			}
			if err := assignHeaderRecordPublic(shape, statement, record, scan, ordinal == int(statement.headerRecordCount)); err != nil {
				return nil, err
			}
		case recordRoleBody:
			if circuit.Body == nil {
				return nil, errors.New("this shape holds no body record")
			}
			if err := assignBodyRecordPublic(shape, statement, record, circuit.Body, statement.last); err != nil {
				return nil, err
			}
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
	if circuit.CarryIn != nil {
		if circuit.CarryIn, err = assignCommitment(statement.carryIn); err != nil {
			return nil, fmt.Errorf("the carry in: %w", err)
		}
	}
	if circuit.CarryOut != nil {
		if circuit.CarryOut, err = assignCommitment(statement.carryOut); err != nil {
			return nil, fmt.Errorf("the carry out: %w", err)
		}
	}
	if circuit.Flags == nil {
		if 0 < len(statement.serverRecords) || statement.replyCount != 0 {
			return nil, errors.New("this shape covers no server record")
		}
		return circuit, nil
	}
	if err := assignServerRecords(shape, statement, circuit); err != nil {
		return nil, err
	}
	flags := circuit.Flags
	flags.ReplyCount = statement.replyCount
	if statement.ehloRule() {
		flags.EhloRule = 1
	}
	if statement.requireChunking() {
		flags.RequireChunking = 1
	}
	if statement.last354() {
		flags.Last354 = 1
	}
	if session.version == tlsVersion13 {
		flags.Tls13 = 1
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
	circuit.ResumeTwoBlocks[0] = 0
	if twoBlocks {
		circuit.ResumeTwoBlocks[0] = 1
	}
	// SF's opened octets, as a one-block record with no template of its own
	record := &partRecord{raw: session.serverFinishedRecord}
	template := make([]templateOctet, 4+tlsVerifyData12Bytes)
	block := newPoolBlock(shape.blockBytes(), false)
	if _, err := assignRecordBlocks(shape, statement, record, template, []*poolBlock{block}); err != nil {
		return err
	}
	circuit.ServerFinished.Counter = block.Counter
	copy(circuit.ServerFinished.Cipher, block.Cipher)
	return nil
}

// A blind's 251 bits, or zeros for none, which no commitment opens to. A shape without the wires takes
// none.
func assignBlindBits(wires []frontend.Variable, blind *big.Int) {
	if len(wires) != commitBlindBits || blind == nil || blind.Sign() < 0 || commitBlindBits < blind.BitLen() {
		return
	}
	for i, bit := range commitBlindBitsOf(blind) {
		wires[i] = bit
	}
}

// The private side, added to a public assignment.
func assignWitness(circuit *partCircuit, statement *partStatement, witness *partWitness) {
	assignBlindBits(circuit.KeyBlind, witness.keyBlind)
	switch {
	case !circuit.shape.derivesKeys():
		// the IV wires hold 12 octets; a 1.2 salt fills the first 4, the rest zero as C holds it
		padded := func(iv []byte) []frontend.Variable {
			return assignBits(append(bytes.Clone(iv), make([]byte, max(tlsIv13Bytes-len(iv), 0))...))
		}
		if len(witness.clientKey) == circuit.shape.keyBytes() && len(witness.serverKey) == circuit.shape.keyBytes() &&
			len(witness.clientIv) <= tlsIv13Bytes && len(witness.serverIv) <= tlsIv13Bytes {
			circuit.ClientKey = assignBits(witness.clientKey)
			circuit.ClientIv = padded(witness.clientIv)
			circuit.ServerKey = assignBits(witness.serverKey)
			circuit.ServerIv = padded(witness.serverIv)
		}
	case statement.session.version == tlsVersion13:
		circuit.HandshakeSecret = assignBits(witness.handshakeSecret)
	default:
		circuit.MasterSecret = assignBits(witness.masterSecret)
	}
	if circuit.Head != nil {
		if roles, err := partRoles(statement); err == nil {
			for i, role := range roles {
				if role == recordRoleHeaderBlock && i < len(witness.clientPlaintexts) {
					assignHeaderPrivate(circuit.Head, witness.clientPlaintexts[i])
				}
			}
		}
	}
	for i := range circuit.CarryInState {
		circuit.CarryInState[i] = (uint32(witness.carryInState) >> i) & 1
	}
	assignBlindBits(circuit.CarryInBlind, witness.carryInBlind)
	assignBlindBits(circuit.CarryOutBlind, witness.carryOutBlind)
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
