//go:build !js

// record_seal.go's sealing and opening: golden sealed entries in testdata/record/sealed.json, checked both by sealing
// them again from their inputs and from the file's own bytes; a key, salt, nonce and entry_id drawn per entry; a body
// that opens only under its own key, log and entry, and only when its salt commits to it; the refusals a header and
// body hold before anything is drawn or signed; and the identity key signing every header alone. The js leg opens no
// files, so these stay off it.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var updateRecordSealed = flag.Bool("update-record-sealed", false, "rewrite testdata/record/sealed.json")

const testRecordSealedPath = "testdata/record/sealed.json"

// RecordSealEnv.Sign takes Sidecar.Sign as it is.
var _ func(string, bridge.SignedType, []byte, *Id) (*bridge.Signed, error) = (&Sidecar{}).Sign

// What Sidecar.Sign makes, with a test's key: §6.9's Signed by the identity key, signer_id the sidecar's id.
func testRecordSigner(sidecarId Id, key ed25519.PrivateKey) func(string, bridge.SignedType, []byte, *Id) (*bridge.Signed, error) {
	return func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body:      bytes.Clone(body),
			SignerId:  sidecarId.Bytes(),
			Signature: ed25519.Sign(key, bridge.SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		}, nil
	}
}

// The record component's directory of a fresh, unlocked network on a memory medium.
func testRecordStore(t *testing.T) SidecarStore {
	t.Helper()
	instance, _, _ := enrolledInstance(t)
	return storeOf(t, instance, testNetworkId, "record")
}

// A chain and sealing env for writer, signing with key, drawing from random (crypto/rand's when nil).
func testRecordSealEnv(t *testing.T, writer Id, key ed25519.PrivateKey, random []byte) *RecordSealEnv {
	t.Helper()
	env := &RecordSealEnv{
		Chain: NewRecordChainStore(testRecordStore(t), writer),
		Sign:  testRecordSigner(writer, key),
	}
	if random != nil {
		env.Random = bytes.NewReader(random)
	}
	return env
}

// A note an agent wrote in a run, as a v1 writer seals it.
func testRecordNoteArgs(logId Id, text string) *RecordSealArgs {
	agentId := Id(bytes.Repeat([]byte{0x88}, 16))
	runId := Id(bytes.Repeat([]byte{0x77}, 16))
	return &RecordSealArgs{
		LogId:         logId,
		Kind:          RecordKindNote,
		Source:        RecordSourceAgent,
		AgentSource:   RecordAgentSourceAsserted,
		AgentId:       &agentId,
		RunId:         &runId,
		TimeMillis:    1762387200000,
		PolicyVersion: 7,
		Body:          &protocol.CoordinationBody{Text: text},
	}
}

// testdata/record/sealed.json: the writer's key and ids, then each entry's inputs and what sealing made of them, in
// lowercase hex.
type testRecordSealedVectors struct {
	Comment         string `json:"comment"`
	IdentitySeed    string `json:"identity_seed"`
	WriterSidecarId string `json:"writer_sidecar_id"`
	LogId           string `json:"log_id"`
	SlotId          string `json:"slot_id"`
	Entries         []struct {
		Random         string `json:"random"`
		Body           string `json:"body"`
		Seq            uint64 `json:"seq"`
		PrevSha256     string `json:"prev_sha256"`
		Header         string `json:"header"`
		Signed         string `json:"signed"`
		SealedBody     string `json:"sealed_body"`
		BodyCommitment string `json:"body_commitment"`
		Leaf           string `json:"leaf"`
		KeyIndex       uint32 `json:"key_index"`
		Entry          string `json:"entry"`
	} `json:"entries"`
}

// The golden entries' fixed inputs: a writer's seed, ids, a slot, and per entry its draws and its args.
type testRecordSealedInputs struct {
	seed    []byte
	writer  Id
	logId   Id
	slotId  Id
	randoms [][]byte
	argses  []*RecordSealArgs
}

func testRecordSealedFixture() *testRecordSealedInputs {
	logId := Id(bytes.Repeat([]byte{0x44}, 16))
	runId := Id(bytes.Repeat([]byte{0x77}, 16))
	draws := func(entryId byte, key byte, salt byte, nonce byte) []byte {
		random := bytes.Repeat([]byte{entryId}, 16)
		random = append(random, bytes.Repeat([]byte{key}, 32)...)
		random = append(random, bytes.Repeat([]byte{salt}, 32)...)
		return append(random, bytes.Repeat([]byte{nonce}, 24)...)
	}
	return &testRecordSealedInputs{
		seed:    bytes.Repeat([]byte{0x99}, ed25519.SeedSize),
		writer:  Id(bytes.Repeat([]byte{0x33}, 16)),
		logId:   logId,
		slotId:  Id(bytes.Repeat([]byte{0x09}, 16)),
		randoms: [][]byte{draws(0x01, 0x02, 0x03, 0x04), draws(0x05, 0x06, 0x07, 0x08)},
		argses: []*RecordSealArgs{
			testRecordNoteArgs(logId, "synthetic note"),
			{
				LogId:         logId,
				Kind:          RecordKindCoverage,
				Source:        RecordSourceObserved,
				RunId:         &runId,
				TimeMillis:    1762387201000,
				Tainted:       true,
				PolicyVersion: 7,
				Body:          &protocol.Coverage{RunId: runId.Bytes(), Harness: "claude-code", FirstSeq: 1, LastSeq: 1},
			},
		},
	}
}

// Seals the fixture's entries on a fresh chain and writes down what came of them.
func testRecordComputeSealed(t *testing.T) *testRecordSealedVectors {
	inputs := testRecordSealedFixture()
	key := ed25519.NewKeyFromSeed(inputs.seed)
	env := testRecordSealEnv(t, inputs.writer, key, slices.Concat(inputs.randoms...))
	vectors := &testRecordSealedVectors{
		Comment: "RECORD-M3-01's golden sealed entries: a writer's first two entries in one log, each drawing its " +
			"entry_id, key, salt and nonce from random, in that order, then pushed in one slot at key_index 0 and 1. " +
			"Ed25519 signs deterministically, so the bytes follow from the inputs. go test -run " +
			"TestRecordSealedGoldenEntries -update-record-sealed rewrites this file.",
		IdentitySeed:    hex.EncodeToString(inputs.seed),
		WriterSidecarId: hex.EncodeToString(inputs.writer[:]),
		LogId:           hex.EncodeToString(inputs.logId[:]),
		SlotId:          hex.EncodeToString(inputs.slotId[:]),
	}
	for index, args := range inputs.argses {
		sealed, err := RecordSeal(env, args)
		if err != nil {
			t.Fatal(err)
		}
		header, err := sealed.Header()
		if err != nil {
			t.Fatal(err)
		}
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(args.Body)
		if err != nil {
			t.Fatal(err)
		}
		vectors.Entries = append(vectors.Entries, struct {
			Random         string `json:"random"`
			Body           string `json:"body"`
			Seq            uint64 `json:"seq"`
			PrevSha256     string `json:"prev_sha256"`
			Header         string `json:"header"`
			Signed         string `json:"signed"`
			SealedBody     string `json:"sealed_body"`
			BodyCommitment string `json:"body_commitment"`
			Leaf           string `json:"leaf"`
			KeyIndex       uint32 `json:"key_index"`
			Entry          string `json:"entry"`
		}{
			Random:         hex.EncodeToString(inputs.randoms[index]),
			Body:           hex.EncodeToString(body),
			Seq:            sealed.Seq,
			PrevSha256:     hex.EncodeToString(header.Header.GetPrevSha256()),
			Header:         hex.EncodeToString(header.Bytes),
			Signed:         hex.EncodeToString(sealed.Signed),
			SealedBody:     hex.EncodeToString(sealed.SealedBody),
			BodyCommitment: hex.EncodeToString(header.Header.GetBodyCommitment()),
			Leaf:           hex.EncodeToString(sealed.Leaf[:]),
			KeyIndex:       uint32(index),
			Entry:          hex.EncodeToString(sealed.EntryBytes(&inputs.slotId, uint32(index))),
		})
	}
	return vectors
}

// The golden entries seal again to the file's bytes, and the file's bytes stand on their own: each header verifies
// under the seed's key, its leaf is the next one's prev_sha256 from 32 zero bytes, its body opens under the key and
// salt it drew, and its entry holds exactly its Signed and sealed body.
func TestRecordSealedGoldenEntries(t *testing.T) {
	if *updateRecordSealed {
		encoded, err := json.MarshalIndent(testRecordComputeSealed(t), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(testRecordSealedPath, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := os.ReadFile(testRecordSealedPath)
	if err != nil {
		t.Fatal(err)
	}
	vectors := &testRecordSealedVectors{}
	if err := json.Unmarshal(encoded, vectors); err != nil {
		t.Fatal(err)
	}
	if recomputed := testRecordComputeSealed(t); !slices.Equal(recomputed.Entries, vectors.Entries) {
		t.Errorf("sealing the fixture again gave other bytes")
	}

	inputs := testRecordSealedFixture()
	publicKey := ed25519.NewKeyFromSeed(testRecordHex(t, vectors.IdentitySeed)).Public().(ed25519.PublicKey)
	if len(vectors.Entries) != 2 {
		t.Fatalf("%d entries", len(vectors.Entries))
	}
	prev := make([]byte, 32)
	for index, c := range vectors.Entries {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(testRecordHex(t, c.Signed), signed); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(signed.GetBody(), testRecordHex(t, c.Header)) {
			t.Errorf("entry %d: the Signed holds another header", index)
		}
		err := bridge.VerifySigned(signed, RecordEntryPurpose, bridge.SignedType_SIGNED_RECORD_HEADER, bridge.SignedKeyAlgEd25519, publicKey)
		if err != nil {
			t.Errorf("entry %d: %v", index, err)
		}
		header, err := ParseStoredRecordHeader(testRecordHex(t, c.Header))
		if err != nil {
			t.Fatal(err)
		}
		if header.Header.GetSeq() != uint64(index+1) || c.Seq != uint64(index+1) {
			t.Errorf("entry %d is seq %d", index, header.Header.GetSeq())
		}
		if !bytes.Equal(header.Header.GetPrevSha256(), prev) || c.PrevSha256 != hex.EncodeToString(prev) {
			t.Errorf("entry %d does not chain", index)
		}
		leaf := header.LeafHash()
		if hex.EncodeToString(leaf[:]) != c.Leaf {
			t.Errorf("entry %d's leaf is %x", index, leaf)
		}
		prev = leaf[:]
		random := testRecordHex(t, c.Random)
		if !bytes.Equal(header.Header.GetEntryId(), random[:16]) || !bytes.Equal(signed.GetSignerId(), testRecordHex(t, vectors.WriterSidecarId)) ||
			!bytes.Equal(header.Header.GetLogId(), testRecordHex(t, vectors.LogId)) {
			t.Errorf("entry %d names another entry, writer or log", index)
		}
		body, err := RecordOpen(header, testRecordHex(t, c.SealedBody), random[16:48], random[48:80])
		if err != nil {
			t.Fatalf("entry %d: %v", index, err)
		}
		if !bytes.Equal(body, testRecordHex(t, c.Body)) {
			t.Errorf("entry %d opened to another body", index)
		}
		if !bytes.Equal(testRecordHex(t, c.SealedBody)[:RecordSealNonceByteCount], random[80:]) {
			t.Errorf("entry %d's nonce is not its draw", index)
		}
		entry := &protocol.RecordEntry{}
		if err := proto.Unmarshal(testRecordHex(t, c.Entry), entry); err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(entry.GetHeader(), signed) || !bytes.Equal(entry.GetSealedBody(), testRecordHex(t, c.SealedBody)) ||
			!bytes.Equal(entry.GetKeySlotId(), inputs.slotId[:]) || entry.GetKeyIndex() != c.KeyIndex || entry.GetVersion() != 1 {
			t.Errorf("entry %d's RecordEntry does not hold what was sealed", index)
		}
	}
}

// Every entry draws its own key, salt, nonce and entry_id (owner decision 61), and a body opens only with its own.
func TestRecordSealDrawsAKeyAndSaltPerEntry(t *testing.T) {
	writer := NewId()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := testRecordSealEnv(t, writer, key, nil)
	logId := NewId()
	draws := map[string]bool{}
	entries := []*RecordSealedEntry{}
	for range 8 {
		sealed, err := RecordSeal(env, testRecordNoteArgs(logId, "the same note each time"))
		if err != nil {
			t.Fatal(err)
		}
		for _, draw := range [][]byte{sealed.Key, sealed.Salt, sealed.SealedBody[:RecordSealNonceByteCount], sealed.EntryId[:]} {
			if draws[string(draw)] {
				t.Fatalf("seq %d drew a value an entry already holds", sealed.Seq)
			}
			draws[string(draw)] = true
		}
		entries = append(entries, sealed)
	}
	first, err := entries[0].Header()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RecordOpen(first, entries[0].SealedBody, entries[1].Key, entries[0].Salt); !errors.Is(err, ErrRecordBodyInvalid) {
		t.Errorf("another entry's key opened a body: %v", err)
	}
	if _, err := RecordOpen(first, entries[0].SealedBody, entries[0].Key, entries[1].Salt); !errors.Is(err, ErrRecordBodyInvalid) {
		t.Errorf("another entry's salt committed to a body: %v", err)
	}
}

// The aad binds a body to its log and entry: the same bytes under another entry_id or log_id do not open, and a
// flipped byte anywhere in the sealed body does not either.
func TestRecordOpenRefusesAWrongAad(t *testing.T) {
	writer := NewId()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := testRecordSealEnv(t, writer, key, nil)
	sealed, err := RecordSeal(env, testRecordNoteArgs(NewId(), "bound to its entry"))
	if err != nil {
		t.Fatal(err)
	}
	header, err := sealed.Header()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RecordOpen(header, sealed.SealedBody, sealed.Key, sealed.Salt); err != nil {
		t.Fatal(err)
	}
	moved := func(change func(moved *protocol.RecordHeader)) *StoredRecordHeader {
		header := proto.CloneOf(header.Header)
		change(header)
		return &StoredRecordHeader{Header: header}
	}
	otherId := NewId()
	for name, wrong := range map[string]*StoredRecordHeader{
		"another entry_id": moved(func(moved *protocol.RecordHeader) { moved.EntryId = otherId.Bytes() }),
		"another log_id":   moved(func(moved *protocol.RecordHeader) { moved.LogId = otherId.Bytes() }),
	} {
		if _, err := RecordOpen(wrong, sealed.SealedBody, sealed.Key, sealed.Salt); !errors.Is(err, ErrRecordBodyInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for index := range sealed.SealedBody {
		flipped := bytes.Clone(sealed.SealedBody)
		flipped[index] ^= 0x01
		if _, err := RecordOpen(header, flipped, sealed.Key, sealed.Salt); !errors.Is(err, ErrRecordBodyInvalid) {
			t.Fatalf("a flip at byte %d: %v", index, err)
		}
	}
	for _, cut := range [][]byte{nil, sealed.SealedBody[:RecordSealNonceByteCount], sealed.SealedBody[:len(sealed.SealedBody)-1]} {
		if _, err := RecordOpen(header, cut, sealed.Key, sealed.Salt); !errors.Is(err, ErrRecordBodyInvalid) {
			t.Errorf("a body cut to %d bytes: %v", len(cut), err)
		}
	}
	if _, err := RecordOpen(header, sealed.SealedBody, sealed.Key[:16], sealed.Salt); !errors.Is(err, ErrRecordBodyInvalid) {
		t.Errorf("a short key: %v", err)
	}
}

// A body sealed under its own key but committed to with another salt, as a writer that lied about its commitment
// would make it, opens and fails its commitment: section 5.5 shows it invalid, its header standing.
func TestRecordOpenRefusesABodyItsHeaderDoesNotCommitTo(t *testing.T) {
	writer := NewId()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := testRecordSealEnv(t, writer, key, nil)
	sealed, err := RecordSeal(env, testRecordNoteArgs(NewId(), "committed"))
	if err != nil {
		t.Fatal(err)
	}
	header, err := sealed.Header()
	if err != nil {
		t.Fatal(err)
	}
	recommitted := proto.CloneOf(header.Header)
	recommitted.BodyCommitment = bytes.Repeat([]byte{0xee}, 32)
	_, err = RecordOpen(&StoredRecordHeader{Header: recommitted}, sealed.SealedBody, sealed.Key, sealed.Salt)
	if !errors.Is(err, ErrRecordBodyInvalid) {
		t.Errorf("a commitment that is not the body's: %v", err)
	}
}

// What a header or body cannot hold is refused before anything is drawn or signed, and burns no seq: the next good
// entry is still seq 1.
func TestRecordSealRefusesWhatAHeaderCannotHold(t *testing.T) {
	writer := NewId()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := testRecordSealEnv(t, writer, key, nil)
	signCount := 0
	sign := env.Sign
	env.Sign = func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
		signCount += 1
		return sign(purpose, signedType, body, agentId)
	}
	logId := NewId()
	agentId := NewId()
	cases := map[string]func(args *RecordSealArgs){
		"no log":            func(args *RecordSealArgs) { args.LogId = Id{} },
		"kind 0":            func(args *RecordSealArgs) { args.Kind = RecordKindUnspecified },
		"a derived kind":    func(args *RecordSealArgs) { args.Kind = RecordKindRun },
		"an unknown kind":   func(args *RecordSealArgs) { args.Kind = 60000 },
		"source 0":          func(args *RecordSealArgs) { args.Source = RecordSourceUnknown },
		"an unknown source": func(args *RecordSealArgs) { args.Source = 9 },
		"an unknown agent":  func(args *RecordSealArgs) { args.AgentSource = 9 },
		"an agent source alone": func(args *RecordSealArgs) {
			args.AgentId = nil
		},
		"an agent id alone": func(args *RecordSealArgs) {
			args.AgentSource = RecordAgentSourceNone
			args.AgentId = &agentId
		},
		"a short action_id": func(args *RecordSealArgs) { args.ActionId = []byte{1, 2, 3} },
		"a short grant_id":  func(args *RecordSealArgs) { args.GrantId = []byte{1, 2, 3} },
		"no capture time":   func(args *RecordSealArgs) { args.TimeMillis = 0 },
		"no body":           func(args *RecordSealArgs) { args.Body = nil },
		"another kind's body": func(args *RecordSealArgs) {
			args.Body = &protocol.Coverage{}
		},
		"a signed body of another type": func(args *RecordSealArgs) {
			args.Kind = RecordKindApprovalDecision
			args.Source = RecordSourceApprover
			args.Body = &bridge.Signed{Type: uint32(bridge.SignedType_SIGNED_APPROVAL_CANCEL)}
		},
		"a content ref of short ids": func(args *RecordSealArgs) {
			args.Content = []*protocol.ContentRef{{RepoId: []byte{1}, ObjectId: []byte{2}, Commitment: []byte{3}}}
		},
	}
	for name, change := range cases {
		args := testRecordNoteArgs(logId, "refused")
		change(args)
		if _, err := RecordSeal(env, args); !errors.Is(err, ErrRecordSealInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if signCount != 0 {
		t.Errorf("signed %d refused headers", signCount)
	}
	sealed, err := RecordSeal(env, testRecordNoteArgs(logId, "accepted"))
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Seq != 1 {
		t.Errorf("the first good entry is seq %d", sealed.Seq)
	}
	if _, err := RecordSeal(nil, testRecordNoteArgs(logId, "no env")); !errors.Is(err, ErrRecordSealInvalid) {
		t.Errorf("no env: %v", err)
	}
	if _, err := RecordSeal(env, nil); !errors.Is(err, ErrRecordSealInvalid) {
		t.Errorf("no args: %v", err)
	}
}

// Only the identity key signs a header, under record-entry and SIGNED_RECORD_HEADER, whatever agent filed the entry,
// so no agent key ever names itself to a reader of the header (§6.9); a signer that answers as another sidecar is
// refused, since every reader would refuse that header, and a signer that cannot sign, as while Locked, burns no seq.
func TestRecordSealSignsWithTheIdentityKeyAlone(t *testing.T) {
	writer := NewId()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := testRecordSealEnv(t, writer, key, nil)
	sign := env.Sign
	env.Sign = func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
		if purpose != RecordEntryPurpose || signedType != bridge.SignedType_SIGNED_RECORD_HEADER || agentId != nil {
			t.Errorf("signed as %s, type %#x, for agent %v", purpose, int32(signedType), agentId)
		}
		return sign(purpose, signedType, body, agentId)
	}
	logId := NewId()
	if _, err := RecordSeal(env, testRecordNoteArgs(logId, "an agent's note")); err != nil {
		t.Fatal(err)
	}

	env.Sign = testRecordSigner(NewId(), key)
	if _, err := RecordSeal(env, testRecordNoteArgs(logId, "signed as another")); !errors.Is(err, ErrRecordSealInvalid) {
		t.Errorf("a header signed as another sidecar: %v", err)
	}
	env.Sign = func(string, bridge.SignedType, []byte, *Id) (*bridge.Signed, error) {
		return nil, ErrSidecarStoreLocked
	}
	if _, err := RecordSeal(env, testRecordNoteArgs(logId, "while locked")); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("while locked: %v", err)
	}
	env.Sign = sign
	sealed, err := RecordSeal(env, testRecordNoteArgs(logId, "after unlock"))
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Seq != 2 {
		t.Errorf("after two refusals the next entry is seq %d", sealed.Seq)
	}
}

// EntryBytes writes RecordEntry's own encoding, field for field, so what a hand-built entry holds is what the message
// holds; a deposit's entry names no slot, and its key and salt ride beside it.
func TestRecordEntryBytesAreTheMessagesEncoding(t *testing.T) {
	descriptor := (&protocol.RecordEntry{}).ProtoReflect().Descriptor().Fields()
	for name, number := range map[string]int{
		"header": recordEntryHeaderField, "sealed_body": recordEntrySealedBodyField, "key_slot_id": recordEntryKeySlotIdField,
		"version": recordEntryVersionField, "key_index": recordEntryKeyIndexField,
	} {
		if field := descriptor.ByName(protoreflect.Name(name)); field == nil || int(field.Number()) != number {
			t.Errorf("RecordEntry.%s is not field %d", name, number)
		}
	}
	writer := NewId()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := testRecordSealEnv(t, writer, key, nil)
	sealed, err := RecordSeal(env, testRecordNoteArgs(NewId(), "encoded"))
	if err != nil {
		t.Fatal(err)
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(sealed.Signed, signed); err != nil {
		t.Fatal(err)
	}
	slotId := NewId()
	for _, c := range []struct {
		slotId   *Id
		keyIndex uint32
	}{{slotId: &slotId, keyIndex: 63}, {slotId: &slotId, keyIndex: 0}, {slotId: nil, keyIndex: 0}} {
		message := &protocol.RecordEntry{Header: signed, SealedBody: sealed.SealedBody, Version: 1, KeyIndex: c.keyIndex}
		if c.slotId != nil {
			message.KeySlotId = c.slotId.Bytes()
		}
		want, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		if got := sealed.EntryBytes(c.slotId, c.keyIndex); !bytes.Equal(got, want) {
			t.Errorf("slot %v, index %d: the bytes differ from the message's", c.slotId, c.keyIndex)
		}
	}
	deposit := sealed.Deposit()
	if !bytes.Equal(deposit.GetEntry(), sealed.EntryBytes(nil, 0)) || !bytes.Equal(deposit.GetKey(), sealed.Key) ||
		!bytes.Equal(deposit.GetSalt(), sealed.Salt) {
		t.Error("the deposit does not carry the entry with its key and salt")
	}
	row := sealed.SlotRow(5)
	if row.KeyIndex != 5 || !bytes.Equal(row.Row, append(bytes.Clone(sealed.Key), sealed.Salt...)) {
		t.Error("the slot row is not key || salt at its index")
	}
	splitKey, splitSalt, err := RecordSlotRowSplit(row.Row)
	if err != nil || !bytes.Equal(splitKey, sealed.Key) || !bytes.Equal(splitSalt, sealed.Salt) {
		t.Errorf("the slot row did not split back: %v", err)
	}
	joined, err := RecordSlotRowJoin(splitKey, splitSalt)
	if err != nil || !bytes.Equal(joined, row.Row) {
		t.Errorf("the slot row did not join back: %v", err)
	}
	if _, _, err := RecordSlotRowSplit(row.Row[:63]); !errors.Is(err, ErrRecordStoredInvalid) {
		t.Errorf("a short row: %v", err)
	}
	if _, err := RecordSlotRowJoin(splitKey[:31], splitSalt); !errors.Is(err, ErrRecordStoredInvalid) {
		t.Errorf("a short key: %v", err)
	}
	sealed.Clear()
	if sealed.Key != nil || sealed.Salt != nil || !bytes.Equal(splitKey, deposit.GetKey()) {
		t.Error("Clear left the key or salt, or reached a copy")
	}
}
