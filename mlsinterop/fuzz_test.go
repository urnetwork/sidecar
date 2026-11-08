// §22.6's MLS row (D-TEST-4): mls_*'s decoders held to both peers', thomas-vilte/mls-go's and tmc/mls's, on the same
// bytes. In every build: MLS messages, through ParseMlsHeader, the one keyless parse of a commit gkm runs on every
// epoch object (§10.6); the GkmCommitHeader gkm reads out of a commit's authenticated_data (D-KEYS-3); and the
// Welcome, through JoinWelcome on an engine that holds no KeyPackage, which decodes a Welcome as every engine does
// and then finds none of the refs it names. fuzz_hooks_test.go adds GroupInfo and the ratchet tree under
// sidecar_testhooks, the one build in which the root exports those two decoders.
//
// What mls_* accepts, both peers must read as the same structure, and tmc/mls must encode back to the input byte for
// byte, so mls_* never takes a form RFC 9420's minimal encodings rule out. What mls_* refuses, a peer may accept: the
// subset refuses more (§10.4), every wire format but a commit's framing, a member's PublicMessage commit and, outside
// the root's tests, a basic credential among them. mls-go has no 0x0010 and keeps no 0xF552 body, so it is held to
// what it reads.
//
// A peer decodes only what mls_* reads, since the rule binds nowhere else: mls-go v1.6.0's tree decoder, given a
// ratchet_tree cut short by one byte, falls back to an older format that allocates by the leaf count it reads there,
// past a gigabyte, and its Welcome join never returns on a path_secret with no tree (mlsgo_test.go).
//
// The seeds run as ordinary tests in every test.sh (owner decision 101): the checked-in transcripts of 0x0010 and
// 0x0001, which mls_*, tmc/mls and mls-go wrote; the mlswg's messages; values the exported engine writes here;
// mutations of these, each a form one rule decides; and every file under the root's testdata/fuzz/<target>/, where a
// failing input goes as a seed beside a regression test here.

package mlsinterop

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/tmc/mls"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Every file under the root's testdata/fuzz/<directory>/, none when it holds none: the seeds a person adds, crashers
// among them, beside the ones computed here.
func fuzzMlsSeedFiles(t testing.TB, directory string) [][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(interopRootDirectory(t), "testdata", "fuzz", directory, "*"))
	if err != nil {
		t.Fatal(err)
	}
	seeds := [][]byte{}
	for _, path := range paths {
		seed, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		seeds = append(seeds, seed)
	}
	return seeds
}

// One passive client's view, of any checked-in transcript.
type fuzzMlsView struct {
	cipherSuite uint16
	welcome     []byte
	// nil when the Welcome's GroupInfo carries the tree
	ratchetTree []byte
	commits     [][]byte
}

// Every view under testdata/mls/0x0010/ and testdata/mls/0x0001/.
func fuzzMlsViews(t testing.TB) []*fuzzMlsView {
	t.Helper()
	views := []*fuzzMlsView{}
	for _, directory := range []string{"0x0010", "0x0001"} {
		paths, err := filepath.Glob(filepath.Join(interopRootDirectory(t), "testdata", "mls", directory, "*.json"))
		if err != nil || len(paths) == 0 {
			t.Fatalf("no %s transcript to seed from: %v", directory, err)
		}
		for _, path := range paths {
			encoded, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			transcripts := []struct {
				CipherSuite uint16  `json:"cipher_suite"`
				Welcome     string  `json:"welcome"`
				RatchetTree *string `json:"ratchet_tree"`
				Epochs      []struct {
					Commit string `json:"commit"`
				} `json:"epochs"`
			}{}
			if err := json.Unmarshal(encoded, &transcripts); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			decode := func(text string) []byte {
				decoded, err := hex.DecodeString(text)
				if err != nil {
					t.Fatalf("%s: %v", path, err)
				}
				return decoded
			}
			for _, transcript := range transcripts {
				view := &fuzzMlsView{cipherSuite: transcript.CipherSuite, welcome: decode(transcript.Welcome)}
				if transcript.RatchetTree != nil {
					view.ratchetTree = decode(*transcript.RatchetTree)
				}
				for _, epoch := range transcript.Epochs {
					view.commits = append(view.commits, decode(epoch.Commit))
				}
				views = append(views, view)
			}
		}
	}
	return views
}

// Every hex value of the mlswg's messages.json.
func fuzzMlsMessageVectors(t testing.TB) [][]byte {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join(interopRootDirectory(t), "testdata", "mls", "mlswg", "messages.json"))
	if err != nil {
		t.Fatal(err)
	}
	vectors := []map[string]string{}
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatal(err)
	}
	values := [][]byte{}
	for _, vector := range vectors {
		for _, value := range vector {
			if decoded, err := hex.DecodeString(value); err == nil {
				values = append(values, decoded)
			}
		}
	}
	return values
}

// The 0x0010 transcripts' commits, which mls_* and tmc/mls both wrote and mls_* reads, and the rest: the 0x0001
// transcripts' commits, mls-go's and mls_*'s, whose external commits carry basic credentials production does not
// read, and every value of the mlswg's messages.json.
func fuzzMlsSeeds(t testing.TB) (commits [][]byte, others [][]byte) {
	t.Helper()
	for _, view := range fuzzMlsViews(t) {
		if view.cipherSuite == 0x0010 {
			commits = append(commits, view.commits...)
		} else {
			others = append(others, view.commits...)
		}
	}
	return commits, append(others, fuzzMlsMessageVectors(t)...)
}

// Each commit mutated into a form one of the target's rules decides.
func fuzzMlsMutations(t testing.TB, commit []byte) [][]byte {
	t.Helper()
	mutations := [][]byte{
		commit[:len(commit)/2],
		commit[:len(commit)-1],
		append(bytes.Clone(commit), 0),
	}
	otherVersion := bytes.Clone(commit)
	otherVersion[1] ^= 2
	mutations = append(mutations, otherVersion)
	otherFormat := bytes.Clone(commit)
	otherFormat[3] ^= 3
	mutations = append(mutations, otherFormat)
	// a group_id length of 16 written in two bytes, as RFC 9420 §2.1.2 forbids
	if 4 < len(commit) && commit[4] == 16 {
		mutations = append(mutations, append(append(bytes.Clone(commit[:4]), 0x40), commit[4:]...))
	}
	// another epoch, encoded back by tmc/mls
	message := &mls.Message{}
	if err := mls.Unmarshal(commit, message); err == nil {
		switch {
		case message.PrivateMessage != nil:
			message.PrivateMessage.Epoch += 1
		case message.PublicMessage != nil:
			message.PublicMessage.Content.Epoch += 1
		}
		if encoded, err := mls.Marshal(message); err == nil {
			mutations = append(mutations, encoded)
		}
	}
	return mutations
}

// The messages rule: when mls_* reads encoded as a commit, both peers read it as one with the same wire format,
// group, epoch, content type, sender kind and authenticated_data, and tmc/mls encodes it back unchanged. Returns
// mls_*'s header, nil when mls_* refuses it.
func fuzzMlsHeaderAgrees(t *testing.T, encoded []byte) *sidecar.MlsHeader {
	t.Helper()
	header, err := sidecar.ParseMlsHeader(encoded)
	if err != nil {
		return nil
	}
	tmcMessage := &mls.Message{}
	tmcErr := mls.Unmarshal(encoded, tmcMessage)
	goMessage, goErr := framing.UnmarshalMLSMessage(encoded)
	if tmcErr != nil {
		t.Fatalf("mls_* reads a commit tmc/mls refuses: %v", tmcErr)
	}
	if goErr != nil {
		t.Fatalf("mls_* reads a commit mls-go refuses: %v", goErr)
	}
	if reencoded, err := mls.Marshal(tmcMessage); err != nil || !bytes.Equal(reencoded, encoded) {
		t.Fatalf("mls_* reads bytes tmc/mls does not encode back to themselves: %v", err)
	}
	type fields struct {
		groupId           []byte
		epoch             uint64
		contentType       uint8
		external          bool
		authenticatedData []byte
	}
	ours := fields{groupId: header.GroupId, epoch: header.Epoch, contentType: header.ContentType, external: header.External != nil,
		authenticatedData: header.AuthenticatedData}
	var tmcFields, goFields fields
	switch {
	case tmcMessage.PrivateMessage != nil && goMessage.PrivateMessage != nil:
		private := tmcMessage.PrivateMessage
		tmcFields = fields{groupId: private.GroupID, epoch: private.Epoch, contentType: uint8(private.ContentType),
			authenticatedData: private.AuthenticatedData}
		goPrivate := goMessage.PrivateMessage
		goFields = fields{groupId: goPrivate.GroupID, epoch: goPrivate.Epoch, contentType: uint8(goPrivate.ContentType),
			authenticatedData: goPrivate.AuthenticatedData}
	case tmcMessage.PublicMessage != nil && goMessage.PublicMessage != nil:
		content := tmcMessage.PublicMessage.Content
		tmcFields = fields{groupId: content.GroupID, epoch: content.Epoch, contentType: uint8(content.ContentType),
			external: content.Sender.Type == mls.SenderTypeNewMemberCommit, authenticatedData: content.AuthenticatedData}
		goContent := goMessage.PublicMessage.Content
		goFields = fields{groupId: goContent.GroupID, epoch: goContent.Epoch, contentType: uint8(goContent.ContentType()),
			external: goContent.Sender.Type == framing.SenderTypeNewMemberCommit, authenticatedData: goContent.AuthenticatedData}
	default:
		t.Fatalf("mls_* reads a commit the peers read as another wire format: tmc/mls %d", tmcMessage.WireFormat)
	}
	equal := func(a fields, b fields) bool {
		return bytes.Equal(a.groupId, b.groupId) && a.epoch == b.epoch && a.contentType == b.contentType &&
			a.external == b.external && bytes.Equal(a.authenticatedData, b.authenticatedData)
	}
	if !equal(ours, tmcFields) {
		t.Fatalf("mls_* reads %+v where tmc/mls reads %+v", ours, tmcFields)
	}
	if !equal(ours, goFields) {
		t.Fatalf("mls_* reads %+v where mls-go reads %+v", ours, goFields)
	}
	return header
}

func FuzzMlsHeaderAgreesWithPeers(f *testing.F) {
	commits, others := fuzzMlsSeeds(f)
	for _, commit := range commits {
		f.Add(commit)
		for _, mutation := range fuzzMlsMutations(f, commit) {
			f.Add(mutation)
		}
	}
	for _, other := range others {
		f.Add(other)
	}
	for _, seed := range fuzzMlsSeedFiles(f, "mls_messages") {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		fuzzMlsHeaderAgrees(t, encoded)
	})
}

// The seeds hold what the target needs to mean anything: mls_* reads every 0x0010 commit, refuses each mutation the
// rules above name, the minimal-encoding one among them, and reads the 0x0001 transcripts' member commits, mls-go's
// and its own.
func TestFuzzMlsHeaderSeedsReachEveryRule(t *testing.T) {
	commits, others := fuzzMlsSeeds(t)
	if len(commits) < 10 || len(others) == 0 {
		t.Fatalf("%d commits and %d other messages to seed from", len(commits), len(others))
	}
	external, private := 0, 0
	for index, commit := range commits {
		header, err := sidecar.ParseMlsHeader(commit)
		if err != nil {
			t.Fatalf("commit %d: %v", index, err)
		}
		if header.External != nil {
			external += 1
		} else {
			private += 1
		}
		for mutationIndex, mutation := range fuzzMlsMutations(t, commit) {
			_, err := sidecar.ParseMlsHeader(mutation)
			// the changed epoch alone is still a commit's framing
			if isEpochChange := mutationIndex == len(fuzzMlsMutations(t, commit))-1; isEpochChange {
				if err != nil {
					t.Errorf("commit %d: another epoch: %v", index, err)
				}
				continue
			}
			if err == nil {
				t.Errorf("commit %d: mutation %d reads", index, mutationIndex)
			}
		}
	}
	if external == 0 || private == 0 {
		t.Errorf("%d external and %d member commits seed the target", external, private)
	}
	memberCommits := 0
	for _, view := range fuzzMlsViews(t) {
		if view.cipherSuite != 0x0001 {
			continue
		}
		for _, commit := range view.commits {
			if header, err := sidecar.ParseMlsHeader(commit); err == nil && header.External == nil {
				memberCommits += 1
			}
		}
	}
	if memberCommits < 10 {
		t.Errorf("%d of the 0x0001 transcripts' member commits read", memberCommits)
	}
}

// A sidecar identity for engines made here, signing as Sidecar.Sign does.
type fuzzMlsIdentity struct {
	sidecarId  sidecar.Id
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func (self *fuzzMlsIdentity) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.privateKey, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

// An engine of a fresh identity on a store of its own, taking in every leaf whose credential holds for its key: the
// seeds need groups, not admission, which KEYS-M2-19 checks.
func newFuzzMlsEngine(t testing.TB) sidecar.MlsEngine {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := &fuzzMlsIdentity{sidecarId: sidecar.NewId(), publicKey: publicKey, privateKey: privateKey}
	engine, err := sidecar.NewMlsEngine(&sidecar.MlsEngineArgs{
		SidecarId:         identity.sidecarId,
		IdentityPublicKey: publicKey,
		AdmissionSha256:   make([]byte, 32),
		Sign:              identity.sign,
		Store:             sidecartest.NewFakeStore().Root(),
		CheckCredential:   func(credential *protocol.UrMlsCredential) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

// A GkmCommitHeader's encoding.
func fuzzMlsGkmCommitHeader(t testing.TB, header *protocol.GkmCommitHeader) []byte {
	t.Helper()
	encoded, err := proto.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// What the exported engine writes under 0x0010, each commit carrying a real GkmCommitHeader: a creator's path commit,
// an Add with its Welcome, the joiner's path commit, and a recovery self-join's external commit, whose header names
// generation 0 (§10.6's epoch PUT). Returns the commits, the Welcome, and the full GroupInfo of the joiner's epoch.
func fuzzMlsEngineWrites(t testing.TB) (commits [][]byte, welcome []byte, groupInfo []byte) {
	t.Helper()
	creator, joiner, external := newFuzzMlsEngine(t), newFuzzMlsEngine(t), newFuzzMlsEngine(t)
	pin := func(version uint64) *bridge.AuthPin {
		return &bridge.AuthPin{Version: version, Chain: bytes.Repeat([]byte{byte(version)}, 32)}
	}
	group, err := creator.CreateGroup(sidecar.NewId(), &sidecar.MlsUrGroup{NetworkId: sidecar.NewId(), RepoId: sidecar.NewId(),
		Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	if err != nil {
		t.Fatal(err)
	}
	staged, err := group.Commit(&sidecar.MlsCommitArgs{Path: true,
		AuthenticatedData: fuzzMlsGkmCommitHeader(t, &protocol.GkmCommitHeader{Generation: 1, Auth: pin(3)})})
	if err != nil {
		t.Fatal(err)
	}
	commits = append(commits, staged.Message())
	if group, err = staged.Adopt(); err != nil {
		t.Fatal(err)
	}
	keyPackage, err := joiner.CreateKeyPackage(false)
	if err != nil {
		t.Fatal(err)
	}
	staged, err = group.Commit(&sidecar.MlsCommitArgs{Adds: [][]byte{keyPackage.Encoded},
		AuthenticatedData: fuzzMlsGkmCommitHeader(t, &protocol.GkmCommitHeader{Generation: 1, Auth: pin(4)})})
	if err != nil {
		t.Fatal(err)
	}
	commits = append(commits, staged.Message())
	welcome = staged.Welcome()
	full, err := staged.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = staged.Adopt(); err != nil {
		t.Fatal(err)
	}
	pending, err := joiner.JoinWelcome(welcome)
	if err != nil {
		t.Fatal(err)
	}
	joined, err := pending.Complete(full)
	if err != nil {
		t.Fatal(err)
	}
	staged, err = joined.Commit(&sidecar.MlsCommitArgs{Path: true,
		AuthenticatedData: fuzzMlsGkmCommitHeader(t, &protocol.GkmCommitHeader{Generation: 2, Auth: pin(5)})})
	if err != nil {
		t.Fatal(err)
	}
	commits = append(commits, staged.Message())
	if joined, err = staged.Adopt(); err != nil {
		t.Fatal(err)
	}
	if groupInfo, err = joined.GroupInfo(); err != nil {
		t.Fatal(err)
	}
	self, err := external.JoinExternal(groupInfo, &sidecar.MlsCommitArgs{Path: true,
		AuthenticatedData: fuzzMlsGkmCommitHeader(t, &protocol.GkmCommitHeader{Generation: 0, Auth: pin(6)})})
	if err != nil {
		t.Fatal(err)
	}
	commits = append(commits, self.Message())
	return commits, welcome, groupInfo
}

// commit with its authenticated_data replaced, encoded again by tmc/mls; nil when tmc/mls does not read commit.
func fuzzMlsWithAuthenticatedData(t testing.TB, commit []byte, authenticatedData []byte) []byte {
	t.Helper()
	message := &mls.Message{}
	if err := mls.Unmarshal(commit, message); err != nil {
		return nil
	}
	switch {
	case message.PrivateMessage != nil:
		message.PrivateMessage.AuthenticatedData = authenticatedData
	case message.PublicMessage != nil:
		message.PublicMessage.Content.AuthenticatedData = authenticatedData
	}
	encoded, err := mls.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// Headers in each form gkm's protobuf decoding decides: an unknown field and a known one of the wrong wire type, which
// proto keeps as unknown; a non-minimal varint and a repeated field, which decode to the value and to the last; a
// cut-short message and a length past the end, which it refuses; and the empty encoding, generation 0 with no pin.
func fuzzMlsHeaderForms(t testing.TB) map[string][]byte {
	t.Helper()
	header := fuzzMlsGkmCommitHeader(t, &protocol.GkmCommitHeader{Generation: 9, Auth: &bridge.AuthPin{Version: 2, Chain: make([]byte, 32)}})
	return map[string][]byte{
		"unknown field":       append(bytes.Clone(header), 0x78, 0x01),
		"non-minimal varint":  append([]byte{0x08, 0x89, 0x00}, header[2:]...),
		"repeated field":      append(bytes.Clone(header), 0x08, 0x0a),
		"wrong wire type":     append([]byte{0x0a, 0x00}, header[2:]...),
		"cut short":           header[:len(header)-1],
		"length past its end": append([]byte{0x12, 0x7f}, header[2:]...),
		"empty":               {},
		"canonical":           header,
	}
}

func FuzzMlsGkmCommitHeaderAgreesWithPeers(f *testing.F) {
	commits, _, _ := fuzzMlsEngineWrites(f)
	for _, commit := range commits {
		f.Add(commit)
		for _, form := range fuzzMlsHeaderForms(f) {
			if mutated := fuzzMlsWithAuthenticatedData(f, commit, form); mutated != nil {
				f.Add(mutated)
			}
		}
	}
	for _, seed := range fuzzMlsSeedFiles(f, "mls_gkm_commit_header") {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		header := fuzzMlsHeaderAgrees(t, encoded)
		if header == nil {
			return
		}
		// what gkm reads of the header: bytes all three stacks read alike, which decode to one message or to none,
		// and a message that decodes keeps its meaning through a deterministic encoding (§22.6's first row)
		gkmHeader := &protocol.GkmCommitHeader{}
		if err := proto.Unmarshal(header.AuthenticatedData, gkmHeader); err != nil {
			return
		}
		deterministic, err := proto.MarshalOptions{Deterministic: true}.Marshal(gkmHeader)
		if err != nil {
			t.Fatal(err)
		}
		again := &protocol.GkmCommitHeader{}
		if err := proto.Unmarshal(deterministic, again); err != nil || !proto.Equal(again, gkmHeader) {
			t.Fatalf("a GkmCommitHeader that does not survive its own encoding: %v", err)
		}
	})
}

// The engine's commits carry the headers they were given, as all three stacks read them; each header form keeps
// the commit readable by ParseMlsHeader, since authenticated_data is opaque to the framing, and decodes or is
// refused as protobuf's rules say.
func TestFuzzMlsGkmCommitHeaderSeedsReachEveryRule(t *testing.T) {
	commits, _, _ := fuzzMlsEngineWrites(t)
	generations := []uint64{}
	external := 0
	for index, commit := range commits {
		header, err := sidecar.ParseMlsHeader(commit)
		if err != nil {
			t.Fatalf("commit %d: %v", index, err)
		}
		if header.External != nil {
			external += 1
		}
		gkmHeader := &protocol.GkmCommitHeader{}
		if err := proto.Unmarshal(header.AuthenticatedData, gkmHeader); err != nil {
			t.Fatalf("commit %d: %v", index, err)
		}
		generations = append(generations, gkmHeader.GetGeneration())
	}
	if external != 1 || len(generations) != 4 || generations[3] != 0 {
		t.Errorf("%d external commits, generations %v", external, generations)
	}
	refused := map[string]bool{"cut short": true, "length past its end": true}
	for name, form := range fuzzMlsHeaderForms(t) {
		mutated := fuzzMlsWithAuthenticatedData(t, commits[0], form)
		header, err := sidecar.ParseMlsHeader(mutated)
		if err != nil || !bytes.Equal(header.AuthenticatedData, form) {
			t.Errorf("%s: the framing does not carry the header: %v", name, err)
			continue
		}
		err = proto.Unmarshal(header.AuthenticatedData, &protocol.GkmCommitHeader{})
		if refused[name] != (err != nil) {
			t.Errorf("%s: decoding says %v", name, err)
		}
	}
}

// An engine's answer to a Welcome it holds no KeyPackage for: ErrMlsNotMember when it decodes, any other error when
// it does not.
func fuzzMlsWelcomeDecodes(engine sidecar.MlsEngine, encoded []byte) bool {
	_, err := engine.JoinWelcome(encoded)
	return errors.Is(err, sidecar.ErrMlsNotMember)
}

// A Welcome cut short, with a byte after its end, as another version and as another wire format, and with its
// secrets' length written in more bytes than it needs.
func fuzzMlsWelcomeMutations(welcome []byte) [][]byte {
	if len(welcome) < 8 {
		return nil
	}
	otherVersion := bytes.Clone(welcome)
	otherVersion[1] ^= 2
	otherFormat := bytes.Clone(welcome)
	otherFormat[3] ^= 1
	mutations := [][]byte{welcome[:len(welcome)-1], append(bytes.Clone(welcome), 0), otherVersion, otherFormat}
	// version, wire format and cipher_suite take six bytes; a one-byte length after them becomes two
	if welcome[6]&0xc0 == 0 {
		mutations = append(mutations, append(append(bytes.Clone(welcome[:6]), 0x40), welcome[6:]...))
	}
	return mutations
}

// Welcomes from every stack: the transcripts', mls_*'s and mls-go's, the mlswg's of other implementations, and one
// the engine writes here; mutations of each into forms one rule decides; and the seed files.
func fuzzMlsWelcomeSeeds(t testing.TB) [][]byte {
	t.Helper()
	welcomes := [][]byte{}
	for _, view := range fuzzMlsViews(t) {
		welcomes = append(welcomes, view.welcome)
	}
	encoded, err := os.ReadFile(filepath.Join(interopRootDirectory(t), "testdata", "mls", "mlswg", "welcome.json"))
	if err != nil {
		t.Fatal(err)
	}
	vectors := []struct {
		Welcome string `json:"welcome"`
	}{}
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		if decoded, err := hex.DecodeString(vector.Welcome); err == nil {
			welcomes = append(welcomes, decoded)
		}
	}
	_, written, _ := fuzzMlsEngineWrites(t)
	welcomes = append(welcomes, written)
	seeds := [][]byte{}
	for _, welcome := range welcomes {
		seeds = append(seeds, welcome)
		seeds = append(seeds, fuzzMlsWelcomeMutations(welcome)...)
	}
	return append(seeds, fuzzMlsSeedFiles(t, "mls_welcome")...)
}

func FuzzMlsWelcomeAgreesWithPeers(f *testing.F) {
	engine := newFuzzMlsEngine(f)
	for _, seed := range fuzzMlsWelcomeSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if !fuzzMlsWelcomeDecodes(engine, encoded) {
			return
		}
		tmcMessage := &mls.Message{}
		tmcErr := mls.Unmarshal(encoded, tmcMessage)
		goMessage, goErr := framing.UnmarshalMLSMessage(encoded)
		var goWelcome *group.Welcome
		if goErr == nil {
			goWelcome, goErr = group.UnmarshalWelcome(goMessage.Welcome)
		}
		if tmcErr != nil || tmcMessage.Welcome == nil {
			t.Fatalf("mls_* decodes a Welcome tmc/mls does not: %v", tmcErr)
		}
		if reencoded, err := mls.Marshal(tmcMessage); err != nil || !bytes.Equal(reencoded, encoded) {
			t.Fatalf("mls_* decodes a Welcome tmc/mls does not encode back to itself: %v", err)
		}
		if goErr != nil {
			t.Fatalf("mls_* decodes a Welcome mls-go does not: %v", goErr)
		}
		if !bytes.Equal(goWelcome.Marshal(), encoded[4:]) {
			t.Fatal("mls_* decodes a Welcome mls-go does not encode back to itself")
		}
		theirs := tmcMessage.Welcome
		if uint16(theirs.CipherSuite) != uint16(goWelcome.CipherSuite) || len(theirs.Secrets) != len(goWelcome.Secrets) ||
			!bytes.Equal(theirs.EncryptedGroupInfo, goWelcome.EncryptedGroupInfo) {
			t.Fatal("tmc/mls and mls-go read another Welcome")
		}
		for index := range theirs.Secrets {
			tmcSecrets, goSecrets := theirs.Secrets[index], goWelcome.Secrets[index]
			if !bytes.Equal(tmcSecrets.NewMember, goSecrets.NewMember) ||
				!bytes.Equal(tmcSecrets.EncryptedGroupSecrets.KEMOutput, goSecrets.EncryptedGroupSecrets.KEMOutput) ||
				!bytes.Equal(tmcSecrets.EncryptedGroupSecrets.Ciphertext, goSecrets.EncryptedGroupSecrets.Ciphertext) {
				t.Fatalf("tmc/mls and mls-go read other group secrets at %d", index)
			}
		}
	})
}

// The seeds reach the rules: the engine decodes every stack's Welcome, mls_*'s, mls-go's and the mlswg's, and
// refuses each mutation.
func TestFuzzMlsWelcomeSeedsReachEveryRule(t *testing.T) {
	engine := newFuzzMlsEngine(t)
	decoded := 0
	for _, view := range fuzzMlsViews(t) {
		if !fuzzMlsWelcomeDecodes(engine, view.welcome) {
			t.Fatalf("a %#04x transcript's Welcome does not decode", view.cipherSuite)
		}
		decoded += 1
		for index, mutation := range fuzzMlsWelcomeMutations(view.welcome) {
			if fuzzMlsWelcomeDecodes(engine, mutation) {
				t.Errorf("a %#04x transcript's Welcome decodes after mutation %d", view.cipherSuite, index)
			}
		}
	}
	_, written, _ := fuzzMlsEngineWrites(t)
	if !fuzzMlsWelcomeDecodes(engine, written) {
		t.Error("the engine's own Welcome does not decode")
	}
	if decoded < 4 {
		t.Errorf("%d transcript Welcomes", decoded)
	}
}
