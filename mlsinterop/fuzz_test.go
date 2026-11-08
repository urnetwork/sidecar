// §22.6's MLS messages row (D-TEST-4): ParseMlsHeader, the one keyless parse of a commit that gkm runs on every
// epoch object (§10.6), held to both peers' decoders, thomas-vilte/mls-go's framing and tmc/mls's codec, on the
// same bytes. What mls_* accepts, both peers must read as the same wire format, group, epoch, content type, sender
// kind and authenticated_data, and tmc/mls must encode back to the input byte for byte, so mls_* never takes a form
// RFC 9420's minimal encodings rule out. What mls_* refuses, a peer may accept: the subset refuses more (§10.4),
// every wire format but a commit's framing, a member's PublicMessage commit among them.
//
// The seeds run as an ordinary test in every test.sh (owner decision 101): every commit of the checked-in 0x0010
// transcripts, which mls_* and tmc/mls both made, every framed message of the mlswg's messages.json, and mutations
// of the commits, each a form one rule above decides: cut short, another version, another wire format, another
// epoch, a length prefix not minimal, bytes after the end. A failing input becomes a seed and a regression test here.

package mlsinterop

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/thomas-vilte/mls-go/framing"
	"github.com/tmc/mls"

	"github.com/urnetwork/sidecar"
)

// The commits of every checked-in 0x0010 transcript, and every hex value of the mlswg's messages.json.
func fuzzMlsSeeds(t testing.TB) (commits [][]byte, others [][]byte) {
	t.Helper()
	root := interopRootDirectory(t)
	paths, err := filepath.Glob(filepath.Join(root, "testdata", "mls", "0x0010", "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no 0x0010 transcript to seed from: %v", err)
	}
	for _, path := range paths {
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		transcripts := []struct {
			Epochs []struct {
				Commit string `json:"commit"`
			} `json:"epochs"`
		}{}
		if err := json.Unmarshal(encoded, &transcripts); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, transcript := range transcripts {
			for _, epoch := range transcript.Epochs {
				commit, err := hex.DecodeString(epoch.Commit)
				if err != nil {
					t.Fatal(err)
				}
				commits = append(commits, commit)
			}
		}
	}
	encoded, err := os.ReadFile(filepath.Join(root, "testdata", "mls", "mlswg", "messages.json"))
	if err != nil {
		t.Fatal(err)
	}
	vectors := []map[string]string{}
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		for _, value := range vector {
			if decoded, err := hex.DecodeString(value); err == nil {
				others = append(others, decoded)
			}
		}
	}
	return commits, others
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
	f.Fuzz(func(t *testing.T, encoded []byte) {
		header, err := sidecar.ParseMlsHeader(encoded)
		tmcMessage := &mls.Message{}
		tmcErr := mls.Unmarshal(encoded, tmcMessage)
		goMessage, goErr := framing.UnmarshalMLSMessage(encoded)
		if err != nil {
			return
		}
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
	})
}

// The seeds hold what the target needs to mean anything: mls_* reads every transcript commit, and refuses each
// mutation the rules above name, the minimal-encoding one among them.
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
}
