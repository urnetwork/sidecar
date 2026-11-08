// §22.10's vectors row (D-KEYS-10): the 0x0010 transcripts mlsinterop's stacks row records between mls_* and
// tmc/mls, checked in under testdata/mls/0x0010/ in the mlswg's passive-client form, replayed here through mls_*
// as their passive client, on the suite and settings production runs. mlsinterop replays the same files through
// tmc/mls, so both stacks hold to one set of bytes in every test.sh. A transcript's passive member is a tmc/mls leaf
// carrying credential 0xF552, whose credential is checked here for its own signature and its leaf's key alone: no
// log admits it.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// Each transcript joins at its Welcome on the tree beside it, and every commit, a member's PrivateMessage of either
// stack or an external commit of either, lands it on the epoch_authenticator the transcript names.
func TestMlsInteropTranscripts(t *testing.T) {
	type transcript struct {
		CipherSuite               uint16      `json:"cipher_suite"`
		KeyPackage                mlsHexBytes `json:"key_package"`
		SignaturePriv             mlsHexBytes `json:"signature_priv"`
		EncryptionPriv            mlsHexBytes `json:"encryption_priv"`
		InitPriv                  mlsHexBytes `json:"init_priv"`
		Welcome                   mlsHexBytes `json:"welcome"`
		RatchetTree               mlsHexBytes `json:"ratchet_tree"`
		InitialEpochAuthenticator mlsHexBytes `json:"initial_epoch_authenticator"`
		Epochs                    []struct {
			Proposals          []mlsHexBytes `json:"proposals"`
			Commit             mlsHexBytes   `json:"commit"`
			EpochAuthenticator mlsHexBytes   `json:"epoch_authenticator"`
		} `json:"epochs"`
	}
	paths, err := fs.Glob(mlsVectorFiles, path.Join("testdata", "mls", "0x0010", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no 0x0010 transcript is checked in")
	}
	suite := mlsSuite
	settings := defaultMlsGroupSettings()
	validator := mlsUrCredentialValidator(func(credential *protocol.UrMlsCredential) error { return nil })
	totalEpochs := 0
	for _, filePath := range paths {
		var transcripts []transcript
		mlsLoadVectorFile(t, "0x0010", path.Base(filePath[:len(filePath)-len(".json")]), &transcripts)
		for index, vector := range transcripts {
			if vector.CipherSuite != suite.value {
				t.Fatalf("%s %d: suite %#04x", filePath, index, vector.CipherSuite)
			}
			if len(vector.Epochs) < 10 {
				t.Errorf("%s %d: %d epochs, want the stacks row's 10 or more", filePath, index, len(vector.Epochs))
			}
			held := mlsTestVectorHeld(t, suite, vector.KeyPackage, vector.InitPriv, vector.EncryptionPriv, vector.SignaturePriv)
			welcome := &mlsWelcome{}
			if err := mlsUnmarshalMessageOf(vector.Welcome, mlsWireFormatWelcome, welcome); err != nil {
				t.Fatalf("%s %d: %v", filePath, index, err)
			}
			opened, err := openMlsWelcome(suite, welcome, held)
			if err != nil {
				t.Fatalf("%s %d: %v", filePath, index, err)
			}
			tree, err := decodeMlsRatchetTree(suite, settings.Tree, vector.RatchetTree)
			if err != nil {
				t.Fatalf("%s %d: %v", filePath, index, err)
			}
			state, err := opened.complete(tree, nil, settings, validator)
			if err != nil {
				t.Fatalf("%s %d: %v", filePath, index, err)
			}
			if !bytes.Equal(state.epochAuthenticator, vector.InitialEpochAuthenticator) {
				t.Fatalf("%s %d: another initial epoch_authenticator", filePath, index)
			}
			for epochIndex, epoch := range vector.Epochs {
				if len(epoch.Proposals) != 0 {
					t.Fatalf("%s %d: epoch %d names a standalone proposal, which §10.4 refuses", filePath, index, epochIndex)
				}
				staged, err := state.processCommit(epoch.Commit)
				if err != nil {
					t.Fatalf("%s %d: epoch %d: %v", filePath, index, epochIndex, err)
				}
				if staged.next == nil {
					t.Fatalf("%s %d: epoch %d removes the passive client", filePath, index, epochIndex)
				}
				state = staged.next
				if !bytes.Equal(state.epochAuthenticator, epoch.EpochAuthenticator) {
					t.Fatalf("%s %d: epoch %d: another epoch_authenticator", filePath, index, epochIndex)
				}
				totalEpochs += 1
			}
		}
	}
	t.Logf("%d transcript files, %d commits followed", len(paths), totalEpochs)
}

// Every transcript under testdata/mls/0x0010/ and 0x0001/ is the run its SOURCE describes: SOURCE names each file
// and gives its sha256, so a file recorded again without its provenance written down fails here.
func TestMlsTranscriptSourcesNameTheirFiles(t *testing.T) {
	for _, directory := range []string{"0x0010", "0x0001"} {
		source, err := mlsVectorFiles.ReadFile(path.Join("testdata", "mls", directory, "SOURCE"))
		if err != nil {
			t.Fatal(err)
		}
		nameSums := map[string]string{}
		name := ""
		for _, line := range strings.Split(string(source), "\n") {
			trimmed := strings.TrimSpace(line)
			switch {
			case line == trimmed && strings.HasSuffix(line, ".json"):
				name = line
			case name != "" && strings.HasPrefix(trimmed, "sha256 "):
				nameSums[name] = strings.TrimPrefix(trimmed, "sha256 ")
				name = ""
			}
		}
		paths, err := fs.Glob(mlsVectorFiles, path.Join("testdata", "mls", directory, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		if len(paths) == 0 || len(paths) != len(nameSums) {
			t.Errorf("%s: %d files, %d named in SOURCE", directory, len(paths), len(nameSums))
		}
		for _, filePath := range paths {
			encoded, err := mlsVectorFiles.ReadFile(filePath)
			if err != nil {
				t.Fatal(err)
			}
			if sum := fmt.Sprintf("%x", sha256.Sum256(encoded)); nameSums[path.Base(filePath)] != sum {
				t.Errorf("%s: sha256 %s, SOURCE gives %q", filePath, sum, nameSums[path.Base(filePath)])
			}
		}
	}
}
