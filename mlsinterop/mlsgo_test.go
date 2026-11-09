// Owner decision 43's differential against thomas-vilte/mls-go, under suite 0x0001 (§10.4; D-TEST-4, D-TEST-7):
// mls-go has no 0x0010, and mls_* runs 0x0001 and basic credentials only in the root's own tests, which import no
// peer (D-REPO-2). So the two stacks meet through transcripts in the mlswg's passive-client form under
// testdata/mls/0x0001/, each replayed through both, in every test.sh:
//
//   - mlsgo.json is TestMlsGoLifecycle's run, mls-go's members alone, from the views of its two passive members, P
//     and Q. The root's TestMlsGoTranscripts replays it through mls_*, which so reads what mls-go writes: its
//     Welcomes, the ratchet tree in their GroupInfo, PrivateMessage commits with their paths, Adds and Removes, and
//     external commits with ExternalInit, a resync among them.
//   - mls.json is the root's TestMlsGoContinuation: mls_* joins mlsgo.json's group as P and goes on committing in
//     it, through its own code, from Q's view and from that of a joiner mls_* adds. TestMlsGoReplaysTheTranscripts
//     replays it through mls-go, which so reads what mls_* writes.
//
// Every member commit here is a PrivateMessage, the one framing the subset takes for a member's commit (D-KEYS-3):
// mls-go frames its own as PublicMessages unless asked, which the mlswg's passive-client vectors do throughout, so
// those vectors stop mls_* at their first commit. mls-go's leaves carry basic credentials and lifetimes without end,
// as the mlswg's do, so a transcript reads the same on any date.
//
// Set MLSINTEROP_MLSGO_TRANSCRIPT_OUT to an absolute path to write this run's mlsgo.json; the root's SOURCE file
// says how to record mls.json after it.

package mlsinterop

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// The pin the transcripts were recorded against, and the suite they run.
const (
	mlsGoModulePath    = "github.com/thomas-vilte/mls-go"
	mlsGoModuleVersion = "v1.6.0"
	mlsGoSuite         = ciphersuite.MLS128DHKEMX25519
)

// The checked-in transcripts are this pin's: a new mls-go reruns them and records them again (D-TEST-7).
func TestMlsGoIsPinned(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("no build info to read mls-go's version from")
	}
	for _, module := range info.Deps {
		if module.Path != mlsGoModulePath {
			continue
		}
		if module.Replace != nil || module.Version != mlsGoModuleVersion {
			t.Fatalf("%s is %s (replaced: %v); testdata/mls/0x0001/ was recorded against %s", mlsGoModulePath,
				module.Version, module.Replace != nil, mlsGoModuleVersion)
		}
		return
	}
	t.Fatalf("%s is not linked", mlsGoModulePath)
}

// One passive client's view in the mlswg's form, hex throughout. ratchet_tree is null when the Welcome's GroupInfo
// carries the tree, as mls-go's do, and mls_*'s never do (§10.6).
type mlsGoTranscript struct {
	CipherSuite               uint16                  `json:"cipher_suite"`
	ExternalPsks              []any                   `json:"external_psks"`
	KeyPackage                string                  `json:"key_package"`
	SignaturePriv             string                  `json:"signature_priv"`
	EncryptionPriv            string                  `json:"encryption_priv"`
	InitPriv                  string                  `json:"init_priv"`
	Welcome                   string                  `json:"welcome"`
	RatchetTree               *string                 `json:"ratchet_tree"`
	InitialEpochAuthenticator string                  `json:"initial_epoch_authenticator"`
	Epochs                    []*mlsGoTranscriptEpoch `json:"epochs"`
}

type mlsGoTranscriptEpoch struct {
	Proposals          []string `json:"proposals"`
	Commit             string   `json:"commit"`
	EpochAuthenticator string   `json:"epoch_authenticator"`
}

// One mls-go member: its basic credential, its signature key, the KeyPackage it joins or creates under, with its
// private keys, and its group once it has one.
type mlsGoMember struct {
	name         string
	credential   *credentials.CredentialWithKey
	signatureKey *ciphersuite.SignaturePrivateKey
	keyPackage   *keypackages.KeyPackage
	privateKeys  *keypackages.KeyPackagePrivateKeys
	group        *group.Group
}

func newMlsGoMember(t testing.TB, name string) *mlsGoMember {
	t.Helper()
	credential, signatureKey, err := credentials.GenerateCredentialWithKeyForCS([]byte("mls-go "+name), mlsGoSuite)
	if err != nil {
		t.Fatal(err)
	}
	keyPackage, privateKeys, err := keypackages.Generate(credential, mlsGoSuite, keypackages.InfiniteLifetime())
	if err != nil {
		t.Fatal(err)
	}
	return &mlsGoMember{name: name, credential: credential, signatureKey: signatureKey, keyPackage: keyPackage, privateKeys: privateKeys}
}

// The KeyPackage as an MLSMessage, as the mlswg's key_package is.
func (self *mlsGoMember) keyPackageMessage() []byte {
	return (&framing.MLSMessage{KeyPackage: self.keyPackage.Marshal()}).Marshal()
}

func (self *mlsGoMember) leaf() group.LeafNodeIndex {
	return self.group.OwnLeafIndex()
}

// The lifecycle's members now, and the passive members' views as they grow.
type mlsGoLifecycle struct {
	t       testing.TB
	members []*mlsGoMember
	// the passive members, whose views are the transcript
	passives    []*mlsGoMember
	transcripts []*mlsGoTranscript
	// the commit delivered since the last agreement
	delivered []byte
	epochs    int
}

// Commits what the committer's group holds pending, together with adds and removes, as a PrivateMessage under the
// epoch it leaves, then merges it. Returns the commit and, with adds, the Welcome, both as MLSMessages.
func (self *mlsGoLifecycle) commit(committer *mlsGoMember, adds []*mlsGoMember, removes []*mlsGoMember) (commit []byte, welcome []byte) {
	t := self.t
	t.Helper()
	g := committer.group
	for _, removed := range removes {
		if _, err := g.RemoveMember(removed.leaf()); err != nil {
			t.Fatal(err)
		}
	}
	for _, added := range adds {
		if _, err := g.AddMember(added.keyPackage); err != nil {
			t.Fatal(err)
		}
	}
	staged, err := g.CommitWithFormat(committer.signatureKey, committer.signatureKey.PublicKey(), nil, framing.WireFormatPrivateMessage)
	if err != nil {
		t.Fatalf("%s commits: %v", committer.name, err)
	}
	private, err := framing.Encrypt(framing.EncryptParams{
		AuthContent:      staged.AuthenticatedContent(),
		SenderLeafIndex:  uint32(g.OwnLeafIndex()),
		CipherSuite:      g.CipherSuite(),
		SenderDataSecret: g.EpochSecrets().SenderDataSecret,
		SecretTree:       g.SecretTree(),
	})
	if err != nil {
		t.Fatalf("%s seals its commit: %v", committer.name, err)
	}
	commit = framing.NewMLSMessagePrivate(private).Marshal()
	keyPackages := []*keypackages.KeyPackage{}
	for _, added := range adds {
		keyPackages = append(keyPackages, added.keyPackage)
	}
	joinerSecret := staged.JoinerSecret()
	if err := g.MergeCommit(staged); err != nil {
		t.Fatal(err)
	}
	if len(adds) == 0 {
		return commit, nil
	}
	created, err := g.CreateWelcomeWithOpts(keyPackages, committer.signatureKey,
		group.WithJoinerSecret(joinerSecret),
		group.WithPSKIDs(staged.PskIDs()),
		group.WithPSKSecret(staged.RawPskSecret()),
		group.WithStagedCommit(staged),
	)
	if err != nil {
		t.Fatalf("%s's Welcome: %v", committer.name, err)
	}
	return commit, (&framing.MLSMessage{Welcome: created.Marshal()}).Marshal()
}

// Takes a commit into every other current member's group, removed members aside.
func (self *mlsGoLifecycle) deliver(committer *mlsGoMember, commit []byte, removed ...*mlsGoMember) {
	t := self.t
	t.Helper()
	for _, member := range self.members {
		if member == committer || slices.Contains(removed, member) || member.group == nil {
			continue
		}
		if err := mlsGoProcess(member.group, commit); err != nil {
			t.Fatalf("%s refuses %s's commit: %v", member.name, committer.name, err)
		}
	}
	remaining := []*mlsGoMember{}
	for _, member := range self.members {
		if !slices.Contains(removed, member) {
			remaining = append(remaining, member)
		}
	}
	self.members = remaining
	self.delivered = commit
}

// Joins each joiner to the Welcome, from the tree in its GroupInfo.
func (self *mlsGoLifecycle) join(welcome []byte, joiners ...*mlsGoMember) {
	t := self.t
	t.Helper()
	for _, joiner := range joiners {
		joined, err := mlsGoJoin(welcome, joiner.keyPackage, joiner.privateKeys)
		if err != nil {
			t.Fatalf("%s does not join: %v", joiner.name, err)
		}
		joiner.group = joined
		self.members = append(self.members, joiner)
	}
}

// Every current member at one epoch with one authenticator and one output under each label; the delivered commit
// joins each passive member's view.
func (self *mlsGoLifecycle) agree(step string) {
	t := self.t
	t.Helper()
	first := self.members[0].group
	epoch := first.Epoch().AsUint64()
	epochAuthenticator := first.EpochAuthenticator()
	kek, err := first.Export("UR evs 1.0 kek", []byte("repo"), 32)
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range self.members[1:] {
		if member.group.Epoch().AsUint64() != epoch {
			t.Fatalf("%s: %s is at epoch %d, %s at %d", step, member.name, member.group.Epoch().AsUint64(), self.members[0].name, epoch)
		}
		if !bytes.Equal(member.group.EpochAuthenticator(), epochAuthenticator) {
			t.Fatalf("%s: %s computes another epoch_authenticator at epoch %d", step, member.name, epoch)
		}
		memberKek, err := member.group.Export("UR evs 1.0 kek", []byte("repo"), 32)
		if err != nil || !bytes.Equal(memberKek, kek) {
			t.Fatalf("%s: %s exports another value at epoch %d: %v", step, member.name, epoch, err)
		}
	}
	if self.delivered != nil {
		for _, transcript := range self.transcripts {
			transcript.Epochs = append(transcript.Epochs, &mlsGoTranscriptEpoch{
				Proposals:          []string{},
				Commit:             hex.EncodeToString(self.delivered),
				EpochAuthenticator: hex.EncodeToString(epochAuthenticator),
			})
		}
	}
	self.delivered = nil
	self.epochs = int(epoch)
	t.Logf("epoch %d after %s: %d members agree", epoch, step, len(self.members))
}

// A member's commit as a PrivateMessage or an external commit as a PublicMessage, into g.
func mlsGoProcess(g *group.Group, encoded []byte) error {
	message, err := framing.UnmarshalMLSMessage(encoded)
	if err != nil {
		return err
	}
	if private, ok := message.AsPrivate(); ok {
		return g.ProcessPrivateMessage(private)
	}
	if public, ok := message.AsPublic(); ok {
		return g.ProcessPublicMessage(public)
	}
	return framing.ErrInvalidMessage
}

// A join through an MLSMessage Welcome. mls-go takes the ratchet tree from the Welcome's GroupInfo alone.
func mlsGoJoin(welcome []byte, keyPackage *keypackages.KeyPackage, privateKeys *keypackages.KeyPackagePrivateKeys) (*group.Group, error) {
	message, err := framing.UnmarshalMLSMessage(welcome)
	if err != nil {
		return nil, err
	}
	decoded, err := group.UnmarshalWelcome(message.Welcome)
	if err != nil {
		return nil, err
	}
	return group.JoinFromWelcome(decoded, keyPackage, privateKeys, nil)
}

// Whether the Welcome's group secrets under initKey carry a path_secret, read as mls-go's JoinFromWelcome reads
// them. mls-go v1.6.0 joins a Welcome whose GroupInfo carries no tree on a one-leaf stand-in tree, and with a
// path_secret it then walks the committer's direct path in that tree, which never reaches its root: JoinFromWelcome
// does not return (treesync's DirectPath). A tree-less Welcome is the only kind mls_* sends (§10.6), so a view of one
// that mls-go is to replay must come from a commit without a path.
func mlsGoWelcomeCarriesPathSecret(t *testing.T, welcome []byte, initKey *ecdh.PrivateKey) bool {
	t.Helper()
	message, err := framing.UnmarshalMLSMessage(welcome)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := group.UnmarshalWelcome(message.Welcome)
	if err != nil {
		t.Fatal(err)
	}
	for index := range decoded.Secrets {
		opened, err := ciphersuite.DecryptWithLabel(initKey.Bytes(), "Welcome", decoded.EncryptedGroupInfo,
			&decoded.Secrets[index].EncryptedGroupSecrets, decoded.CipherSuite)
		if err != nil {
			continue
		}
		secrets, err := group.UnmarshalGroupSecrets(opened)
		if err != nil {
			t.Fatal(err)
		}
		return len(secrets.PathSecret) != 0
	}
	t.Fatal("no group secrets of the Welcome open under the init key")
	return false
}

// The scripted lifecycle: mls-go alone, every kind of step mls_* takes, past 10 epochs.
func TestMlsGoLifecycle(t *testing.T) {
	life := &mlsGoLifecycle{t: t}

	a := newMlsGoMember(t, "A")
	groupId, err := group.NewGroupIDRandom()
	if err != nil {
		t.Fatal(err)
	}
	created, err := group.NewGroup(groupId, mlsGoSuite, a.keyPackage, a.privateKeys)
	if err != nil {
		t.Fatal(err)
	}
	a.group = created
	life.members = []*mlsGoMember{a}
	life.agree("create")

	// A adds B and the passive P and Q, which join by Welcome
	b, p, q := newMlsGoMember(t, "B"), newMlsGoMember(t, "P"), newMlsGoMember(t, "Q")
	commit, welcome := life.commit(a, []*mlsGoMember{b, p, q}, nil)
	life.deliver(a, commit)
	life.join(welcome, b, p, q)
	life.agree("A adds B, P and Q by Welcome")
	// each view starts at the Welcome, with the commits after it
	life.passives = []*mlsGoMember{p, q}
	for _, passive := range life.passives {
		life.transcripts = append(life.transcripts, &mlsGoTranscript{
			CipherSuite:               uint16(mlsGoSuite),
			ExternalPsks:              []any{},
			KeyPackage:                hex.EncodeToString(passive.keyPackageMessage()),
			SignaturePriv:             hex.EncodeToString(passive.credential.Ed25519PrivateKey.Seed()),
			EncryptionPriv:            hex.EncodeToString(passive.privateKeys.EncryptionKey.Bytes()),
			InitPriv:                  hex.EncodeToString(passive.privateKeys.InitKey.Bytes()),
			Welcome:                   hex.EncodeToString(welcome),
			InitialEpochAuthenticator: hex.EncodeToString(passive.group.EpochAuthenticator()),
			Epochs:                    []*mlsGoTranscriptEpoch{},
		})
	}

	commit, _ = life.commit(b, nil, nil)
	life.deliver(b, commit)
	life.agree("B commits a path")

	c := newMlsGoMember(t, "C")
	commit, welcome = life.commit(a, []*mlsGoMember{c}, nil)
	life.deliver(a, commit)
	life.join(welcome, c)
	life.agree("A adds C by Welcome")
	// what the replay's guard reads: a Welcome from a commit with a path carries a path_secret, A's first did not
	if !mlsGoWelcomeCarriesPathSecret(t, welcome, c.privateKeys.InitKey) {
		t.Error("a Welcome from a commit with a path carries no path_secret")
	}
	if first, err := hex.DecodeString(life.transcripts[0].Welcome); err != nil || mlsGoWelcomeCarriesPathSecret(t, first, p.privateKeys.InitKey) {
		t.Errorf("the Welcome of A's first commit, which has no path, carries a path_secret: %v", err)
	}

	commit, _ = life.commit(c, nil, nil)
	life.deliver(c, commit)
	life.agree("C commits a path")

	commit, _ = life.commit(c, nil, []*mlsGoMember{b})
	life.deliver(c, commit, b)
	life.agree("C removes B")

	commit, _ = life.commit(a, nil, nil)
	life.deliver(a, commit)
	life.agree("A commits a path")

	// X joins by external commit with ExternalInit from A's GroupInfo, as bytes
	x := newMlsGoMember(t, "X")
	external := func(joiner *mlsGoMember, from *mlsGoMember, removePriorLeaf *group.LeafNodeIndex) []byte {
		info, err := from.group.GetGroupInfo(from.signatureKey)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := group.UnmarshalGroupInfo(info.Marshal())
		if err != nil {
			t.Fatal(err)
		}
		joined, staged, err := group.ExternalCommit(decoded, mlsGoSuite, joiner.signatureKey, joiner.signatureKey.PublicKey(),
			removePriorLeaf, joiner.credential.Credential)
		if err != nil {
			t.Fatalf("%s's external commit: %v", joiner.name, err)
		}
		joiner.group = joined
		authenticated := staged.AuthenticatedContent()
		return framing.NewMLSMessagePublic(&framing.PublicMessage{Content: authenticated.Content, Auth: authenticated.Auth}).Marshal()
	}
	commit = external(x, a, nil)
	life.deliver(x, commit)
	life.members = append(life.members, x)
	life.agree("X joins by external commit")

	commit, _ = life.commit(x, nil, nil)
	life.deliver(x, commit)
	life.agree("X commits a path")

	// X resyncs: an external commit from C's GroupInfo, under a new signature key, removing its own old leaf
	old := x.leaf()
	credential, signatureKey, err := credentials.GenerateCredentialWithKeyForCS([]byte("mls-go X"), mlsGoSuite)
	if err != nil {
		t.Fatal(err)
	}
	x.credential, x.signatureKey = credential, signatureKey
	x.group = nil
	life.members = slices.DeleteFunc(life.members, func(member *mlsGoMember) bool { return member == x })
	commit = external(x, c, &old)
	life.deliver(x, commit)
	life.members = append(life.members, x)
	life.agree("X resyncs by external commit, removing its old leaf")

	commit, _ = life.commit(a, nil, []*mlsGoMember{x})
	life.deliver(a, commit, x)
	life.agree("A removes X")

	d := newMlsGoMember(t, "D")
	commit, welcome = life.commit(c, []*mlsGoMember{d}, nil)
	life.deliver(c, commit)
	life.join(welcome, d)
	life.agree("C adds D by Welcome")

	commit, _ = life.commit(d, nil, nil)
	life.deliver(d, commit)
	life.agree("D commits a path")

	commit, _ = life.commit(a, nil, nil)
	life.deliver(a, commit)
	life.agree("A commits a path")

	if life.epochs < 10 {
		t.Errorf("the lifecycle reached epoch %d, want 10 or more", life.epochs)
	}
	for _, passive := range life.passives {
		if !slices.Contains(life.members, passive) {
			t.Fatalf("passive %s left the group", passive.name)
		}
	}
	if path := os.Getenv("MLSINTEROP_MLSGO_TRANSCRIPT_OUT"); path != "" {
		encoded, err := json.MarshalIndent(life.transcripts, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote P's and Q's views, %d epochs each, to %s", len(life.transcripts[0].Epochs), path)
	}
}

// Every checked-in 0x0001 transcript replays through mls-go as its passive client: the Welcome joins and lands on the
// initial epoch_authenticator, and each commit on the one the transcript names. mls.json's views are mls_*'s
// writing, so this is the half of the differential where mls-go reads mls_*. mls-go takes a Welcome's tree only from
// its GroupInfo, and mls_*'s Welcome carries none (§10.6), so a view joining mls_*'s Welcome is a join alone: mls-go
// then holds no tree to follow commits with, and the opened group secrets, the GroupInfo they decrypt, its
// confirmation tag and the joined epoch's authenticator are what it checks. The writer of mls.json keeps such views
// to their join.
func TestMlsGoReplaysTheTranscripts(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(interopRootDirectory(t), "testdata", "mls", "0x0001", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, path := range paths {
		names = append(names, filepath.Base(path))
	}
	for _, want := range []string{"mlsgo.json", "mls.json"} {
		if !slices.Contains(names, want) {
			t.Fatalf("testdata/mls/0x0001/%s is not checked in", want)
		}
	}
	decode := func(text string) []byte {
		decoded, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	followed, joinsOnly := 0, 0
	for _, path := range paths {
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		transcripts := []*mlsGoTranscript{}
		if err := json.Unmarshal(encoded, &transcripts); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for index, transcript := range transcripts {
			if transcript.CipherSuite != uint16(mlsGoSuite) {
				t.Fatalf("%s %d: suite %#04x", path, index, transcript.CipherSuite)
			}
			keyPackageMessage, err := framing.UnmarshalMLSMessage(decode(transcript.KeyPackage))
			if err != nil || keyPackageMessage.KeyPackage == nil {
				t.Fatalf("%s %d: key_package: %v", path, index, err)
			}
			keyPackage, err := keypackages.UnmarshalKeyPackage(keyPackageMessage.KeyPackage)
			if err != nil {
				t.Fatalf("%s %d: key_package: %v", path, index, err)
			}
			initKey, err := ecdh.X25519().NewPrivateKey(decode(transcript.InitPriv))
			if err != nil {
				t.Fatal(err)
			}
			encryptionKey, err := ecdh.X25519().NewPrivateKey(decode(transcript.EncryptionPriv))
			if err != nil {
				t.Fatal(err)
			}
			if transcript.RatchetTree != nil && mlsGoWelcomeCarriesPathSecret(t, decode(transcript.Welcome), initKey) {
				t.Fatalf("%s %d: a Welcome with no tree and a path_secret, which mls-go v1.6.0 never returns from joining", path, index)
			}
			joined, err := mlsGoJoin(decode(transcript.Welcome), keyPackage, &keypackages.KeyPackagePrivateKeys{InitKey: initKey, EncryptionKey: encryptionKey})
			if err != nil {
				t.Fatalf("%s %d: mls-go does not join: %v", path, index, err)
			}
			if !bytes.Equal(joined.EpochAuthenticator(), decode(transcript.InitialEpochAuthenticator)) {
				t.Fatalf("%s %d: another initial epoch_authenticator", path, index)
			}
			if transcript.RatchetTree != nil {
				if len(transcript.Epochs) != 0 {
					t.Fatalf("%s %d: a view joining a Welcome with no tree follows %d commits mls-go cannot", path, index, len(transcript.Epochs))
				}
				joinsOnly += 1
				t.Logf("%s %d: joined mls_*'s Welcome at epoch %d", filepath.Base(path), index, joined.Epoch().AsUint64())
				continue
			}
			for epochIndex, epoch := range transcript.Epochs {
				if len(epoch.Proposals) != 0 {
					t.Fatalf("%s %d: epoch %d names a standalone proposal, which §10.4 refuses", path, index, epochIndex)
				}
				if err := mlsGoProcess(joined, decode(epoch.Commit)); err != nil {
					t.Fatalf("%s %d: epoch %d: mls-go refuses the commit: %v", path, index, epochIndex, err)
				}
				if !bytes.Equal(joined.EpochAuthenticator(), decode(epoch.EpochAuthenticator)) {
					t.Fatalf("%s %d: epoch %d: another epoch_authenticator", path, index, epochIndex)
				}
				followed += 1
			}
			t.Logf("%s %d: joined and followed %d commits to epoch %d", filepath.Base(path), index, len(transcript.Epochs), joined.Epoch().AsUint64())
		}
	}
	t.Logf("%d commits followed, %d joins alone", followed, joinsOnly)
}
