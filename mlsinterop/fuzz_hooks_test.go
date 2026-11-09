//go:build sidecar_testhooks

// §22.6's GroupInfo and ratchet tree targets (D-TEST-4), held to the peers under fuzz_test.go's rule: what mls_*
// decodes, both peers read as the same structure, and tmc/mls encodes back unchanged. Nothing the root exports reads
// either structure without judging it too, so mls_*'s decoders come through MlsTestDecodeGroupInfo and
// MlsTestDecodeRatchetTree, which the root has under sidecar_testhooks alone; make check and landcheck run this
// module's tests in that build as in the plain one.
//
// mls-go reads a tree under its own suite: it parses every parent's key as an X25519 key and drops a credential's
// body when it has no codec for the type, and mls_* outside the root's tests reads 0xF552 alone. So mls-go is held
// to a tree mls_* reads only when every key in it is X25519's size, and then to everything but credential bodies.
// The mlswg's trees carry basic credentials, so the seeds also carry each with its credentials made 0xF552 ones,
// their bodies the basic identities: decoding checks no signature, and the trees are the same in every other byte.

package mlsinterop

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/treesync"
	"github.com/tmc/mls"

	"github.com/urnetwork/sidecar"
)

// A GroupInfo mls-go writes under 0x0001: its creator's, of a group of two, as an MLSMessage.
func fuzzMlsGoGroupInfo(t testing.TB) []byte {
	t.Helper()
	life := &mlsGoLifecycle{t: t}
	creator, joiner := newMlsGoMember(t, "A"), newMlsGoMember(t, "B")
	groupId, err := group.NewGroupIDRandom()
	if err != nil {
		t.Fatal(err)
	}
	if creator.group, err = group.NewGroup(groupId, mlsGoSuite, creator.keyPackage, creator.privateKeys); err != nil {
		t.Fatal(err)
	}
	life.members = []*mlsGoMember{creator}
	life.commit(creator, []*mlsGoMember{joiner}, nil)
	info, err := creator.group.GetGroupInfo(creator.signatureKey)
	if err != nil {
		t.Fatal(err)
	}
	return (&framing.MLSMessage{GroupInfo: info.Marshal()}).Marshal()
}

// A GroupInfo cut short, with a byte after its end, as another version, as another wire format, with another
// version inside its GroupContext, with its group_id's length written in two bytes, and with its first extension
// twice, which RFC 9420 §13.4 forbids.
func fuzzMlsGroupInfoMutations(t testing.TB, groupInfo []byte) [][]byte {
	t.Helper()
	if len(groupInfo) < 10 {
		return nil
	}
	mutations := [][]byte{groupInfo[:len(groupInfo)-1], append(bytes.Clone(groupInfo), 0)}
	for _, offset := range []int{1, 3, 5} {
		mutated := bytes.Clone(groupInfo)
		mutated[offset] ^= 2
		mutations = append(mutations, mutated)
	}
	// version, wire format, then the GroupContext's version and cipher_suite take eight bytes
	if groupInfo[8]&0xc0 == 0 {
		mutations = append(mutations, append(append(bytes.Clone(groupInfo[:8]), 0x40), groupInfo[8:]...))
	}
	message := &mls.Message{}
	if err := mls.Unmarshal(groupInfo, message); err == nil && message.GroupInfo != nil && len(message.GroupInfo.Extensions) != 0 {
		message.GroupInfo.Extensions = append(message.GroupInfo.Extensions, message.GroupInfo.Extensions[0])
		if encoded, err := mls.Marshal(message); err == nil {
			mutations = append(mutations, encoded)
		}
	}
	return mutations
}

// GroupInfos of mls_*, under 0x0010, and of mls-go, under 0x0001, the mlswg's of other implementations, mutations
// of the first two, and the seed files.
func fuzzMlsGroupInfoSeeds(t testing.TB) (written [][]byte, seeds [][]byte) {
	t.Helper()
	_, _, ours := fuzzMlsEngineWrites(t)
	written = [][]byte{ours, fuzzMlsGoGroupInfo(t)}
	seeds = append(seeds, written...)
	for _, groupInfo := range written {
		seeds = append(seeds, fuzzMlsGroupInfoMutations(t, groupInfo)...)
	}
	encoded, err := os.ReadFile(filepath.Join(interopRootDirectory(t), "testdata", "mls", "mlswg", "messages.json"))
	if err != nil {
		t.Fatal(err)
	}
	vectors := []struct {
		GroupInfo string `json:"mls_group_info"`
	}{}
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		if decoded, err := hex.DecodeString(vector.GroupInfo); err == nil {
			seeds = append(seeds, decoded)
		}
	}
	return written, append(seeds, fuzzMlsSeedFiles(t, "mls_group_info")...)
}

// The one GroupInfo mls-go refuses that mls_*'s decoder reads, a difference of where and not of whether: one of a
// suite mls-go implements whose tree_hash, confirmed_transcript_hash or confirmation_tag is neither empty nor that
// suite's Nh. mls-go refuses it as it decodes (RFC 9420 §7.8, §8.2); mls_* decodes the suite from the same bytes and
// refuses it once the suite is known, before anything derives from it (checkHashLengths in openMlsWelcome and
// checkTree; TestMlsGroupContextHashLengthsAreTheSuites). This target found the confirmed_transcript_hash case, which
// mls_* took until then: testdata/fuzz/mls_group_info/confirmed_transcript_hash_of_three_bytes.
func fuzzMlsGoRefusesHashLengths(groupInfo *mls.GroupInfo) bool {
	hashLength := ciphersuite.CipherSuite(groupInfo.GroupContext.CipherSuite).HashLength()
	off := func(value []byte) bool {
		return len(value) != 0 && len(value) != hashLength
	}
	return 0 < hashLength && (off(groupInfo.GroupContext.TreeHash) || off(groupInfo.GroupContext.ConfirmedTranscriptHash) ||
		off(groupInfo.ConfirmationTag))
}

func FuzzMlsGroupInfoAgreesWithPeers(f *testing.F) {
	_, seeds := fuzzMlsGroupInfoSeeds(f)
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		reencoded, err := sidecar.MlsTestDecodeGroupInfo(encoded)
		if err != nil {
			return
		}
		tmcMessage := &mls.Message{}
		tmcErr := mls.Unmarshal(encoded, tmcMessage)
		goMessage, goErr := framing.UnmarshalMLSMessage(encoded)
		var goInfo *group.Info
		if goErr == nil {
			goInfo, goErr = group.UnmarshalGroupInfo(goMessage.GroupInfo)
		}
		if !bytes.Equal(reencoded, encoded) {
			t.Fatal("mls_* decodes a GroupInfo it does not encode back to itself")
		}
		if tmcErr != nil || tmcMessage.GroupInfo == nil {
			t.Fatalf("mls_* decodes a GroupInfo tmc/mls does not: %v", tmcErr)
		}
		if again, err := mls.Marshal(tmcMessage); err != nil || !bytes.Equal(again, encoded) {
			t.Fatalf("mls_* decodes a GroupInfo tmc/mls does not encode back to itself: %v", err)
		}
		if goErr != nil {
			if !fuzzMlsGoRefusesHashLengths(tmcMessage.GroupInfo) {
				t.Fatalf("mls_* decodes a GroupInfo mls-go does not: %v", goErr)
			}
			return
		}
		if !bytes.Equal(goInfo.Marshal(), encoded[4:]) {
			t.Fatal("mls_* decodes a GroupInfo mls-go does not encode back to itself")
		}
		theirs, goContext := tmcMessage.GroupInfo, goInfo.GroupContext
		context := theirs.GroupContext
		sameExtensions := func(tmcExtensions mls.Extensions, goExtensions []group.Extension) bool {
			if len(tmcExtensions) != len(goExtensions) {
				return false
			}
			for index := range tmcExtensions {
				if uint16(tmcExtensions[index].Type) != uint16(goExtensions[index].Type) || !bytes.Equal(tmcExtensions[index].Data, goExtensions[index].Data) {
					return false
				}
			}
			return true
		}
		if uint16(context.Version) != uint16(goContext.Version) || uint16(context.CipherSuite) != uint16(goContext.CipherSuite) ||
			!bytes.Equal(context.GroupID, goContext.GroupID.AsSlice()) || context.Epoch != goContext.Epoch.AsUint64() ||
			!bytes.Equal(context.TreeHash, goContext.TreeHash) || !bytes.Equal(context.ConfirmedTranscriptHash, goContext.ConfirmedTranscriptHash) ||
			!sameExtensions(context.Extensions, goContext.Extensions) {
			t.Fatal("tmc/mls and mls-go read another GroupContext")
		}
		if !sameExtensions(theirs.Extensions, goInfo.Extensions) || !bytes.Equal(theirs.ConfirmationTag, goInfo.ConfirmationTag) ||
			theirs.Signer != uint32(goInfo.Signer) || !bytes.Equal(theirs.Signature, goInfo.Signature) {
			t.Fatal("tmc/mls and mls-go read another GroupInfo")
		}
	})
}

// mls_* decodes its own GroupInfo and mls-go's, and refuses each mutation.
func TestFuzzMlsGroupInfoSeedsReachEveryRule(t *testing.T) {
	written, _ := fuzzMlsGroupInfoSeeds(t)
	for index, groupInfo := range written {
		if reencoded, err := sidecar.MlsTestDecodeGroupInfo(groupInfo); err != nil || !bytes.Equal(reencoded, groupInfo) {
			t.Fatalf("GroupInfo %d: %v", index, err)
		}
		mutations := fuzzMlsGroupInfoMutations(t, groupInfo)
		if len(mutations) < 7 {
			t.Errorf("GroupInfo %d: %d mutations", index, len(mutations))
		}
		for mutationIndex, mutation := range mutations {
			if _, err := sidecar.MlsTestDecodeGroupInfo(mutation); err == nil {
				t.Errorf("GroupInfo %d decodes after mutation %d", index, mutationIndex)
			}
		}
	}
}

// encoded, a tree tmc/mls reads, with every basic credential made a 0xF552 one whose body is the basic identity;
// nil when tmc/mls does not read it.
func fuzzMlsTreeAsUrSidecar(encoded []byte) []byte {
	tree := mls.RatchetTree{}
	if err := mls.Unmarshal(encoded, &tree); err != nil {
		return nil
	}
	for _, node := range tree {
		if node != nil && node.Leaf != nil && node.Leaf.Credential.Type == mls.CredentialTypeBasic {
			node.Leaf.Credential = mls.Credential{Type: tmcCredentialTypeUrSidecar, Body: &tmcUrCredential{encoded: node.Leaf.Credential.Identity}}
		}
	}
	reencoded, err := mls.Marshal(&tree)
	if err != nil {
		return nil
	}
	return reencoded
}

// Whether every HPKE key of a tree tmc/mls read is X25519's size, so mls-go can read it as a 0x0001 tree.
func fuzzMlsTreeIsX25519(tree mls.RatchetTree) bool {
	for _, node := range tree {
		switch {
		case node == nil:
		case node.Leaf != nil && len(node.Leaf.EncryptionKey) != 32:
			return false
		case node.Parent != nil && len(node.Parent.EncryptionKey) != 32:
			return false
		}
	}
	return true
}

// A tree cut short, with a byte after its end, with a blank node after its last one, which RFC 9420 §12.4.3.3
// forbids, and with its length written in four bytes.
func fuzzMlsTreeMutations(encoded []byte) [][]byte {
	if len(encoded) < 4 {
		return nil
	}
	mutations := [][]byte{encoded[:len(encoded)-1], append(bytes.Clone(encoded), 0)}
	tree := mls.RatchetTree{}
	if err := mls.Unmarshal(encoded, &tree); err == nil {
		tree = append(tree, nil)
		if blank, err := mls.Marshal(&tree); err == nil {
			mutations = append(mutations, blank)
		}
	}
	// a two-byte length, 0b01 and fourteen bits, as four bytes, 0b10 and thirty
	if encoded[0]&0xc0 == 0x40 {
		length := int(encoded[0]&0x3f)<<8 | int(encoded[1])
		mutations = append(mutations, append([]byte{0x80, 0, byte(length >> 8), byte(length)}, encoded[2:]...))
	}
	return mutations
}

// Trees: the 0x0010 transcript's and the engine's, mls_*'s and tmc/mls's; mls.json's, mls_*'s under 0x0001 with
// basic credentials, as written and made 0xF552; the mlswg's of other implementations, as written and made 0xF552;
// mutations of each; and the seed files.
func fuzzMlsTreeSeeds(t testing.TB) (urSidecar [][]byte, basic [][]byte, seeds [][]byte) {
	t.Helper()
	for _, view := range fuzzMlsViews(t) {
		switch {
		case view.ratchetTree == nil:
		case view.cipherSuite == 0x0010:
			urSidecar = append(urSidecar, view.ratchetTree)
		default:
			basic = append(basic, view.ratchetTree)
		}
	}
	_, _, groupInfo := fuzzMlsEngineWrites(t)
	message := &mls.Message{}
	if err := mls.Unmarshal(groupInfo, message); err != nil || message.GroupInfo == nil {
		t.Fatalf("tmc/mls does not read the engine's GroupInfo: %v", err)
	}
	if extension := message.GroupInfo.Extensions.Find(mls.ExtensionTypeRatchetTree); extension != nil {
		urSidecar = append(urSidecar, extension.Data)
	}
	encoded, err := os.ReadFile(filepath.Join(interopRootDirectory(t), "testdata", "mls", "mlswg", "tree-validation.json"))
	if err != nil {
		t.Fatal(err)
	}
	vectors := []struct {
		Tree string `json:"tree"`
	}{}
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		if decoded, err := hex.DecodeString(vector.Tree); err == nil {
			basic = append(basic, decoded)
		}
	}
	for _, tree := range basic {
		if made := fuzzMlsTreeAsUrSidecar(tree); made != nil {
			urSidecar = append(urSidecar, made)
		}
	}
	for _, tree := range slices.Concat(urSidecar, basic) {
		seeds = append(seeds, tree)
		seeds = append(seeds, fuzzMlsTreeMutations(tree)...)
	}
	return urSidecar, basic, append(seeds, fuzzMlsSeedFiles(t, "mls_ratchet_tree")...)
}

// tmc/mls's reading and mls-go's of one tree, node by node, credential bodies aside; mls-go's array may run on past
// tmc/mls's in blanks, since it fills a tree out to a power of two.
func fuzzMlsTreesAgree(t *testing.T, tree mls.RatchetTree, goTree *treesync.RatchetTree) {
	t.Helper()
	if len(goTree.Nodes) < len(tree) {
		t.Fatalf("mls-go reads %d nodes, tmc/mls %d", len(goTree.Nodes), len(tree))
	}
	for index, goNode := range goTree.Nodes[len(tree):] {
		if goNode.State != treesync.NodeStateEmpty {
			t.Fatalf("mls-go reads node %d past the tree's end", len(tree)+index)
		}
	}
	sameUint16s := func(tmcValues []uint16, goValues []uint16) bool {
		return slices.Equal(tmcValues, goValues) || (len(tmcValues) == 0 && len(goValues) == 0)
	}
	toUint16s := func(count int, value func(int) uint16) []uint16 {
		values := []uint16{}
		for index := range count {
			values = append(values, value(index))
		}
		return values
	}
	for index, node := range tree {
		goNode := goTree.Nodes[index]
		switch {
		case node == nil:
			if goNode.State != treesync.NodeStateEmpty {
				t.Fatalf("node %d: blank to tmc/mls, not to mls-go", index)
			}
		case node.Leaf != nil:
			leaf, goLeaf := node.Leaf, goNode.LeafData
			if goLeaf == nil || goLeaf.Credential == nil || goLeaf.Capabilities == nil {
				t.Fatalf("node %d: a leaf to tmc/mls, not to mls-go", index)
			}
			capabilities, goCapabilities := leaf.Capabilities, goLeaf.Capabilities
			same := bytes.Equal(leaf.EncryptionKey, goLeaf.EncryptionKey) && bytes.Equal(leaf.SignatureKey, goLeaf.SignatureKeyRaw) &&
				uint16(leaf.Credential.Type) == uint16(goLeaf.Credential.CredentialType) &&
				uint8(leaf.Source) == goLeaf.LeafNodeSource && bytes.Equal(leaf.Signature, goLeaf.Signature) &&
				sameUint16s(toUint16s(len(capabilities.Versions), func(i int) uint16 { return uint16(capabilities.Versions[i]) }), goCapabilities.ProtocolVersions) &&
				sameUint16s(toUint16s(len(capabilities.CipherSuites), func(i int) uint16 { return uint16(capabilities.CipherSuites[i]) }), goCapabilities.CipherSuites) &&
				sameUint16s(toUint16s(len(capabilities.Extensions), func(i int) uint16 { return uint16(capabilities.Extensions[i]) }), goCapabilities.Extensions) &&
				sameUint16s(toUint16s(len(capabilities.Proposals), func(i int) uint16 { return uint16(capabilities.Proposals[i]) }), goCapabilities.Proposals) &&
				sameUint16s(toUint16s(len(capabilities.Credentials), func(i int) uint16 { return uint16(capabilities.Credentials[i]) }), goCapabilities.Credentials)
			switch leaf.Source {
			case mls.LeafNodeSourceKeyPackage:
				same = same && goLeaf.Lifetime != nil && leaf.Lifetime.NotBefore == goLeaf.Lifetime.NotBefore && leaf.Lifetime.NotAfter == goLeaf.Lifetime.NotAfter
			case mls.LeafNodeSourceCommit:
				same = same && bytes.Equal(leaf.ParentHash, goLeaf.ParentHash)
			}
			if !same {
				t.Fatalf("node %d: tmc/mls and mls-go read another leaf", index)
			}
		case node.Parent != nil:
			parent := node.Parent
			unmerged := []uint32{}
			for _, leafIndex := range goNode.UnmergedLeaves {
				unmerged = append(unmerged, uint32(leafIndex))
			}
			if goNode.EncryptionKey == nil || !bytes.Equal(parent.EncryptionKey, goNode.EncryptionKey.Bytes()) ||
				!bytes.Equal(parent.ParentHash, goNode.ParentHash) ||
				!(slices.Equal(parent.UnmergedLeaves, unmerged) || (len(parent.UnmergedLeaves) == 0 && len(unmerged) == 0)) {
				t.Fatalf("node %d: tmc/mls and mls-go read another parent", index)
			}
		}
	}
}

func FuzzMlsRatchetTreeAgreesWithPeers(f *testing.F) {
	_, _, seeds := fuzzMlsTreeSeeds(f)
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		reencoded, err := sidecar.MlsTestDecodeRatchetTree(encoded)
		if err != nil {
			return
		}
		tree := mls.RatchetTree{}
		tmcErr := mls.Unmarshal(encoded, &tree)
		if !bytes.Equal(reencoded, encoded) {
			t.Fatal("mls_* decodes a tree it does not encode back to itself")
		}
		if tmcErr != nil {
			t.Fatalf("mls_* decodes a tree tmc/mls does not: %v", tmcErr)
		}
		if again, err := mls.Marshal(&tree); err != nil || !bytes.Equal(again, encoded) {
			t.Fatalf("mls_* decodes a tree tmc/mls does not encode back to itself: %v", err)
		}
		if !fuzzMlsTreeIsX25519(tree) {
			return
		}
		goTree, goErr := treesync.UnmarshalTreeFromExtension(encoded, ciphersuite.MLS128DHKEMX25519)
		if goErr != nil {
			t.Fatalf("mls_* decodes an X25519 tree mls-go does not: %v", goErr)
		}
		fuzzMlsTreesAgree(t, tree, goTree)
	})
}

// mls_* decodes the 0x0010 trees and every tree made 0xF552, refuses the basic ones as production does, and refuses
// each mutation; mls-go reads at least one tree mls_* reads, so the target holds it to something.
func TestFuzzMlsRatchetTreeSeedsReachEveryRule(t *testing.T) {
	urSidecar, basic, _ := fuzzMlsTreeSeeds(t)
	if len(urSidecar) < 4 || len(basic) < 2 {
		t.Fatalf("%d 0xF552 trees and %d basic ones", len(urSidecar), len(basic))
	}
	readByMlsGo := 0
	for index, encoded := range urSidecar {
		if reencoded, err := sidecar.MlsTestDecodeRatchetTree(encoded); err != nil || !bytes.Equal(reencoded, encoded) {
			t.Fatalf("tree %d: %v", index, err)
		}
		tree := mls.RatchetTree{}
		if err := mls.Unmarshal(encoded, &tree); err != nil {
			t.Fatal(err)
		}
		if fuzzMlsTreeIsX25519(tree) {
			goTree, err := treesync.UnmarshalTreeFromExtension(encoded, ciphersuite.MLS128DHKEMX25519)
			if err != nil {
				t.Fatalf("tree %d: mls-go: %v", index, err)
			}
			fuzzMlsTreesAgree(t, tree, goTree)
			readByMlsGo += 1
		}
		for mutationIndex, mutation := range fuzzMlsTreeMutations(encoded) {
			if _, err := sidecar.MlsTestDecodeRatchetTree(mutation); err == nil {
				t.Errorf("tree %d decodes after mutation %d", index, mutationIndex)
			}
		}
	}
	for index, encoded := range basic {
		if _, err := sidecar.MlsTestDecodeRatchetTree(encoded); err == nil {
			t.Errorf("basic tree %d decodes outside the root's tests", index)
		}
	}
	if readByMlsGo == 0 {
		t.Error("mls-go reads none of the trees mls_* reads")
	}
	t.Logf("%d 0xF552 trees, %d of them read by mls-go too, and %d basic ones", len(urSidecar), readByMlsGo, len(basic))
}
