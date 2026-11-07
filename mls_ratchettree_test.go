// The ratchet tree and TreeKEM against the mlswg's tree-validation, tree-operations, treekem and
// messages vectors under 0x0001.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"maps"
	"slices"
	"testing"
)

// Settings for the mlswg's leaves, whose lifetimes run from 0 to the end of time.
func mlsVectorTreeSettings() *mlsTreeSettings {
	settings := defaultMlsTreeSettings()
	settings.MaximumLeafLifetime = 0
	return settings
}

// The vectors' credentials are all basic, and none stands for an admitted device.
func mlsAcceptBasicCredential(credential *mlsCredential, signatureKey []byte) error {
	if credential.credentialType != mlsCredentialTypeBasic {
		return errMlsRefused
	}
	return nil
}

// Validation for a group under the vectors' rules.
func mlsTestLeafValidation(groupId []byte) *mlsLeafValidation {
	return &mlsLeafValidation{groupId: groupId, credentialValidator: mlsAcceptBasicCredential}
}

func TestMlsTreeValidationVectors(t *testing.T) {
	var vectors []struct {
		CipherSuite uint16        `json:"cipher_suite"`
		Tree        mlsHexBytes   `json:"tree"`
		GroupId     mlsHexBytes   `json:"group_id"`
		Resolutions [][]uint32    `json:"resolutions"`
		TreeHashes  []mlsHexBytes `json:"tree_hashes"`
	}
	mlsLoadVectors(t, "tree-validation", &vectors)

	suite := mlsTestSuiteX25519
	ran := 0
	for index, vector := range vectors {
		if vector.CipherSuite != suite.value {
			continue
		}
		ran++
		tree, err := decodeMlsRatchetTree(suite, mlsVectorTreeSettings(), vector.Tree)
		if err != nil {
			t.Fatalf("vector %d: %v", index, err)
		}
		encoded, err := mlsMarshal(tree)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, vector.Tree) {
			t.Errorf("vector %d: the tree re-encoded differently", index)
		}
		if len(tree.nodes) != len(vector.Resolutions) {
			t.Fatalf("vector %d: %d nodes, want %d", index, len(tree.nodes), len(vector.Resolutions))
		}
		for node := range tree.nodes {
			resolution := tree.resolution(mlsNodeIndex(node))
			want := vector.Resolutions[node]
			if len(resolution) != len(want) {
				t.Errorf("vector %d node %d: resolution %v, want %v", index, node, resolution, want)
				continue
			}
			for position := range want {
				if uint32(resolution[position]) != want[position] {
					t.Errorf("vector %d node %d: resolution %v, want %v", index, node, resolution, want)
					break
				}
			}
			hash, err := tree.nodeTreeHash(mlsNodeIndex(node))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(hash, vector.TreeHashes[node]) {
				t.Errorf("vector %d node %d: tree hash %x, want %x", index, node, hash, vector.TreeHashes[node])
			}
		}
		if err := tree.validate(mlsTestLeafValidation(vector.GroupId)); err != nil {
			t.Errorf("vector %d: %v", index, err)
		}
	}
	if ran == 0 {
		t.Fatal("no vector for suite 0x0001")
	}
}

func TestMlsTreeOperationsVectors(t *testing.T) {
	var vectors []struct {
		CipherSuite    uint16      `json:"cipher_suite"`
		TreeBefore     mlsHexBytes `json:"tree_before"`
		Proposal       mlsHexBytes `json:"proposal"`
		ProposalSender uint32      `json:"proposal_sender"`
		TreeHashBefore mlsHexBytes `json:"tree_hash_before"`
		TreeAfter      mlsHexBytes `json:"tree_after"`
		TreeHashAfter  mlsHexBytes `json:"tree_hash_after"`
	}
	mlsLoadVectors(t, "tree-operations", &vectors)

	suite := mlsTestSuiteX25519
	applied := 0
	refused := 0
	for index, vector := range vectors {
		if vector.CipherSuite != suite.value {
			continue
		}
		tree, err := decodeMlsRatchetTree(suite, mlsVectorTreeSettings(), vector.TreeBefore)
		if err != nil {
			t.Fatalf("vector %d: %v", index, err)
		}
		hash, err := tree.treeHash()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(hash, vector.TreeHashBefore) {
			t.Errorf("vector %d: tree hash before %x, want %x", index, hash, vector.TreeHashBefore)
		}

		proposal := &mlsProposal{}
		err = mlsUnmarshal(vector.Proposal, proposal)
		if errors.Is(err, errMlsRefused) {
			// §10.4 refuses Update when parsed, so this entry covers no v0 feature
			if proposal.proposalType != mlsProposalTypeUpdate {
				t.Errorf("vector %d: refused proposal type %#x", index, proposal.proposalType)
			}
			refused++
			continue
		}
		if err != nil {
			t.Fatalf("vector %d: %v", index, err)
		}
		switch proposal.proposalType {
		case mlsProposalTypeAdd:
			if _, err := tree.addLeaf(&proposal.keyPackage.leafNode); err != nil {
				t.Fatalf("vector %d: %v", index, err)
			}
		case mlsProposalTypeRemove:
			if err := tree.removeLeaf(proposal.removed); err != nil {
				t.Fatalf("vector %d: %v", index, err)
			}
		default:
			t.Fatalf("vector %d: proposal type %#x", index, proposal.proposalType)
		}
		applied++

		encoded, err := mlsMarshal(tree)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, vector.TreeAfter) {
			t.Errorf("vector %d: tree after differs", index)
		}
		hash, err = tree.treeHash()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(hash, vector.TreeHashAfter) {
			t.Errorf("vector %d: tree hash after %x, want %x", index, hash, vector.TreeHashAfter)
		}
	}
	if applied == 0 || refused == 0 {
		t.Fatalf("%d entries applied, %d refused", applied, refused)
	}
}

// A member's own copy, so one vector's update paths do not disturb the next.
func (self *mlsTreeSecrets) cloneForTest() *mlsTreeSecrets {
	return &mlsTreeSecrets{suite: self.suite, leaf: self.leaf, nodeIndexKeys: maps.Clone(self.nodeIndexKeys)}
}

func TestMlsTreeKemVectors(t *testing.T) {
	var vectors []struct {
		CipherSuite             uint16      `json:"cipher_suite"`
		GroupId                 mlsHexBytes `json:"group_id"`
		Epoch                   uint64      `json:"epoch"`
		ConfirmedTranscriptHash mlsHexBytes `json:"confirmed_transcript_hash"`
		RatchetTree             mlsHexBytes `json:"ratchet_tree"`
		LeavesPrivate           []struct {
			Index          uint32      `json:"index"`
			EncryptionPriv mlsHexBytes `json:"encryption_priv"`
			SignaturePriv  mlsHexBytes `json:"signature_priv"`
			PathSecrets    []struct {
				Node       uint32      `json:"node"`
				PathSecret mlsHexBytes `json:"path_secret"`
			} `json:"path_secrets"`
		} `json:"leaves_private"`
		UpdatePaths []struct {
			Sender        uint32        `json:"sender"`
			UpdatePath    mlsHexBytes   `json:"update_path"`
			PathSecrets   []mlsHexBytes `json:"path_secrets"`
			CommitSecret  mlsHexBytes   `json:"commit_secret"`
			TreeHashAfter mlsHexBytes   `json:"tree_hash_after"`
		} `json:"update_paths"`
	}
	mlsLoadVectors(t, "treekem", &vectors)

	suite := mlsTestSuiteX25519
	ran := 0
	for index, vector := range vectors {
		if vector.CipherSuite != suite.value {
			continue
		}
		ran++
		tree, err := decodeMlsRatchetTree(suite, mlsVectorTreeSettings(), vector.RatchetTree)
		if err != nil {
			t.Fatalf("vector %d: %v", index, err)
		}
		validation := mlsTestLeafValidation(vector.GroupId)

		leafIndexSecrets := map[mlsLeafIndex]*mlsTreeSecrets{}
		leafIndexSignatureSeeds := map[mlsLeafIndex][]byte{}
		for _, private := range vector.LeavesPrivate {
			leaf := mlsLeafIndex(private.Index)
			leafKey, err := suite.loadKemKey("test", private.EncryptionPriv)
			if err != nil {
				t.Fatal(err)
			}
			secrets := newMlsTreeSecrets(suite, leaf, leafKey)
			for _, pathSecret := range private.PathSecrets {
				if err := secrets.implantPathSecret(tree, mlsNodeIndex(pathSecret.Node), pathSecret.PathSecret); err != nil {
					t.Fatalf("vector %d leaf %d: %v", index, leaf, err)
				}
			}
			if !secrets.consistentWith(tree) {
				t.Errorf("vector %d leaf %d: private state does not match the tree", index, leaf)
			}
			leafIndexSecrets[leaf] = secrets
			leafIndexSignatureSeeds[leaf] = private.SignaturePriv
		}

		contextFor := func(tree *mlsRatchetTree) []byte {
			treeHash, err := tree.treeHash()
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := mlsMarshal(&mlsGroupContext{
				cipherSuite:             suite.value,
				groupId:                 vector.GroupId,
				epoch:                   vector.Epoch,
				treeHash:                treeHash,
				confirmedTranscriptHash: vector.ConfirmedTranscriptHash,
			})
			if err != nil {
				t.Fatal(err)
			}
			return encoded
		}

		for _, entry := range vector.UpdatePaths {
			sender := mlsLeafIndex(entry.Sender)
			updatePath := &mlsUpdatePath{}
			if err := mlsUnmarshal(entry.UpdatePath, updatePath); err != nil {
				t.Fatalf("vector %d: %v", index, err)
			}
			reencoded, err := mlsMarshal(updatePath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(reencoded, entry.UpdatePath) {
				t.Errorf("vector %d: the update path re-encoded differently", index)
			}

			merged := tree.clone()
			if err := merged.mergeUpdatePath(sender, updatePath, nil, validation); err != nil {
				t.Fatalf("vector %d sender %d: %v", index, sender, err)
			}
			treeHash, err := merged.treeHash()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(treeHash, entry.TreeHashAfter) {
				t.Errorf("vector %d sender %d: tree hash %x, want %x", index, sender, treeHash, entry.TreeHashAfter)
			}
			if err := merged.validate(validation); err != nil {
				t.Errorf("vector %d sender %d: the merged tree: %v", index, sender, err)
			}

			groupContext := contextFor(merged)
			for leaf, secrets := range leafIndexSecrets {
				if leaf == sender {
					continue
				}
				receiver := secrets.cloneForTest()
				position, pathSecret, err := receiver.decryptPathSecret(merged, sender, updatePath, groupContext, nil)
				if err != nil {
					t.Fatalf("vector %d sender %d leaf %d: %v", index, sender, leaf, err)
				}
				if !bytes.Equal(pathSecret, entry.PathSecrets[leaf]) {
					t.Errorf("vector %d sender %d leaf %d: path secret %x, want %x", index, sender, leaf, pathSecret, entry.PathSecrets[leaf])
				}
				commitSecret, err := receiver.adoptPathSecret(merged, sender, updatePath, position, pathSecret)
				if err != nil {
					t.Fatalf("vector %d sender %d leaf %d: %v", index, sender, leaf, err)
				}
				if !bytes.Equal(commitSecret, entry.CommitSecret) {
					t.Errorf("vector %d sender %d leaf %d: commit secret %x, want %x", index, sender, leaf, commitSecret, entry.CommitSecret)
				}
				if !receiver.consistentWith(merged) {
					t.Errorf("vector %d sender %d leaf %d: private state left stale", index, sender, leaf)
				}
			}

			// a path built here must be one every other member can process
			signatureKey, err := suite.loadSignatureKey("test", leafIndexSignatureSeeds[sender])
			if err != nil {
				t.Fatal(err)
			}
			committerTree := tree.clone()
			prepared, err := committerTree.prepareUpdatePath(sender, tree.leafNode(sender), signatureKey, vector.GroupId)
			if err != nil {
				t.Fatal(err)
			}
			newPath, err := prepared.encrypt(contextFor(committerTree), nil)
			if err != nil {
				t.Fatal(err)
			}
			receiverTree := tree.clone()
			if err := receiverTree.mergeUpdatePath(sender, newPath, nil, validation); err != nil {
				t.Fatalf("vector %d sender %d: a fresh path: %v", index, sender, err)
			}
			groupContext = contextFor(receiverTree)
			if !bytes.Equal(groupContext, contextFor(committerTree)) {
				t.Errorf("vector %d sender %d: committer and receiver trees differ", index, sender)
			}
			for leaf, secrets := range leafIndexSecrets {
				if leaf == sender {
					continue
				}
				commitSecret, err := secrets.cloneForTest().receiveUpdatePath(receiverTree, sender, newPath, groupContext, nil)
				if err != nil {
					t.Fatalf("vector %d sender %d leaf %d: %v", index, sender, leaf, err)
				}
				if !bytes.Equal(commitSecret, prepared.commitSecret) {
					t.Errorf("vector %d sender %d leaf %d: commit secret %x, want %x", index, sender, leaf, commitSecret, prepared.commitSecret)
				}
			}
		}
	}
	if ran == 0 {
		t.Fatal("no vector for suite 0x0001")
	}
}

// messages.json checks syntax alone. Everything inside the subset must round-trip byte for byte, and
// everything outside it must be refused, not misread. Its other fields, the framed messages, wait for
// the framing layer.
func TestMlsMessagesVectors(t *testing.T) {
	var vectors []struct {
		RatchetTree                    mlsHexBytes `json:"ratchet_tree"`
		AddProposal                    mlsHexBytes `json:"add_proposal"`
		UpdateProposal                 mlsHexBytes `json:"update_proposal"`
		RemoveProposal                 mlsHexBytes `json:"remove_proposal"`
		PreSharedKeyProposal           mlsHexBytes `json:"pre_shared_key_proposal"`
		ReInitProposal                 mlsHexBytes `json:"re_init_proposal"`
		ExternalInitProposal           mlsHexBytes `json:"external_init_proposal"`
		GroupContextExtensionsProposal mlsHexBytes `json:"group_context_extensions_proposal"`
	}
	mlsLoadVectors(t, "messages", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}

	withType := func(proposalType uint16, body []byte) []byte {
		encoder := &mlsEncoder{}
		encoder.writeUint16(proposalType)
		encoder.writeFixed(body)
		return encoder.encoded
	}
	roundTrip := func(index int, name string, encoded []byte, value mlsDecodableEncodable) {
		t.Helper()
		if err := mlsUnmarshal(encoded, value); err != nil {
			t.Errorf("vector %d: %s: %v", index, name, err)
			return
		}
		reencoded, err := mlsMarshal(value)
		if err != nil {
			t.Errorf("vector %d: %s: %v", index, name, err)
			return
		}
		if !bytes.Equal(reencoded, encoded) {
			t.Errorf("vector %d: %s re-encoded differently", index, name)
		}
	}

	suite := mlsTestSuiteX25519
	for index, vector := range vectors {
		tree, err := decodeMlsRatchetTree(suite, mlsVectorTreeSettings(), vector.RatchetTree)
		if err != nil {
			t.Errorf("vector %d: ratchet tree: %v", index, err)
		} else {
			encoded, err := mlsMarshal(tree)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded, vector.RatchetTree) {
				t.Errorf("vector %d: the ratchet tree re-encoded differently", index)
			}
		}

		roundTrip(index, "add", withType(mlsProposalTypeAdd, vector.AddProposal), &mlsProposal{})
		roundTrip(index, "remove", withType(mlsProposalTypeRemove, vector.RemoveProposal), &mlsProposal{})
		roundTrip(index, "external_init", withType(mlsProposalTypeExternalInit, vector.ExternalInitProposal), &mlsProposal{})
		roundTrip(index, "group_context_extensions", withType(mlsProposalTypeGroupContextExtensions, vector.GroupContextExtensionsProposal), &mlsProposal{})

		refused := []struct {
			name         string
			proposalType uint16
			body         []byte
		}{
			{name: "update", proposalType: mlsProposalTypeUpdate, body: vector.UpdateProposal},
			{name: "psk", proposalType: mlsProposalTypePsk, body: vector.PreSharedKeyProposal},
			{name: "reinit", proposalType: mlsProposalTypeReInit, body: vector.ReInitProposal},
		}
		for _, c := range refused {
			if err := mlsUnmarshal(withType(c.proposalType, c.body), &mlsProposal{}); !errors.Is(err, errMlsRefused) {
				t.Errorf("vector %d: %s: %v", index, c.name, err)
			}
		}
	}
}

// A value that goes both ways through the codec.
type mlsDecodableEncodable interface {
	mlsEncodable
	mlsDecodable
}

// A leaf named for a test: its key is its name, which is all a shape needs.
func mlsShapeLeaf(name string) mlsTreeNode {
	return mlsTreeNode{leaf: &mlsLeafNode{
		encryptionKey:  []byte(name),
		signatureKey:   []byte("signature " + name),
		credential:     mlsCredential{credentialType: mlsCredentialTypeBasic, identity: []byte(name)},
		leafNodeSource: mlsLeafNodeSourceUpdate,
	}}
}

// A parent named for a test.
func mlsShapeParent(name string, unmergedLeaves ...mlsLeafIndex) mlsTreeNode {
	return mlsTreeNode{parent: &mlsParentNode{encryptionKey: []byte(name), unmergedLeaves: unmergedLeaves}}
}

// A tree of exactly these nodes, for shape tests. Nothing here is signed.
func mlsShapedTree(nodes ...mlsTreeNode) *mlsRatchetTree {
	return &mlsRatchetTree{
		suite:      mlsSuite,
		settings:   defaultMlsTreeSettings(),
		nodes:      nodes,
		nodeHashes: make([][]byte, len(nodes)),
	}
}

// Figure 10's tree under its top node: X over A, B, _ and D with B unmerged, Y over E and F.
func TestMlsResolutionsOfFigure10(t *testing.T) {
	blank := mlsTreeNode{}
	tree := mlsShapedTree(
		mlsShapeLeaf("A"), blank, mlsShapeLeaf("B"), mlsShapeParent("X", 1), blank, blank, mlsShapeLeaf("D"),
		blank,
		mlsShapeLeaf("E"), mlsShapeParent("Y"), mlsShapeLeaf("F"), blank, blank, blank, mlsShapeLeaf("H"),
	)
	cases := []struct {
		node mlsNodeIndex
		want []mlsNodeIndex
	}{
		{node: 3, want: []mlsNodeIndex{3, 2}},        // X, B
		{node: 4, want: nil},                         // leaf 2
		{node: 12, want: nil},                        // leaf 6
		{node: 7, want: []mlsNodeIndex{3, 2, 9, 14}}, // X, B, Y, H
	}
	for _, c := range cases {
		if got := tree.resolution(c.node); !slices.Equal(got, c.want) {
			t.Errorf("node %d: resolution %v, want %v", c.node, got, c.want)
		}
	}
}

// Figure 11 and its table: blank U, V and Z drop out of the paths whose copath child is empty.
func TestMlsFilteredDirectPathsOfFigure11(t *testing.T) {
	blank := mlsTreeNode{}
	tree := mlsShapedTree(
		mlsShapeLeaf("A"), mlsShapeParent("T"), mlsShapeLeaf("B"), blank, blank, blank, blank,
		mlsShapeParent("W"),
		mlsShapeLeaf("E"), mlsShapeParent("X"), mlsShapeLeaf("F"), mlsShapeParent("Y"), mlsShapeLeaf("G"), blank, blank,
	)
	cases := []struct {
		leaf mlsLeafIndex
		want []mlsNodeIndex
	}{
		{leaf: 0, want: []mlsNodeIndex{1, 7}},     // T, W
		{leaf: 1, want: []mlsNodeIndex{1, 7}},     // T, W
		{leaf: 4, want: []mlsNodeIndex{9, 11, 7}}, // X, Y, W
		{leaf: 5, want: []mlsNodeIndex{9, 11, 7}}, // X, Y, W
		{leaf: 6, want: []mlsNodeIndex{11, 7}},    // Y, W
	}
	for _, c := range cases {
		var got []mlsNodeIndex
		for _, entry := range tree.filteredDirectPath(c.leaf) {
			got = append(got, entry.node)
			left, _ := entry.node.left()
			right, _ := entry.node.right()
			wantChild := left
			if left.subtreeContains(c.leaf.node()) {
				wantChild = right
			}
			if entry.copathChild != wantChild {
				t.Errorf("leaf %d: copath child of %d is %d, want %d", c.leaf, entry.node, entry.copathChild, wantChild)
			}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("leaf %d: filtered path %v, want %v", c.leaf, got, c.want)
		}
	}
}

// An unmerged leaf keeps a node on the path though the copath child's own node is blank: the
// parenthetical in RFC §4.1.2.
func TestMlsUnmergedLeavesCountTowardTheResolution(t *testing.T) {
	blank := mlsTreeNode{}
	tree := mlsShapedTree(mlsShapeLeaf("A"), mlsShapeParent("X", 1), mlsShapeLeaf("B"))
	if got := tree.resolution(1); !slices.Equal(got, []mlsNodeIndex{1, 2}) {
		t.Fatalf("resolution %v", got)
	}
	tree = mlsShapedTree(mlsShapeLeaf("A"), blank, mlsShapeLeaf("B"), blank, blank, blank, blank)
	if got := tree.filteredDirectPath(0); len(got) != 1 || got[0].node != 1 {
		t.Fatalf("path %v", got)
	}
}

func TestMlsDecodeRefusesAnEmptyTree(t *testing.T) {
	if _, err := decodeMlsRatchetTree(mlsSuite, defaultMlsTreeSettings(), []byte{0}); !errors.Is(err, errMlsMalformed) {
		t.Fatal(err)
	}
}

// Encodes a node list with its blanks exactly as given.
func mlsEncodeNodeList(t testing.TB, nodes []mlsTreeNode) []byte {
	t.Helper()
	encoder := &mlsEncoder{}
	encoder.writeVectorOf(func(elements *mlsEncoder) {
		for index := range nodes {
			node := &nodes[index]
			elements.writeOptional(!node.blank())
			switch {
			case node.leaf != nil:
				elements.writeUint8(mlsNodeTypeLeaf)
				node.leaf.encode(elements)
			case node.parent != nil:
				elements.writeUint8(mlsNodeTypeParent)
				node.parent.encode(elements)
			}
		}
	})
	encoded, err := encoder.finish()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestMlsDecodeRefusesTrailingBlanks(t *testing.T) {
	encoded := mlsEncodeNodeList(t, []mlsTreeNode{mlsShapeLeaf("A"), {}})
	if _, err := decodeMlsRatchetTree(mlsSuite, defaultMlsTreeSettings(), encoded); !errors.Is(err, errMlsMalformed) {
		t.Fatal(err)
	}
}

func TestMlsDecodeRefusesNodesOutOfPlace(t *testing.T) {
	cases := [][]mlsTreeNode{
		{mlsShapeParent("X")},
		{mlsShapeLeaf("A"), mlsShapeLeaf("B"), mlsShapeLeaf("C")},
		{mlsShapeLeaf("A"), mlsShapeParent("X"), mlsShapeParent("Y")},
	}
	for index, nodes := range cases {
		encoded := mlsEncodeNodeList(t, nodes)
		if _, err := decodeMlsRatchetTree(mlsSuite, defaultMlsTreeSettings(), encoded); !errors.Is(err, errMlsMalformed) {
			t.Errorf("case %d: %v", index, err)
		}
	}
}

func TestMlsDecodeExtendsTheArrayToAFullTree(t *testing.T) {
	nodes := []mlsTreeNode{
		mlsShapeLeaf("A"), {}, mlsShapeLeaf("B"), {}, mlsShapeLeaf("C"),
	}
	tree, err := decodeMlsRatchetTree(mlsSuite, defaultMlsTreeSettings(), mlsEncodeNodeList(t, nodes))
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.nodes) != 7 || tree.leafCount() != 4 {
		t.Fatalf("%d nodes, %d leaves", len(tree.nodes), tree.leafCount())
	}
	if !tree.nodes[5].blank() || !tree.nodes[6].blank() {
		t.Fatal("the extension is not blank")
	}
	// and trailing blanks stay off the wire
	encoded, err := mlsMarshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, mlsEncodeNodeList(t, nodes)) {
		t.Fatal("the tree re-encoded with its blanks")
	}
}

func TestMlsDecodeRefusesUnknownNodeTypes(t *testing.T) {
	encoded := []byte{2, 1, 3}
	if _, err := decodeMlsRatchetTree(mlsSuite, defaultMlsTreeSettings(), encoded); !errors.Is(err, errMlsMalformed) {
		t.Fatal(err)
	}
}

func TestMlsDecodeRefusesUnmergedLeavesOutOfOrder(t *testing.T) {
	for _, unmerged := range [][]mlsLeafIndex{{2, 1}, {1, 1}} {
		parent := &mlsParentNode{encryptionKey: []byte("X"), unmergedLeaves: unmerged}
		encoded, err := mlsMarshal(parent)
		if err != nil {
			t.Fatal(err)
		}
		if err := mlsUnmarshal(encoded, &mlsParentNode{}); !errors.Is(err, errMlsMalformed) {
			t.Errorf("%v: %v", unmerged, err)
		}
	}
}

func TestMlsDecodeRefusesATreeWiderThanTheSettings(t *testing.T) {
	settings := &mlsTreeSettings{MaximumLeafCount: 2}
	nodes := []mlsTreeNode{{}, {}, {}, {}, mlsShapeLeaf("C")}
	if _, err := decodeMlsRatchetTree(mlsSuite, settings, mlsEncodeNodeList(t, nodes)); !errors.Is(err, errMlsRefused) {
		t.Fatal(err)
	}
	narrower := []mlsTreeNode{{}, {}, mlsShapeLeaf("B")}
	if _, err := decodeMlsRatchetTree(mlsSuite, settings, mlsEncodeNodeList(t, narrower)); err != nil {
		t.Fatal(err)
	}
}

func TestMlsDecodeRefusesASettingThatIsNoTree(t *testing.T) {
	settings := &mlsTreeSettings{MaximumLeafCount: 1000}
	if _, err := decodeMlsRatchetTree(mlsSuite, settings, mlsEncodeNodeList(t, []mlsTreeNode{mlsShapeLeaf("A")})); err == nil {
		t.Fatal("a maximum of 1000 leaves is not a full tree")
	}
}

// Figure 16: extending for a third member, then adding beyond.
func TestMlsAddFillsTheLeftmostBlankThenExtends(t *testing.T) {
	blank := mlsTreeNode{}
	tree := mlsShapedTree(mlsShapeLeaf("A"), blank, blank)
	leaf, err := tree.addLeaf(mlsShapeLeaf("B").leaf)
	if err != nil || leaf != 1 {
		t.Fatalf("leaf %d, %v", leaf, err)
	}
	leaf, err = tree.addLeaf(mlsShapeLeaf("C").leaf)
	if err != nil || leaf != 2 {
		t.Fatalf("leaf %d, %v", leaf, err)
	}
	if tree.leafCount() != 4 || len(tree.nodes) != 7 {
		t.Fatalf("%d leaves, %d nodes", tree.leafCount(), len(tree.nodes))
	}
	if tree.nodes[7/2].parent != nil {
		t.Fatal("the new root is not blank")
	}
	if len(tree.nodeHashes) != len(tree.nodes) {
		t.Fatalf("%d hash slots for %d nodes", len(tree.nodeHashes), len(tree.nodes))
	}
}

func TestMlsAddMarksEveryNonBlankAncestorUnmergedInOrder(t *testing.T) {
	blank := mlsTreeNode{}
	tree := mlsShapedTree(
		blank, mlsShapeParent("X", 1), mlsShapeLeaf("B"), mlsShapeParent("Y", 1), mlsShapeLeaf("C"), blank, mlsShapeLeaf("D"),
	)
	leaf, err := tree.addLeaf(mlsShapeLeaf("A").leaf)
	if err != nil || leaf != 0 {
		t.Fatalf("leaf %d, %v", leaf, err)
	}
	for _, node := range []mlsNodeIndex{1, 3} {
		if got := tree.nodes[node].parent.unmergedLeaves; !slices.Equal(got, []mlsLeafIndex{0, 1}) {
			t.Errorf("node %d: unmerged %v", node, got)
		}
	}
	if tree.nodes[5].parent != nil {
		t.Error("a blank ancestor gained a value")
	}
}

// Parents are shared between clones, so adding must install a new node, not edit the old one.
func TestMlsAddDoesNotReachThroughAClone(t *testing.T) {
	tree := mlsShapedTree(mlsShapeLeaf("A"), mlsShapeParent("X"), mlsTreeNode{})
	clone := tree.clone()
	if _, err := clone.addLeaf(mlsShapeLeaf("B").leaf); err != nil {
		t.Fatal(err)
	}
	if got := tree.nodes[1].parent.unmergedLeaves; len(got) != 0 {
		t.Fatalf("the original's parent changed: %v", got)
	}
	if !tree.nodes[2].blank() {
		t.Fatal("the original's leaf changed")
	}
}

func TestMlsAddStopsAtTheSettingsWidth(t *testing.T) {
	tree := mlsShapedTree(mlsShapeLeaf("A"), mlsTreeNode{}, mlsShapeLeaf("B"))
	tree.settings = &mlsTreeSettings{MaximumLeafCount: 2}
	if _, err := tree.addLeaf(mlsShapeLeaf("C").leaf); !errors.Is(err, errMlsRefused) {
		t.Fatal(err)
	}
	if tree.leafCount() != 2 {
		t.Fatalf("%d leaves", tree.leafCount())
	}
}

// Figure 17: removing C leaves a right subtree with no leaf, so the tree halves.
func TestMlsRemoveBlanksThePathAndTruncates(t *testing.T) {
	blank := mlsTreeNode{}
	tree := mlsShapedTree(
		mlsShapeLeaf("A"), mlsShapeParent("X"), mlsShapeLeaf("B"), mlsShapeParent("Y"), mlsShapeLeaf("C"), blank, blank,
	)
	if err := tree.removeLeaf(2); err != nil {
		t.Fatal(err)
	}
	if tree.leafCount() != 2 || len(tree.nodes) != 3 {
		t.Fatalf("%d leaves, %d nodes", tree.leafCount(), len(tree.nodes))
	}
	if tree.nodes[1].parent == nil {
		t.Fatal("X, the new root, lost its value")
	}
}

func TestMlsRemoveKeepsTheTreeWhileItsRightHalfHasAMember(t *testing.T) {
	blank := mlsTreeNode{}
	tree := mlsShapedTree(
		mlsShapeLeaf("A"), mlsShapeParent("X"), mlsShapeLeaf("B"), mlsShapeParent("Y"), mlsShapeLeaf("C"), blank, mlsShapeLeaf("D"),
	)
	if err := tree.removeLeaf(1); err != nil {
		t.Fatal(err)
	}
	if tree.leafCount() != 4 {
		t.Fatalf("%d leaves", tree.leafCount())
	}
	if !tree.nodes[1].blank() || !tree.nodes[3].blank() || !tree.nodes[2].blank() {
		t.Fatal("the leaf's path is not blank")
	}
}

// Truncating past two halves in one Remove.
func TestMlsRemoveTruncatesRepeatedly(t *testing.T) {
	nodes := make([]mlsTreeNode, 15)
	nodes[0] = mlsShapeLeaf("A")
	nodes[8] = mlsShapeLeaf("E")
	tree := mlsShapedTree(nodes...)
	if err := tree.removeLeaf(4); err != nil {
		t.Fatal(err)
	}
	if tree.leafCount() != 1 {
		t.Fatalf("%d leaves", tree.leafCount())
	}
}

func TestMlsRemoveRefusesABlankOrMissingLeaf(t *testing.T) {
	tree := mlsShapedTree(mlsShapeLeaf("A"), mlsTreeNode{}, mlsTreeNode{}, mlsTreeNode{}, mlsShapeLeaf("C"), mlsTreeNode{}, mlsTreeNode{})
	for _, leaf := range []mlsLeafIndex{1, 3, 4, 100} {
		if err := tree.removeLeaf(leaf); !errors.Is(err, errMlsInvalid) {
			t.Errorf("leaf %d: %v", leaf, err)
		}
	}
}

func TestMlsTreeHashCacheFollowsChanges(t *testing.T) {
	tree := mlsShapedTree(mlsShapeLeaf("A"), mlsTreeNode{}, mlsShapeLeaf("B"))
	before, err := tree.treeHash()
	if err != nil {
		t.Fatal(err)
	}
	tree.setNode(2, mlsShapeLeaf("C"))
	after, err := tree.treeHash()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("the root hash ignored a leaf change")
	}
	fresh := mlsShapedTree(mlsShapeLeaf("A"), mlsTreeNode{}, mlsShapeLeaf("C"))
	want, err := fresh.treeHash()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, want) {
		t.Fatal("the cached hash is stale")
	}
}

// RFC §7.8: a blank leaf still hashes with its index, so two blanks differ.
func TestMlsTreeHashOfBlankLeavesDependsOnPosition(t *testing.T) {
	tree := mlsShapedTree(mlsShapeLeaf("A"), mlsTreeNode{}, mlsTreeNode{}, mlsTreeNode{}, mlsTreeNode{}, mlsTreeNode{}, mlsShapeLeaf("D"))
	first, err := tree.nodeTreeHash(2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := tree.nodeTreeHash(4)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two blank leaves hash alike")
	}
}

// Figure 21: with W's unmerged F, Y's original tree hash blanks F and drops it from Y.
func TestMlsOriginalTreeHashOfFigure21(t *testing.T) {
	blank := mlsTreeNode{}
	nodes := []mlsTreeNode{
		mlsShapeLeaf("A"), mlsShapeParent("T"), mlsShapeLeaf("B"), mlsShapeParent("U"), mlsShapeLeaf("C"), blank, mlsShapeLeaf("D"),
		mlsShapeParent("W", 5),
		mlsShapeLeaf("E"), blank, mlsShapeLeaf("F"), mlsShapeParent("Y", 5), mlsShapeLeaf("G"), blank, blank,
	}
	tree := mlsShapedTree(nodes...)
	original, err := tree.originalTreeHash(11, []mlsLeafIndex{5})
	if err != nil {
		t.Fatal(err)
	}

	stripped := mlsShapedTree(slices.Clone(nodes)...)
	stripped.nodes[10] = blank
	stripped.nodes[11] = mlsShapeParent("Y")
	want, err := stripped.nodeTreeHash(11)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, want) {
		t.Fatal("the original hash is not the hash of the tree without F")
	}
	current, err := tree.nodeTreeHash(11)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(original, current) {
		t.Fatal("excluding a leaf changed nothing")
	}
	// the tree itself must keep F
	if got := tree.nodes[11].parent.unmergedLeaves; !slices.Equal(got, []mlsLeafIndex{5}) {
		t.Fatalf("the computation edited Y: %v", got)
	}
}

func TestMlsLeavesOfATreeAreFoundOrNil(t *testing.T) {
	tree := mlsShapedTree(mlsShapeLeaf("A"), mlsTreeNode{}, mlsTreeNode{})
	if tree.leafNode(0) == nil {
		t.Error("leaf 0 is missing")
	}
	if tree.leafNode(1) != nil || tree.leafNode(2) != nil || tree.leafNode(1000) != nil {
		t.Error("a blank or missing leaf answered")
	}
}

// A valid group's tree, for each test to break in its own way.
func mlsValidTestTree(t *testing.T, suite *mlsCipherSuite) (*mlsTestGroup, *mlsRatchetTree) {
	t.Helper()
	group := mlsNewMergedTestGroup(t, suite, 5)
	// leaves added after the last commit stand unmerged under the path nodes
	group.commit(0, nil, 2, false)
	tree := group.members[0].tree.clone()
	if err := tree.validate(group.validation); err != nil {
		t.Fatal(err)
	}
	return group, tree
}

// The index of a non-blank parent, the highest one with unmerged leaves.
func mlsUnmergedParentOf(t *testing.T, tree *mlsRatchetTree) mlsNodeIndex {
	t.Helper()
	for index := len(tree.nodes) - 1; 0 <= index; index-- {
		node := tree.nodes[index]
		if node.parent != nil && 0 < len(node.parent.unmergedLeaves) {
			return mlsNodeIndex(index)
		}
	}
	t.Fatal("no parent with unmerged leaves")
	return 0
}

// Installs a changed copy of a parent, as the tree's own changes do.
func mlsReplaceParent(tree *mlsRatchetTree, index mlsNodeIndex, change func(parent *mlsParentNode)) {
	parent := *tree.nodes[index].parent
	change(&parent)
	tree.setNode(index, mlsTreeNode{parent: &parent})
}

func TestMlsValidateRefusesAnAlteredParentKey(t *testing.T) {
	group, tree := mlsValidTestTree(t, mlsTestSuiteX25519)
	other, err := tree.suite.generateKemKey("test")
	if err != nil {
		t.Fatal(err)
	}
	root := mlsTreeRoot(tree.leafCount())
	mlsReplaceParent(tree, root, func(parent *mlsParentNode) {
		parent.encryptionKey = other.PublicKey().Bytes()
	})
	if err := tree.validate(group.validation); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

func TestMlsValidateRefusesAnAlteredParentHash(t *testing.T) {
	group, tree := mlsValidTestTree(t, mlsTestSuiteX25519)
	root := mlsTreeRoot(tree.leafCount())
	left, _ := root.left()
	mlsReplaceParent(tree, left, func(parent *mlsParentNode) {
		parent.parentHash = bytes.Repeat([]byte{1}, 32)
	})
	if err := tree.validate(group.validation); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

// The hash checks alone would pass here: this is RFC §7.9.2's third condition. A leaf dropped from P's
// unmerged list, while kept under D, makes P's list disagree with C's resolution.
func TestMlsValidateRefusesAParentListingTooFewUnmergedLeaves(t *testing.T) {
	group, tree := mlsValidTestTree(t, mlsTestSuiteX25519)
	index := mlsUnmergedParentOf(t, tree)
	mlsReplaceParent(tree, index, func(parent *mlsParentNode) {
		parent.unmergedLeaves = parent.unmergedLeaves[1:]
	})
	if err := tree.validate(group.validation); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

func TestMlsValidateRefusesAnUnmergedLeafThatIsBlank(t *testing.T) {
	group, tree := mlsValidTestTree(t, mlsTestSuiteX25519)
	index := mlsUnmergedParentOf(t, tree)
	// a leaf outside the tree altogether, and a value past 2^31 whose node index would wrap
	for _, leaf := range []mlsLeafIndex{mlsLeafIndex(tree.leafCount()), 0x80000000} {
		mlsReplaceParent(tree, index, func(parent *mlsParentNode) {
			parent.unmergedLeaves = append(slices.Clone(parent.unmergedLeaves), leaf)
		})
		if err := tree.validate(group.validation); !errors.Is(err, errMlsInvalid) {
			t.Errorf("leaf %d: %v", leaf, err)
		}
		mlsReplaceParent(tree, index, func(parent *mlsParentNode) {
			parent.unmergedLeaves = parent.unmergedLeaves[:len(parent.unmergedLeaves)-1]
		})
	}
}

func TestMlsValidateRefusesAnUnmergedLeafNotBelowIt(t *testing.T) {
	group, tree := mlsValidTestTree(t, mlsTestSuiteX25519)
	root := mlsTreeRoot(tree.leafCount())
	left, _ := root.left()
	if tree.nodes[left].parent == nil {
		t.Fatal("no node to break")
	}
	var outside mlsLeafIndex
	for index := range tree.leafCount() {
		if leaf := mlsLeafIndex(index); tree.leafNode(leaf) != nil && !left.subtreeContains(leaf.node()) {
			outside = leaf
		}
	}
	mlsReplaceParent(tree, left, func(parent *mlsParentNode) {
		parent.unmergedLeaves = append(slices.Clone(parent.unmergedLeaves), outside)
	})
	if err := tree.validate(group.validation); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

// A tree anyone can write, since parent hashes need no signature: node 1 lists leaf 100 of a four-leaf
// tree and is parent-hash valid, linked from leaf 0, and the root above it takes that leaf into a
// resolution. No fuzzer writes this one, for the link is a hash it would have to invert.
func mlsTestTreeListingALeafOutside(t testing.TB) []byte {
	t.Helper()
	suite := mlsTestSuiteX25519
	listing := mlsShapeParent("listing", 100)
	listing.parent.parentHash = []byte{}
	tree := &mlsRatchetTree{suite: suite}
	blankLeafHash, err := tree.hashLeaf(1, nil)
	if err != nil {
		t.Fatal(err)
	}
	link, err := tree.hashParentHashInput(listing.parent.encryptionKey, listing.parent.parentHash, blankLeafHash)
	if err != nil {
		t.Fatal(err)
	}
	member := mlsShapeLeaf("member")
	member.leaf.leafNodeSource = mlsLeafNodeSourceCommit
	member.leaf.parentHash = link
	return mlsEncodeNodeList(t, []mlsTreeNode{member, listing, {}, mlsShapeParent("root")})
}

// A leaf index comes off the wire as a uint32, and 2n must not wrap onto a member's path: a sender this
// names does not exist, so it has no path to follow.
func TestMlsFilteredDirectPathOfALeafOutsideTheTreeIsEmpty(t *testing.T) {
	tree := mlsShapedTree(mlsShapeLeaf("a"), mlsTreeNode{}, mlsShapeLeaf("b"))
	if path := tree.filteredDirectPath(1); len(path) != 1 {
		t.Fatalf("leaf 1's path is %v", path)
	}
	for _, leaf := range []mlsLeafIndex{2, 1024*1024*1024*2 + 1} {
		if path := tree.filteredDirectPath(leaf); len(path) != 0 {
			t.Errorf("leaf %d's path is %v", leaf, path)
		}
	}
}

// Nothing here may trust an unmerged list: validate refuses one like this first, but parent hashes are
// checked on their own too, and an index into the tree must not be what stops them.
func TestMlsParentHashesRefuseAnUnmergedLeafOutsideTheTree(t *testing.T) {
	tree, err := decodeMlsRatchetTree(mlsTestSuiteX25519, mlsVectorTreeSettings(), mlsTestTreeListingALeafOutside(t))
	if err != nil {
		t.Fatal(err)
	}
	// so it is the root that reaches the leaf outside, not a refusal below it
	if err := tree.verifyParentHash(1); err != nil {
		t.Fatal(err)
	}
	if err := tree.verifyParentHashes(); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

// The decoder refuses this list, and validate holds the rule for a tree that did not come off the wire.
func TestMlsValidateRefusesUnmergedLeavesOutOfOrder(t *testing.T) {
	tree := mlsShapedTree(
		mlsShapeLeaf("A"), mlsTreeNode{}, mlsShapeLeaf("B"), mlsShapeParent("Y", 1, 0), mlsTreeNode{}, mlsTreeNode{}, mlsTreeNode{},
	)
	if err := tree.validateUnmergedLeaves(3); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

func TestMlsValidateRefusesAnIntermediateOmittingAnUnmergedLeaf(t *testing.T) {
	blank := mlsTreeNode{}
	tree := mlsShapedTree(
		mlsShapeLeaf("A"), mlsShapeParent("X"), mlsShapeLeaf("B"), mlsShapeParent("Y", 1), blank, blank, blank,
	)
	if err := tree.validateUnmergedLeaves(3); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
	tree.nodes[1] = mlsShapeParent("X", 1)
	if err := tree.validateUnmergedLeaves(3); err != nil {
		t.Fatal(err)
	}
	// a blank node between them has no list to keep
	tree.nodes[1] = blank
	if err := tree.validateUnmergedLeaves(3); err != nil {
		t.Fatal(err)
	}
}

// Two leaves on one key, each otherwise valid: nothing but the uniqueness rule can catch this.
func TestMlsValidateRefusesTwoLeavesOnOneEncryptionKey(t *testing.T) {
	suite := mlsTestSuiteX25519
	group := mlsNewTestGroup(t, suite)
	tree := group.members[0].tree
	twin := mlsNewTestClient(t, suite, "twin")
	leaf := twin.keyPackage.leafNode
	leaf.encryptionKey = tree.leafNode(0).encryptionKey
	if err := leaf.sign(suite, twin.signatureKey, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := tree.addLeaf(&leaf); err != nil {
		t.Fatal(err)
	}
	if err := tree.validate(group.validation); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

// A committer free to pick its path's keys, with every hash and signature in order, reuses another
// member's key at the root (RFC §12.4.3.1's last check). Without the rule that member could read
// what is encrypted to the root while the tree invariant says it holds nothing there.
func TestMlsValidateRefusesAParentOnAnotherNodesKey(t *testing.T) {
	suite := mlsTestSuiteX25519
	group := mlsNewMergedTestGroup(t, suite, 2)
	member := group.members[0]
	tree := member.tree.clone()

	path := tree.filteredDirectPath(0)
	tree.blankPath(0)
	parentHash, err := tree.installPathKeys(path, [][]byte{tree.leafNode(1).encryptionKey})
	if err != nil {
		t.Fatal(err)
	}
	leaf := *tree.leafNode(0)
	leaf.parentHash = parentHash
	if err := leaf.sign(suite, member.signatureKey, group.groupId, 0); err != nil {
		t.Fatal(err)
	}
	tree.setNode(mlsLeafIndex(0).node(), mlsTreeNode{leaf: &leaf})

	if err := tree.validate(group.validation); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
	if err := tree.verifyParentHashes(); err != nil {
		t.Fatalf("the hashes were meant to hold: %v", err)
	}
}

func TestMlsValidateRefusesARepeatedSignatureKey(t *testing.T) {
	suite := mlsTestSuiteX25519
	group := mlsNewTestGroup(t, suite)
	tree := group.members[0].tree
	twin := mlsNewTestClient(t, suite, "twin")
	leaf := twin.keyPackage.leafNode
	leaf.signatureKey = []byte(group.members[0].signatureKey.Public().(ed25519.PublicKey))
	if err := leaf.sign(suite, group.members[0].signatureKey, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := tree.addLeaf(&leaf); err != nil {
		t.Fatal(err)
	}
	if err := tree.validate(group.validation); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

func TestMlsValidateRefusesABadLeafSignature(t *testing.T) {
	group, tree := mlsValidTestTree(t, mlsTestSuiteX25519)
	leaf := *tree.leafNode(3)
	leaf.signature = bytes.Clone(leaf.signature)
	leaf.signature[0] ^= 1
	tree.setNode(mlsLeafIndex(3).node(), mlsTreeNode{leaf: &leaf})
	if err := tree.validate(group.validation); !errors.Is(err, errMlsAuthentication) {
		t.Fatal(err)
	}
}

// Leaves from a commit bind the group: a tree lifted into another group fails at its first one.
func TestMlsValidateBindsTheGroupId(t *testing.T) {
	group, tree := mlsValidTestTree(t, mlsTestSuiteX25519)
	validation := *group.validation
	validation.groupId = []byte("another group")
	if err := tree.validate(&validation); !errors.Is(err, errMlsAuthentication) {
		t.Fatal(err)
	}
}

func TestMlsValidateRefusesWhatTheValidatorRefuses(t *testing.T) {
	group, tree := mlsValidTestTree(t, mlsTestSuiteX25519)
	validation := *group.validation
	validation.credentialValidator = mlsRefuseEveryCredential
	if err := tree.validate(&validation); !errors.Is(err, errMlsRefused) {
		t.Fatal(err)
	}
}

func TestMlsValidateRefusesALifetimeOverTheBound(t *testing.T) {
	suite := mlsTestSuiteX25519
	client := mlsNewTestClient(t, suite, "long-lived")
	leaf := client.keyPackage.leafNode
	leaf.lifetime.notAfter = leaf.lifetime.notBefore + 91*24*60*60
	if err := leaf.sign(suite, client.signatureKey, nil, 0); err != nil {
		t.Fatal(err)
	}
	tree := newMlsRatchetTree(suite, defaultMlsTreeSettings(), &leaf)
	if err := tree.validate(mlsTestLeafValidation([]byte("group"))); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

// With its hashes and signatures in order, as a joiner would get it from a malicious committer.
func TestMlsValidateRefusesAParentKeyNobodyCanEncryptTo(t *testing.T) {
	suite := mlsSuite
	group := mlsNewMergedTestGroup(t, suite, 2)
	member := group.members[0]
	tree := member.tree.clone()

	path := tree.filteredDirectPath(0)
	tree.blankPath(0)
	parentHash, err := tree.installPathKeys(path, [][]byte{[]byte("no key at all")})
	if err != nil {
		t.Fatal(err)
	}
	leaf := *tree.leafNode(0)
	leaf.parentHash = parentHash
	if err := leaf.sign(suite, member.signatureKey, group.groupId, 0); err != nil {
		t.Fatal(err)
	}
	tree.setNode(mlsLeafIndex(0).node(), mlsTreeNode{leaf: &leaf})

	if err := tree.verifyParentHashes(); err != nil {
		t.Fatalf("the hashes were meant to hold: %v", err)
	}
	if err := tree.validate(group.validation); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

func TestMlsValidateRefusesATreeOfNoMembers(t *testing.T) {
	tree := mlsShapedTree(mlsTreeNode{})
	if err := tree.validate(mlsTestLeafValidation(nil)); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

func TestMlsValidateRefusesATreePastTheSettingsWidth(t *testing.T) {
	group, tree := mlsValidTestTree(t, mlsTestSuiteX25519)
	tree.settings = &mlsTreeSettings{MaximumLeafCount: 1}
	if err := tree.validate(group.validation); !errors.Is(err, errMlsRefused) {
		t.Fatal(err)
	}
}

// A required_capabilities extension's data.
func mlsRequiredCapabilitiesExtension(t *testing.T, required *mlsRequiredCapabilities) mlsExtension {
	t.Helper()
	encoded, err := mlsMarshal(required)
	if err != nil {
		t.Fatal(err)
	}
	return mlsExtension{extensionType: mlsExtensionTypeRequiredCapabilities, extensionData: encoded}
}

func TestMlsValidateChecksRequiredCapabilities(t *testing.T) {
	group, tree := mlsValidTestTree(t, mlsTestSuiteX25519)
	met := *group.validation
	met.groupExtensions = []mlsExtension{mlsRequiredCapabilitiesExtension(t, &mlsRequiredCapabilities{
		credentialTypes: []uint16{mlsCredentialTypeBasic},
	})}
	if err := tree.validate(&met); err != nil {
		t.Fatal(err)
	}
	unmet := *group.validation
	unmet.groupExtensions = []mlsExtension{mlsRequiredCapabilitiesExtension(t, &mlsRequiredCapabilities{
		credentialTypes: []uint16{mlsCredentialTypeUrSidecar},
	})}
	if err := tree.validate(&unmet); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
	malformed := *group.validation
	malformed.groupExtensions = []mlsExtension{{extensionType: mlsExtensionTypeRequiredCapabilities, extensionData: []byte{9}}}
	if err := tree.validate(&malformed); !errors.Is(err, errMlsMalformed) {
		t.Fatal(err)
	}
}

// RFC §13.4: every GroupContext extension must be in each member's capabilities, default ones
// implicitly.
func TestMlsValidateChecksGroupContextExtensions(t *testing.T) {
	group, tree := mlsValidTestTree(t, mlsTestSuiteX25519)
	implicit := *group.validation
	implicit.groupExtensions = []mlsExtension{{extensionType: mlsExtensionTypeExternalSenders}}
	if err := tree.validate(&implicit); err != nil {
		t.Fatal(err)
	}
	unknown := *group.validation
	unknown.groupExtensions = []mlsExtension{{extensionType: 0xf00d}}
	if err := tree.validate(&unknown); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

// One tree, one new leaf, one rule broken each way.
func TestMlsValidateNewLeafRefusals(t *testing.T) {
	suite := mlsTestSuiteX25519
	group := mlsNewMergedTestGroup(t, suite, 3)
	tree := group.members[0].tree
	newClient := func() *mlsTestClient {
		return mlsNewTestClient(t, suite, "newcomer")
	}

	valid := newClient()
	if err := tree.validateNewLeaf(&valid.keyPackage.leafNode, 3, mlsLeafNodeSourceKeyPackage, group.validation); err != nil {
		t.Fatal(err)
	}
	if err := tree.validateNewLeaf(&valid.keyPackage.leafNode, 3, mlsLeafNodeSourceCommit, group.validation); !errors.Is(err, errMlsInvalid) {
		t.Errorf("wrong source: %v", err)
	}

	sameEncryptionKey := newClient()
	leaf := sameEncryptionKey.keyPackage.leafNode
	leaf.encryptionKey = tree.leafNode(1).encryptionKey
	if err := leaf.sign(suite, sameEncryptionKey.signatureKey, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := tree.validateNewLeaf(&leaf, 3, mlsLeafNodeSourceKeyPackage, group.validation); !errors.Is(err, errMlsInvalid) {
		t.Errorf("repeated encryption key: %v", err)
	}

	sameSignatureKey := newClient()
	leaf = sameSignatureKey.keyPackage.leafNode
	leaf.signatureKey = tree.leafNode(1).signatureKey
	if err := leaf.sign(suite, group.members[1].signatureKey, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := tree.validateNewLeaf(&leaf, 3, mlsLeafNodeSourceKeyPackage, group.validation); !errors.Is(err, errMlsInvalid) {
		t.Errorf("repeated signature key: %v", err)
	}
}

// RFC §7.3's fourth check, in both directions. Only basic parses today, so a second type exists
// only as a member's in-memory leaf, which is all this check reads.
func TestMlsValidateNewLeafChecksMutualCredentialSupport(t *testing.T) {
	suite := mlsTestSuiteX25519
	group := mlsNewMergedTestGroup(t, suite, 2)

	// a member using a type the newcomer does not list
	tree := group.members[0].tree.clone()
	other := *tree.leafNode(1)
	other.credential.credentialType = 0x7777
	tree.nodes[mlsLeafIndex(1).node()].leaf = &other
	narrow := mlsNewTestClient(t, suite, "narrow")
	if err := tree.validateNewLeaf(&narrow.keyPackage.leafNode, 2, mlsLeafNodeSourceKeyPackage, group.validation); !errors.Is(err, errMlsInvalid) {
		t.Errorf("a type in use the leaf lacks: %v", err)
	}
	wide := mlsNewTestClient(t, suite, "wide")
	leaf := wide.keyPackage.leafNode
	leaf.capabilities.credentials = []uint16{mlsCredentialTypeBasic, 0x7777}
	if err := leaf.sign(suite, wide.signatureKey, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := tree.validateNewLeaf(&leaf, 2, mlsLeafNodeSourceKeyPackage, group.validation); err != nil {
		t.Errorf("a leaf listing both: %v", err)
	}

	// a newcomer using a type a member does not list
	tree = group.members[0].tree.clone()
	other = *tree.leafNode(1)
	other.capabilities.credentials = []uint16{0x7777}
	tree.nodes[mlsLeafIndex(1).node()].leaf = &other
	if err := tree.validateNewLeaf(&narrow.keyPackage.leafNode, 2, mlsLeafNodeSourceKeyPackage, group.validation); !errors.Is(err, errMlsInvalid) {
		t.Errorf("a type a member lacks: %v", err)
	}
}
