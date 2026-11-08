// MLS state on disk (§10.5's last paragraph; D-KEYS-14): each group's state, trees included, under §5.9's AEAD in
// <state>/net/<network_id>/gkm/, which a SidecarStore seals, so this file makes no file-system call and runs on
// sidecar_http over IndexedDB as well (SidecarHost.Store()). The store's sealing covers every byte, temporary files
// included, and its Commit swaps a whole file in, so each write here is atomic.
//
//	mls/<group_id>/state     the epoch this member holds: GroupContext, its keys, the epoch secrets §10.5 keeps, tree
//	mls/<group_id>/draft     its own commit staged on that epoch, with the next epoch in full (KEYS-M2-09)
//	mls/<group_id>/reached   the newest epoch it reached of the group, kept after a removal drops the state (I-16)
//	mls/<group_id>/sent      the next handshake generation it may seal at in an epoch (§10.4: each key used once)
//	mls/kp/<ref>             a KeyPackage it made, and the private keys only it holds
//
// <group_id> is 32 lowercase hex characters and <ref> 64, as gkm's keys write them (QD-442).
//
// A file is a run of sections, each a big-endian uint32 length and that many bytes, so a reader holds one section at
// a time: a state is a header section, then one section per ratchet_tree entry, which is how a 2.83 MB tree streams
// in and out with no second copy, as iOS needs (§18.4). A reader reads every file to its end, because the store
// authenticates its last chunk only there, so a cut file is a failure and never a shorter state.
//
// Loads only one group's tree at a time, the caller's (§18.4's budgets): nothing here caches a state. Another
// epoch's secrets are never written: a state file holds one epoch, and the draft holds the next only until the
// commit is adopted or discarded (RFC 9420 §9.2). A failed decode or AEAD is a failure, never an absence (D-CORE-15).
//
// Every private key and secret this reads back is an unwrap, so it is hooked here as it is decoded.
//
// The format is local and unfrozen; a version leads each file, and a file of another version fails.
//
// Not safe for concurrent use: the engine serializes its writes.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
)

const (
	// The state store's directory and file class under a network's store.
	mlsStateDirectory = "gkm"
	mlsStateClass     = "gkm"
	// The format of each file here.
	mlsStateVersion uint16 = 1
	// The most bytes one section may hold: far past a header, a node or a KeyPackage, so a length read from a
	// damaged file cannot make a reader allocate more.
	mlsStateSectionMaxByteCount = 4 * 1024 * 1024
)

// A file here that decodes but is not what it should be: a failure, as the store's own are.
var errMlsStateFormat = fmt.Errorf("%w: mls state", ErrSidecarStoreFailed)

// One engine's files, in its network's store.
type mlsStateStore struct {
	store SidecarStore
}

// The state store under store's gkm/ directory.
func newMlsStateStore(store SidecarStore) (*mlsStateStore, error) {
	if store == nil {
		return nil, fmt.Errorf("mls: no store")
	}
	directory, err := store.Directory(mlsStateDirectory, mlsStateClass)
	if err != nil {
		return nil, err
	}
	return &mlsStateStore{store: directory}, nil
}

// A group's file name.
func mlsStateGroupName(groupId Id, name string) string {
	return "mls/" + gkmPathId(groupId) + "/" + name
}

// A KeyPackage's file name.
func mlsStateKeyPackageName(ref []byte) string {
	return "mls/kp/" + hex.EncodeToString(ref)
}

// Writes one section.
func mlsWriteStateSection(writer io.Writer, body []byte) error {
	if mlsStateSectionMaxByteCount < len(body) {
		return fmt.Errorf("mls: a state section of %d bytes", len(body))
	}
	length := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	if _, err := writer.Write(length); err != nil {
		return err
	}
	_, err := writer.Write(body)
	return err
}

// Reads one section, refusing a length past the bound and a file that ends inside one.
func mlsReadStateSection(reader io.Reader) ([]byte, error) {
	length := make([]byte, 4)
	if _, err := io.ReadFull(reader, length); err != nil {
		return nil, mlsStateReadFault(err)
	}
	byteCount := binary.BigEndian.Uint32(length)
	if mlsStateSectionMaxByteCount < byteCount {
		return nil, fmt.Errorf("%w: a section of %d bytes", errMlsStateFormat, byteCount)
	}
	body := make([]byte, byteCount)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, mlsStateReadFault(err)
	}
	return body, nil
}

// Reads past the last section, so the store authenticates the file's end: anything but io.EOF is a failure.
func mlsReadStateEnd(reader io.Reader) error {
	extra := make([]byte, 1)
	if _, err := io.ReadFull(reader, extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: bytes past the last section", errMlsStateFormat)
		}
		return mlsStateReadFault(err)
	}
	return nil
}

// A short read is a cut file, and a store's own error passes as it is.
func mlsStateReadFault(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: a cut file", errMlsStateFormat)
	}
	return err
}

// Writes a whole file of sections through write, swapped in at once.
func (self *mlsStateStore) put(name string, write func(writer io.Writer) error) error {
	writer, err := self.store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if err := write(writer); err != nil {
		return err
	}
	return writer.Commit()
}

// Reads a whole file of sections through read, then its end. ErrSidecarStoreAbsent passes as it is.
func (self *mlsStateStore) get(name string, read func(reader io.Reader) error) error {
	reader, err := self.store.Open(name)
	if err != nil {
		return err
	}
	defer reader.Close()
	if err := read(reader); err != nil {
		return err
	}
	return mlsReadStateEnd(reader)
}

// A one-section file.
func (self *mlsStateStore) putSmall(name string, body []byte) error {
	return self.put(name, func(writer io.Writer) error {
		return mlsWriteStateSection(writer, body)
	})
}

// A one-section file's body.
func (self *mlsStateStore) getSmall(name string) ([]byte, error) {
	var body []byte
	err := self.get(name, func(reader io.Reader) error {
		var err error
		body, err = mlsReadStateSection(reader)
		return err
	})
	return body, err
}

// A decoder over a section that starts with this format's version.
func mlsStateDecoder(body []byte) (*mlsDecoder, error) {
	decoder := &mlsDecoder{remaining: body}
	if version := decoder.readUint16(); decoder.err != nil || version != mlsStateVersion {
		return nil, fmt.Errorf("%w: version", errMlsStateFormat)
	}
	return decoder, nil
}

// Finishes a section's decoder, any failure being the file's.
func mlsStateFinish(decoder *mlsDecoder) error {
	if err := decoder.finish(); err != nil {
		return fmt.Errorf("%w: %w", errMlsStateFormat, err)
	}
	return nil
}

// The newest epoch reached of a group, and whether any was.
func (self *mlsStateStore) reached(groupId Id) (uint64, bool, error) {
	body, err := self.getSmall(mlsStateGroupName(groupId, "reached"))
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	decoder, err := mlsStateDecoder(body)
	if err != nil {
		return 0, false, err
	}
	epoch := decoder.readUint64()
	if err := mlsStateFinish(decoder); err != nil {
		return 0, false, err
	}
	return epoch, true, nil
}

// Records that a group reached epoch.
func (self *mlsStateStore) putReached(groupId Id, epoch uint64) error {
	encoder := &mlsEncoder{}
	encoder.writeUint16(mlsStateVersion)
	encoder.writeUint64(epoch)
	return self.putSmall(mlsStateGroupName(groupId, "reached"), encoder.encoded)
}

// The next handshake generation this member may seal at in epoch of a group: 0 for an epoch it never sealed in.
func (self *mlsStateStore) sent(groupId Id, epoch uint64) (uint32, error) {
	body, err := self.getSmall(mlsStateGroupName(groupId, "sent"))
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	decoder, err := mlsStateDecoder(body)
	if err != nil {
		return 0, err
	}
	sentEpoch := decoder.readUint64()
	generation := decoder.readUint32()
	if err := mlsStateFinish(decoder); err != nil {
		return 0, err
	}
	if sentEpoch != epoch {
		return 0, nil
	}
	return generation, nil
}

// Records that generations below generation are used in epoch of a group.
func (self *mlsStateStore) putSent(groupId Id, epoch uint64, generation uint32) error {
	encoder := &mlsEncoder{}
	encoder.writeUint16(mlsStateVersion)
	encoder.writeUint64(epoch)
	encoder.writeUint32(generation)
	return self.putSmall(mlsStateGroupName(groupId, "sent"), encoder.encoded)
}

// Keeps a KeyPackage and its private keys.
func (self *mlsStateStore) putKeyPackage(held *mlsHeldKeyPackage) error {
	initKey, err := mlsKemKeyBytes(held.initKey)
	if err != nil {
		return err
	}
	defer clear(initKey)
	leafKey, err := mlsKemKeyBytes(held.leafKey)
	if err != nil {
		return err
	}
	defer clear(leafKey)
	encoder := &mlsEncoder{}
	encoder.writeUint16(mlsStateVersion)
	encoder.writeOptional(held.lastResort)
	encoder.writeVector(held.encoded)
	encoder.writeVector(initKey)
	encoder.writeVector(leafKey)
	encoder.writeVector(held.signatureKey.Seed())
	body, err := encoder.finish()
	if err != nil {
		return err
	}
	defer clear(body)
	return self.putSmall(mlsStateKeyPackageName(held.ref), body)
}

// A KeyPackage this engine made, by its ref: ErrSidecarStoreAbsent for one it never made or no longer holds.
func (self *mlsStateStore) keyPackage(suite *mlsCipherSuite, ref []byte) (*mlsHeldKeyPackage, error) {
	body, err := self.getSmall(mlsStateKeyPackageName(ref))
	if err != nil {
		return nil, err
	}
	defer clear(body)
	decoder, err := mlsStateDecoder(body)
	if err != nil {
		return nil, err
	}
	lastResort := decoder.readOptional()
	encoded := decoder.readVector()
	initKeyBytes := decoder.readVector()
	leafKeyBytes := decoder.readVector()
	signatureSeed := decoder.readVector()
	defer clear(initKeyBytes)
	defer clear(leafKeyBytes)
	defer clear(signatureSeed)
	if err := mlsStateFinish(decoder); err != nil {
		return nil, err
	}
	keyPackage := &mlsKeyPackage{}
	if err := mlsUnmarshalMessageOf(encoded, mlsWireFormatKeyPackage, keyPackage); err != nil {
		return nil, fmt.Errorf("%w: %w", errMlsStateFormat, err)
	}
	initKey, err := suite.loadKemKey("init_priv", initKeyBytes)
	if err != nil {
		return nil, err
	}
	leafKey, err := suite.loadKemKey("leaf_priv", leafKeyBytes)
	if err != nil {
		return nil, err
	}
	signatureKey, err := suite.loadSignatureKey("signature_priv", signatureSeed)
	if err != nil {
		return nil, err
	}
	keyRef, err := keyPackage.ref(suite)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(keyRef, ref) || !bytes.Equal(initKey.PublicKey().Bytes(), keyPackage.initKey) ||
		!bytes.Equal(leafKey.PublicKey().Bytes(), keyPackage.leafNode.encryptionKey) {
		return nil, fmt.Errorf("%w: a KeyPackage's keys are not its own", errMlsStateFormat)
	}
	return &mlsHeldKeyPackage{
		keyPackage:   keyPackage,
		encoded:      encoded,
		ref:          bytes.Clone(ref),
		lastResort:   lastResort,
		initKey:      initKey,
		leafKey:      leafKey,
		signatureKey: signatureKey,
	}, nil
}

// Drops a KeyPackage's private keys, once a Welcome under it joined.
func (self *mlsStateStore) removeKeyPackage(ref []byte) error {
	return self.store.Remove(mlsStateKeyPackageName(ref))
}

// Writes a group's state, replacing the one there at once.
func (self *mlsStateStore) putState(groupId Id, state *mlsGroupState) error {
	return self.put(mlsStateGroupName(groupId, "state"), func(writer io.Writer) error {
		return mlsWriteGroupState(writer, state)
	})
}

// A group's state: ErrSidecarStoreAbsent when none is held.
func (self *mlsStateStore) state(groupId Id, suite *mlsCipherSuite, settings *mlsGroupSettings, credentialValidator mlsCredentialValidator) (*mlsGroupState, error) {
	var state *mlsGroupState
	err := self.get(mlsStateGroupName(groupId, "state"), func(reader io.Reader) error {
		var err error
		state, err = mlsReadGroupState(reader, suite, settings, credentialValidator)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(state.groupId(), groupId.Bytes()) {
		return nil, fmt.Errorf("%w: another group's state", errMlsStateFormat)
	}
	return state, nil
}

// Drops a group's state and draft, as a removal or a shred does. Its reached epoch stays.
func (self *mlsStateStore) removeState(groupId Id) error {
	if err := self.store.Remove(mlsStateGroupName(groupId, "draft")); err != nil {
		return err
	}
	if err := self.store.Remove(mlsStateGroupName(groupId, "sent")); err != nil {
		return err
	}
	return self.store.Remove(mlsStateGroupName(groupId, "state"))
}

// A state as sections: a header with everything but the tree, then each ratchet_tree entry up to the last
// non-blank one, each encoded alone so only one is ever in memory.
func mlsWriteGroupState(writer io.Writer, state *mlsGroupState) error {
	last := len(state.tree.nodes) - 1
	for 0 <= last && state.tree.nodes[last].blank() {
		last -= 1
	}
	header, err := state.encodeStateHeader(last + 1)
	if err != nil {
		return err
	}
	defer clear(header)
	if err := mlsWriteStateSection(writer, header); err != nil {
		return err
	}
	for index := 0; index <= last; index += 1 {
		encoder := &mlsEncoder{}
		state.tree.nodes[index].encode(encoder)
		node, err := encoder.finish()
		if err != nil {
			return err
		}
		if err := mlsWriteStateSection(writer, node); err != nil {
			return err
		}
	}
	return nil
}

// The state's header section. Its private keys and secrets are in it, so the caller erases it.
func (self *mlsGroupState) encodeStateHeader(nodeCount int) ([]byte, error) {
	nodes := slices.Sorted(maps.Keys(self.treeSecrets.nodeIndexKeys))
	encoder := &mlsEncoder{}
	encoder.writeUint16(mlsStateVersion)
	self.groupContext.encode(encoder)
	encoder.writeUint32(uint32(self.ownLeaf()))
	encoder.writeVector(self.signatureKey.Seed())
	var keyErr error
	encoder.writeVectorOf(func(elements *mlsEncoder) {
		for _, node := range nodes {
			encoded, err := mlsKemKeyBytes(self.treeSecrets.nodeIndexKeys[node])
			if err != nil {
				keyErr = err
				return
			}
			elements.writeUint32(uint32(node))
			elements.writeVector(encoded)
			clear(encoded)
		}
	})
	if keyErr != nil {
		return nil, keyErr
	}
	encoder.writeVector(self.interimTranscriptHash)
	encoder.writeVector(self.confirmationTag)
	encoder.writeVector(self.initSecret)
	encoder.writeVector(self.exporterSecret)
	encoder.writeVector(self.externalSecret)
	encoder.writeVector(self.encryptionSecret)
	encoder.writeVector(self.senderDataSecret)
	encoder.writeVector(self.epochAuthenticator)
	encoder.writeUint32(uint32(nodeCount))
	return encoder.finish()
}

// A state from its sections, its tree held to its own GroupContext and its keys to the tree, so a state that
// decodes into another group's tree or keys fails.
func mlsReadGroupState(reader io.Reader, suite *mlsCipherSuite, settings *mlsGroupSettings, credentialValidator mlsCredentialValidator) (*mlsGroupState, error) {
	header, err := mlsReadStateSection(reader)
	if err != nil {
		return nil, err
	}
	defer clear(header)
	decoder, err := mlsStateDecoder(header)
	if err != nil {
		return nil, err
	}
	groupContext := &mlsGroupContext{}
	groupContext.decode(decoder)
	ownLeaf := mlsLeafIndex(decoder.readUint32())
	signatureSeed := decoder.readVector()
	defer clear(signatureSeed)
	type nodeKey struct {
		node mlsNodeIndex
		key  []byte
	}
	nodeKeys := []nodeKey{}
	decoder.readVectorOf(func(element *mlsDecoder) {
		node := mlsNodeIndex(element.readUint32())
		nodeKeys = append(nodeKeys, nodeKey{node: node, key: element.readVector()})
	})
	defer func() {
		for _, nodeKey := range nodeKeys {
			clear(nodeKey.key)
		}
	}()
	args := &mlsGroupStateArgs{
		suite:                 suite,
		settings:              settings,
		credentialValidator:   credentialValidator,
		groupContext:          groupContext,
		interimTranscriptHash: decoder.readVector(),
		confirmationTag:       decoder.readVector(),
		epochSecrets: &mlsEpochSecrets{
			initSecret:         decoder.readVector(),
			exporterSecret:     decoder.readVector(),
			externalSecret:     decoder.readVector(),
			encryptionSecret:   decoder.readVector(),
			senderDataSecret:   decoder.readVector(),
			epochAuthenticator: decoder.readVector(),
		},
	}
	defer args.epochSecrets.erase()
	nodeCount := decoder.readUint32()
	if err := mlsStateFinish(decoder); err != nil {
		return nil, err
	}
	if groupContext.cipherSuite != suite.value || mlsTreeWidth(settings.Tree.MaximumLeafCount) < nodeCount {
		return nil, fmt.Errorf("%w: a state of suite %#x and %d nodes", errMlsStateFormat, groupContext.cipherSuite, nodeCount)
	}
	for kind, secret := range map[string][]byte{
		"init_secret":         args.epochSecrets.initSecret,
		"exporter_secret":     args.epochSecrets.exporterSecret,
		"external_secret":     args.epochSecrets.externalSecret,
		"encryption_secret":   args.epochSecrets.encryptionSecret,
		"sender_data_secret":  args.epochSecrets.senderDataSecret,
		"epoch_authenticator": args.epochSecrets.epochAuthenticator,
	} {
		if len(secret) != suite.hashLength {
			return nil, fmt.Errorf("%w: %s of %d bytes", errMlsStateFormat, kind, len(secret))
		}
		testHookSecret(kind, secret)
	}

	nodes := make([]mlsTreeNode, 0, nodeCount)
	for range nodeCount {
		section, err := mlsReadStateSection(reader)
		if err != nil {
			return nil, err
		}
		var node mlsTreeNode
		nodeDecoder := &mlsDecoder{remaining: section}
		node.decode(nodeDecoder)
		if err := mlsStateFinish(nodeDecoder); err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	tree, err := newMlsRatchetTreeFromNodes(suite, settings.Tree, nodes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errMlsStateFormat, err)
	}
	treeHash, err := tree.treeHash()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(treeHash, groupContext.treeHash) || tree.leafNode(ownLeaf) == nil {
		return nil, fmt.Errorf("%w: a tree not its GroupContext's", errMlsStateFormat)
	}

	signatureKey, err := suite.loadSignatureKey("signature_priv", signatureSeed)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(tree.leafNode(ownLeaf).signatureKey, signatureKey.Public().(ed25519.PublicKey)) {
		return nil, fmt.Errorf("%w: a signature key not its leaf's", errMlsStateFormat)
	}
	treeSecrets := &mlsTreeSecrets{suite: suite, leaf: ownLeaf, nodeIndexKeys: map[mlsNodeIndex]hpke.PrivateKey{}}
	for _, nodeKey := range nodeKeys {
		var key hpke.PrivateKey
		if nodeKey.node == ownLeaf.node() {
			key, err = suite.loadKemKey("leaf_priv", nodeKey.key)
		} else {
			key, err = suite.loadKemKey("node_priv", nodeKey.key)
		}
		if err != nil {
			return nil, err
		}
		treeSecrets.nodeIndexKeys[nodeKey.node] = key
	}
	if _, ok := treeSecrets.nodeIndexKeys[ownLeaf.node()]; !ok || !treeSecrets.consistentWith(tree) {
		return nil, fmt.Errorf("%w: keys not its tree's", errMlsStateFormat)
	}
	args.tree = tree
	args.treeSecrets = treeSecrets
	args.signatureKey = signatureKey
	return newMlsGroupState(args)
}

// A staged commit of this member's as its draft file holds it, with the next epoch in full.
func (self *mlsStateStore) putDraft(groupId Id, staged *mlsStagedState) error {
	header := &mlsEncoder{}
	header.writeUint16(mlsStateVersion)
	header.writeUint64(staged.baseEpoch)
	header.writeVector(staged.baseEpochAuthenticator)
	header.writeVector(staged.message)
	header.writeVector(staged.welcome)
	header.writeVector(staged.authenticatedData)
	header.writeUint32(uint32(staged.committer))
	staged.committerLeaf.encode(header)
	header.writeVectorOf(func(elements *mlsEncoder) {
		for _, index := range staged.added {
			elements.writeUint32(uint32(index))
		}
	})
	header.writeVectorOf(func(elements *mlsEncoder) {
		for _, removed := range staged.removed {
			elements.writeUint32(uint32(removed.index))
			removed.leaf.encode(elements)
		}
	})
	encodedHeader, err := header.finish()
	if err != nil {
		return err
	}
	return self.put(mlsStateGroupName(groupId, "draft"), func(writer io.Writer) error {
		if err := mlsWriteStateSection(writer, encodedHeader); err != nil {
			return err
		}
		return mlsWriteGroupState(writer, staged.next)
	})
}

// This member's draft on a group: ErrSidecarStoreAbsent when none is there.
func (self *mlsStateStore) draft(groupId Id, suite *mlsCipherSuite, settings *mlsGroupSettings, credentialValidator mlsCredentialValidator) (*mlsStagedState, error) {
	staged := &mlsStagedState{}
	err := self.get(mlsStateGroupName(groupId, "draft"), func(reader io.Reader) error {
		header, err := mlsReadStateSection(reader)
		if err != nil {
			return err
		}
		decoder, err := mlsStateDecoder(header)
		if err != nil {
			return err
		}
		staged.baseEpoch = decoder.readUint64()
		staged.baseEpochAuthenticator = decoder.readVector()
		staged.message = decoder.readVector()
		staged.welcome = decoder.readVector()
		staged.authenticatedData = decoder.readVector()
		staged.committer = mlsLeafIndex(decoder.readUint32())
		staged.committerLeaf = &mlsLeafNode{}
		staged.committerLeaf.decode(decoder)
		decoder.readVectorOf(func(element *mlsDecoder) {
			staged.added = append(staged.added, mlsLeafIndex(element.readUint32()))
		})
		decoder.readVectorOf(func(element *mlsDecoder) {
			removed := mlsRemovedLeaf{index: mlsLeafIndex(element.readUint32()), leaf: &mlsLeafNode{}}
			removed.leaf.decode(element)
			staged.removed = append(staged.removed, removed)
		})
		if err := mlsStateFinish(decoder); err != nil {
			return err
		}
		if len(staged.welcome) == 0 {
			staged.welcome = nil
		}
		staged.next, err = mlsReadGroupState(reader, suite, settings, credentialValidator)
		return err
	})
	if err != nil {
		return nil, err
	}
	if staged.next.epoch() != staged.baseEpoch+1 || !bytes.Equal(staged.next.groupId(), groupId.Bytes()) {
		return nil, fmt.Errorf("%w: a draft not of its group's next epoch", errMlsStateFormat)
	}
	return staged, nil
}

// Drops a group's draft.
func (self *mlsStateStore) removeDraft(groupId Id) error {
	return self.store.Remove(mlsStateGroupName(groupId, "draft"))
}
