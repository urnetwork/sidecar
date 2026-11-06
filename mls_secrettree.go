// The secret tree and sender ratchets (RFC 9420 §9), which give each member one-use keys and nonces
// for PrivateMessage, and the sender data key (§6.3.2).
//
// This is where forward secrecy of messages is won, so §9.2's deletion schedule is the design. A
// node's secret is overwritten once its two children exist, a leaf's once its two ratchets do, and
// each ratchet keeps only the secret of its next generation.
//
// A ratchet only moves forward. Keys of skipped generations are not kept: §10.4 carries only
// handshakes in PrivateMessage, gkm orders them one commit to an epoch, so a member has no use for a
// late key, and a key not kept cannot leak. RFC 9420 allows this (§9.2's MAY).
//
// A receiver must not lose a key to a forged message, so stepTo holds the next state apart and the
// ratchet moves only when the caller reports the message opened. A sender is the reverse: it moves
// before it encrypts, so two messages can never share a key, whatever fails afterward.
//
// The tree and its ratchets are not safe for concurrent use; one group state owns them.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"slices"
)

const (
	// The two sender ratchets of a leaf, as their labels (§9).
	mlsRatchetHandshake   = "handshake"
	mlsRatchetApplication = "application"
)

// A generation already consumed, or past what the settings allow.
var errMlsGeneration = errors.New("mls: generation out of reach")

// Tunes a secret tree.
type mlsSecretTreeSettings struct {
	// Generations a single message may jump past a ratchet's next unused one. A generation comes
	// from sender data, which every member can forge for any sender, so this bounds the hashing one
	// message can demand. Honest senders stay near zero: a member sends about one handshake an epoch,
	// more only when a commit attempt is dropped. Zero accepts only the next generation.
	MaximumForwardDistance uint32
}

// The defaults every secret tree runs on outside tests.
func defaultMlsSecretTreeSettings() *mlsSecretTreeSettings {
	return &mlsSecretTreeSettings{
		MaximumForwardDistance: 1000,
	}
}

// One sender ratchet: a leaf's handshake or application ratchet (§9.1).
type mlsSenderRatchet struct {
	suite    *mlsCipherSuite
	settings *mlsSecretTreeSettings

	// ratchet_secret_[N]_[generation]
	secret []byte
	// The next generation not yet consumed.
	generation uint32
}

// A receiver's view of one generation, held apart from the ratchet until the message opens.
type mlsRatchetStep struct {
	ratchet    *mlsSenderRatchet
	generation uint32
	key        []byte
	nonce      []byte
	// ratchet_secret_[N]_[generation+1]
	nextSecret []byte
}

// Derives one generation's key and nonce without moving the ratchet. Forward distance is the caller's
// to check.
func (self *mlsSenderRatchet) derive(generation uint32) (*mlsRatchetStep, error) {
	if generation == math.MaxUint32 {
		return nil, fmt.Errorf("%w: the last generation has no successor", errMlsGeneration)
	}
	suite := self.suite
	secret := bytes.Clone(self.secret)
	defer func() { clear(secret) }()
	for current := self.generation; current < generation; current++ {
		next, err := suite.deriveTreeSecret("ratchet_secret", secret, "secret", current, suite.hashLength)
		if err != nil {
			return nil, err
		}
		clear(secret)
		secret = next
	}
	nonce, err := suite.deriveTreeSecret("ratchet_nonce", secret, "nonce", generation, suite.aeadNonceLength)
	if err != nil {
		return nil, err
	}
	key, err := suite.deriveTreeSecret("ratchet_key", secret, "key", generation, suite.aeadKeyLength)
	if err != nil {
		return nil, err
	}
	nextSecret, err := suite.deriveTreeSecret("ratchet_secret", secret, "secret", generation, suite.hashLength)
	if err != nil {
		return nil, err
	}
	return &mlsRatchetStep{
		ratchet:    self,
		generation: generation,
		key:        key,
		nonce:      nonce,
		nextSecret: nextSecret,
	}, nil
}

// For a receiver: this generation's key and nonce, leaving the ratchet where it is until the step is
// consumed. Refuses a generation already consumed or too far ahead.
func (self *mlsSenderRatchet) stepTo(generation uint32) (*mlsRatchetStep, error) {
	if generation < self.generation {
		return nil, fmt.Errorf("%w: %d is consumed, the next is %d", errMlsGeneration, generation, self.generation)
	}
	if distance := generation - self.generation; self.settings.MaximumForwardDistance < distance {
		return nil, fmt.Errorf("%w: %d is %d ahead", errMlsGeneration, generation, distance)
	}
	return self.derive(generation)
}

// For a sender: the next generation's key and nonce, already consumed from the ratchet, for the
// caller to use once and overwrite.
func (self *mlsSenderRatchet) next() (generation uint32, key []byte, nonce []byte, err error) {
	step, err := self.derive(self.generation)
	if err != nil {
		return 0, nil, nil, err
	}
	generation, key, nonce = step.generation, step.key, step.nonce
	step.advance()
	return generation, key, nonce, nil
}

// Moves the ratchet past this step's generation and overwrites what it passed.
func (self *mlsRatchetStep) advance() {
	ratchet := self.ratchet
	clear(ratchet.secret)
	ratchet.secret = self.nextSecret
	ratchet.generation = self.generation + 1
	self.nextSecret = nil
}

// The message opened: the generation and everything before it are gone. A step the ratchet has since
// passed stays erased, and the ratchet never moves back.
func (self *mlsRatchetStep) consume() {
	if self.ratchet.generation <= self.generation && self.nextSecret != nil {
		self.advance()
	}
	self.discard()
}

// The message did not open: the ratchet is as it was.
func (self *mlsRatchetStep) discard() {
	clear(self.key)
	clear(self.nonce)
	clear(self.nextSecret)
	self.nextSecret = nil
}

// A leaf's two ratchets.
type mlsLeafRatchets struct {
	handshake   *mlsSenderRatchet
	application *mlsSenderRatchet
}

// One epoch's secret tree, shaped like the epoch's ratchet tree.
type mlsSecretTree struct {
	suite     *mlsCipherSuite
	settings  *mlsSecretTreeSettings
	leafCount uint32

	// The tree's frontier: nodes whose secret exists and is not yet consumed.
	nodeIndexSecrets map[mlsNodeIndex][]byte
	// Leaves whose secret has become ratchets.
	leafIndexRatchets map[mlsLeafIndex]*mlsLeafRatchets
}

// Starts a tree from encryption_secret at its root. The tree keeps its own copy, so the caller still
// owns and erases the input.
func newMlsSecretTree(suite *mlsCipherSuite, settings *mlsSecretTreeSettings, encryptionSecret []byte, leafCount uint32) (*mlsSecretTree, error) {
	if !mlsTreeLeafCountValid(leafCount) {
		return nil, fmt.Errorf("mls: secret tree of %d leaves", leafCount)
	}
	return &mlsSecretTree{
		suite:             suite,
		settings:          settings,
		leafCount:         leafCount,
		nodeIndexSecrets:  map[mlsNodeIndex][]byte{mlsTreeRoot(leafCount): bytes.Clone(encryptionSecret)},
		leafIndexRatchets: map[mlsLeafIndex]*mlsLeafRatchets{},
	}, nil
}

// A leaf's ratchets, deriving down to it the first time. Every node passed has both children stored
// and is erased (§9.2).
func (self *mlsSecretTree) ratchets(leaf mlsLeafIndex) (*mlsLeafRatchets, error) {
	if self.leafCount <= uint32(leaf) {
		return nil, fmt.Errorf("mls: leaf %d in a secret tree of %d", leaf, self.leafCount)
	}
	if ratchets := self.leafIndexRatchets[leaf]; ratchets != nil {
		return ratchets, nil
	}

	suite := self.suite
	target := leaf.node()
	path := target.directPath(self.leafCount)
	slices.Reverse(path)
	for _, node := range path {
		secret, ok := self.nodeIndexSecrets[node]
		if !ok {
			continue
		}
		left, _ := node.left()
		right, _ := node.right()
		leftSecret, err := suite.expandWithLabel("tree_node_secret", secret, "tree", []byte("left"), suite.hashLength)
		if err != nil {
			return nil, err
		}
		rightSecret, err := suite.expandWithLabel("tree_node_secret", secret, "tree", []byte("right"), suite.hashLength)
		if err != nil {
			return nil, err
		}
		self.nodeIndexSecrets[left] = leftSecret
		self.nodeIndexSecrets[right] = rightSecret
		clear(secret)
		delete(self.nodeIndexSecrets, node)
	}

	leafSecret, ok := self.nodeIndexSecrets[target]
	if !ok {
		return nil, fmt.Errorf("mls: leaf %d's secret is gone", leaf)
	}
	handshakeSecret, err := suite.expandWithLabel("handshake_ratchet_secret", leafSecret, mlsRatchetHandshake, nil, suite.hashLength)
	if err != nil {
		return nil, err
	}
	applicationSecret, err := suite.expandWithLabel("application_ratchet_secret", leafSecret, mlsRatchetApplication, nil, suite.hashLength)
	if err != nil {
		return nil, err
	}
	clear(leafSecret)
	delete(self.nodeIndexSecrets, target)

	ratchets := &mlsLeafRatchets{
		handshake:   &mlsSenderRatchet{suite: suite, settings: self.settings, secret: handshakeSecret},
		application: &mlsSenderRatchet{suite: suite, settings: self.settings, secret: applicationSecret},
	}
	self.leafIndexRatchets[leaf] = ratchets
	return ratchets, nil
}

// Overwrites everything the tree holds, at the end of its epoch.
func (self *mlsSecretTree) erase() {
	for node, secret := range self.nodeIndexSecrets {
		clear(secret)
		delete(self.nodeIndexSecrets, node)
	}
	for leaf, ratchets := range self.leafIndexRatchets {
		clear(ratchets.handshake.secret)
		clear(ratchets.application.secret)
		delete(self.leafIndexRatchets, leaf)
	}
}

// sender_data_key and sender_data_nonce (§6.3.2), from sender_data_secret and the first KDF.Nh bytes
// of the content ciphertext, or all of it if shorter.
func (self *mlsCipherSuite) deriveSenderDataKey(senderDataSecret []byte, ciphertext []byte) (key []byte, nonce []byte, err error) {
	sample := ciphertext[:min(len(ciphertext), self.hashLength)]
	key, err = self.expandWithLabel("sender_data_key", senderDataSecret, "key", sample, self.aeadKeyLength)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = self.expandWithLabel("sender_data_nonce", senderDataSecret, "nonce", sample, self.aeadNonceLength)
	if err != nil {
		return nil, nil, err
	}
	return key, nonce, nil
}
