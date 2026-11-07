// §23.5's fake of the MLS subset: sidecar.MlsEngine for one sidecar, over a FakeMlsWorld every sidecar of a test
// shares. It keeps what gkm's client and gkm can see of the subset, and none of its cryptography:
//
//   - a commit is staged, then adopted or discarded, and a received one is staged for its caller to judge;
//   - an epoch's exporter, KEK_e with it, derives from a secret only the epoch's leaves reach: a sidecar the epoch
//     removed, or never added, gets none of it;
//   - a member's commit is RFC 9420's PrivateMessage up to its last field, so sidecar.ParseMlsHeader reads its
//     group, epoch, content type and authenticated_data as gkm will a real one's; what a real one encrypts is a
//     handle here, which only FakeMls resolves;
//   - an external commit is a PublicMessage up to its content, a handle too, so ParseMlsHeader refuses it as it
//     refuses a real one until KEYS-M2-05's framing lands;
//   - KeyPackages, Welcomes and GroupInfos are MLSMessages of their own wire formats with bodies only FakeMls
//     reads, which a real parser refuses. A GroupInfo carries a MAC under its epoch's secret, so a forged one
//     fails Complete, as a real one fails its signature;
//   - what the subset refuses is refused (§10.4): application data and standalone proposals, Update among them,
//     and any sender but a member or a new member's commit, when a message is processed; a Remove without a path,
//     a committer removing itself and an empty commit, when one is made; a commit on another epoch or by a leaf
//     its epoch does not hold, wherever it arrives.
//
// sidecartest/mlssuite holds FakeMls and the real engine (KEYS-M2-08) to the same behavior.
// Engines and the world are safe for concurrent use; a group, pending join or staged commit has one owner.

package sidecartest

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar"
)

// The MLSMessage values FakeMls frames with: version mls10, RFC 9420's wire formats, its content and sender types,
// and suite 0x0010.
const (
	fakeMlsVersion                 uint16 = 1
	fakeMlsWireFormatPublicMessage uint16 = 1
	fakeMlsWireFormatPrivate       uint16 = 2
	fakeMlsWireFormatWelcome       uint16 = 3
	fakeMlsWireFormatGroupInfo     uint16 = 4
	fakeMlsWireFormatKeyPackage    uint16 = 5
	fakeMlsContentTypeCommit       uint8  = 3
	fakeMlsSenderNewMemberCommit   uint8  = 4
	fakeMlsCipherSuite             uint16 = 0x0010
	fakeMlsHandleByteCount                = 32
	fakeMlsSecretByteCount                = 32
)

// What FakeMls refuses for the subset, or for a message that is not what it claims.
var errFakeMlsRefused = errors.New("fake mls: refused")

// Every group's epochs, commits and KeyPackages, which every engine of a test reads.
type FakeMlsWorld struct {
	stateLock       sync.Mutex
	handleCommits   map[string]*fakeMlsCommit
	epochIdEpochs   map[string]*fakeMlsEpoch
	refKeyPackages  map[string]*fakeMlsKeyPackage
	groupIdUrGroups map[sidecar.Id]*sidecar.MlsUrGroup
}

func NewFakeMlsWorld() *FakeMlsWorld {
	return &FakeMlsWorld{
		handleCommits:   map[string]*fakeMlsCommit{},
		epochIdEpochs:   map[string]*fakeMlsEpoch{},
		refKeyPackages:  map[string]*fakeMlsKeyPackage{},
		groupIdUrGroups: map[sidecar.Id]*sidecar.MlsUrGroup{},
	}
}

// One sidecar's engine. credential is its leaf's, a UrMlsCredential's encoding, which Roster shows.
func (self *FakeMlsWorld) Engine(sidecarId sidecar.Id, credential []byte) *FakeMls {
	return &FakeMls{
		world:          self,
		sidecarId:      sidecarId,
		credential:     bytes.Clone(credential),
		groupIdEpochs:  map[sidecar.Id]*fakeMlsEpoch{},
		keyPackageRefs: map[string]bool{},
	}
}

// 32 random bytes.
func fakeMlsRandom() []byte {
	random := make([]byte, fakeMlsSecretByteCount)
	rand.Read(random)
	return random
}

// One epoch of one group, as a commit made it. Two commits racing on one epoch each make one, and the epoch every
// member adopts is the one gkm took.
type fakeMlsEpoch struct {
	// which epoch of the group this is, among those racing commits made
	epochId []byte
	groupId sidecar.Id
	epoch   uint64
	secret  []byte
	// by leaf index; nil is a blank leaf
	roster []*sidecar.MlsMember
}

// The leaf a sidecar holds in the epoch, or nil.
func (self *fakeMlsEpoch) leafOf(sidecarId sidecar.Id) *sidecar.MlsMember {
	for _, member := range self.roster {
		if member != nil && member.SidecarId == sidecarId {
			return member
		}
	}
	return nil
}

// The epoch's leaves, blanks left out.
func (self *fakeMlsEpoch) members() []sidecar.MlsMember {
	members := []sidecar.MlsMember{}
	for _, member := range self.roster {
		if member != nil {
			members = append(members, fakeMlsCopyMember(member))
		}
	}
	return members
}

// A member that shares nothing with the roster.
func fakeMlsCopyMember(member *sidecar.MlsMember) sidecar.MlsMember {
	return sidecar.MlsMember{LeafIndex: member.LeafIndex, SidecarId: member.SidecarId, Credential: bytes.Clone(member.Credential)}
}

// The epoch's exporter: HKDF over its secret, which only its leaves reach.
func (self *fakeMlsEpoch) exporter(label string, context []byte, length int) ([]byte, error) {
	info := append(append([]byte(label), 0), context...)
	return hkdf.Key(sha256.New, self.secret, []byte("fake mls exporter"), string(info), length)
}

// epoch_authenticator's stand-in.
func (self *fakeMlsEpoch) authenticator() []byte {
	mac := hmac.New(sha256.New, self.secret)
	mac.Write([]byte("fake mls epoch_authenticator"))
	return mac.Sum(nil)
}

// The epoch's GroupInfo as signer's leaf writes it: the epoch it names and a MAC under its secret.
func (self *fakeMlsEpoch) groupInfo(signer uint32) []byte {
	body := fakeMlsAppendHeader(nil, fakeMlsWireFormatGroupInfo)
	body = fakeMlsAppendVector(body, self.groupId.Bytes())
	body = binary.BigEndian.AppendUint64(body, self.epoch)
	body = fakeMlsAppendVector(body, self.epochId)
	body = binary.BigEndian.AppendUint32(body, signer)
	mac := hmac.New(sha256.New, self.secret)
	mac.Write(body)
	return fakeMlsAppendVector(body, mac.Sum(nil))
}

// A commit as the world holds it, behind the handle its message carries.
type fakeMlsCommit struct {
	handle            []byte
	from              *fakeMlsEpoch
	to                *fakeMlsEpoch
	committer         sidecar.MlsMember
	added             []sidecar.MlsMember
	removed           []sidecar.MlsMember
	authenticatedData []byte
	external          bool
	message           []byte
	welcome           []byte
}

// A KeyPackage as the world holds it, by its ref.
type fakeMlsKeyPackage struct {
	ref        []byte
	sidecarId  sidecar.Id
	credential []byte
	lastResort bool
	encoded    []byte
}

// One sidecar's MLS on the fake.
type FakeMls struct {
	world      *FakeMlsWorld
	sidecarId  sidecar.Id
	credential []byte

	stateLock sync.Mutex
	// adopted, by group
	groupIdEpochs map[sidecar.Id]*fakeMlsEpoch
	// the KeyPackages this engine made, which only it can join under
	keyPackageRefs map[string]bool
}

// Its sidecar.
func (self *FakeMls) SidecarId() sidecar.Id {
	return self.sidecarId
}

func (self *FakeMls) CreateKeyPackage(lastResort bool) (*sidecar.MlsKeyPackage, error) {
	encoded := fakeMlsAppendHeader(nil, fakeMlsWireFormatKeyPackage)
	encoded = binary.BigEndian.AppendUint16(encoded, fakeMlsCipherSuite)
	encoded = fakeMlsAppendVector(encoded, self.sidecarId.Bytes())
	encoded = fakeMlsAppendVector(encoded, self.credential)
	encoded = fakeMlsAppendVector(encoded, fakeMlsRandom())
	if lastResort {
		encoded = append(encoded, 1)
	} else {
		encoded = append(encoded, 0)
	}
	refDigest := sha256.Sum256(append([]byte("fake mls KeyPackage ref"), encoded...))
	keyPackage := &fakeMlsKeyPackage{
		ref:        refDigest[:],
		sidecarId:  self.sidecarId,
		credential: bytes.Clone(self.credential),
		lastResort: lastResort,
		encoded:    encoded,
	}
	func() {
		self.world.stateLock.Lock()
		defer self.world.stateLock.Unlock()
		self.world.refKeyPackages[hex.EncodeToString(keyPackage.ref)] = keyPackage
	}()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.keyPackageRefs[hex.EncodeToString(keyPackage.ref)] = true
	}()
	return &sidecar.MlsKeyPackage{Encoded: bytes.Clone(encoded), Ref: bytes.Clone(keyPackage.ref), LastResort: lastResort}, nil
}

func (self *FakeMls) CreateGroup(groupId sidecar.Id, urGroup *sidecar.MlsUrGroup) (sidecar.MlsGroup, error) {
	if urGroup == nil {
		return nil, fmt.Errorf("%w: a group needs its ur_group", errFakeMlsRefused)
	}
	epoch := &fakeMlsEpoch{
		epochId: fakeMlsRandom(),
		groupId: groupId,
		secret:  fakeMlsRandom(),
		roster:  []*sidecar.MlsMember{{LeafIndex: 0, SidecarId: self.sidecarId, Credential: bytes.Clone(self.credential)}},
	}
	err := func() error {
		self.world.stateLock.Lock()
		defer self.world.stateLock.Unlock()
		if _, exists := self.world.groupIdUrGroups[groupId]; exists {
			return fmt.Errorf("%w: group %s exists", errFakeMlsRefused, groupId)
		}
		urGroupCopy := *urGroup
		self.world.groupIdUrGroups[groupId] = &urGroupCopy
		self.world.epochIdEpochs[hex.EncodeToString(epoch.epochId)] = epoch
		return nil
	}()
	if err != nil {
		return nil, err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.groupIdEpochs[groupId] = epoch
	}()
	return &fakeMlsGroup{engine: self, epoch: epoch}, nil
}

func (self *FakeMls) JoinWelcome(welcome []byte) (sidecar.MlsPendingJoin, error) {
	reader := &fakeMlsReader{remaining: welcome}
	reader.header(fakeMlsWireFormatWelcome)
	if reader.uint16() != fakeMlsCipherSuite {
		reader.fail("cipher suite")
	}
	secrets := reader.vector()
	reader.vector()
	if err := reader.finish(); err != nil {
		return nil, err
	}
	secretsReader := &fakeMlsReader{remaining: secrets}
	for len(secretsReader.remaining) != 0 && secretsReader.err == nil {
		ref := secretsReader.vector()
		handle := secretsReader.vector()
		secretsReader.vector()
		if secretsReader.err != nil {
			break
		}
		if !self.madeKeyPackage(ref) {
			continue
		}
		commit, err := self.world.commit(handle)
		if err != nil {
			return nil, err
		}
		if commit.to.leafOf(self.sidecarId) == nil {
			return nil, sidecar.ErrMlsNotMember
		}
		return &fakeMlsPendingJoin{engine: self, epoch: commit.to}, nil
	}
	if secretsReader.err != nil {
		return nil, secretsReader.err
	}
	return nil, fmt.Errorf("%w: a Welcome to none of this sidecar's KeyPackages", sidecar.ErrMlsNotMember)
}

// Whether this engine made the KeyPackage ref names.
func (self *FakeMls) madeKeyPackage(ref []byte) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.keyPackageRefs[hex.EncodeToString(ref)]
}

func (self *FakeMls) JoinExternal(groupInfo []byte, args *sidecar.MlsCommitArgs) (sidecar.MlsStagedCommit, error) {
	if args == nil || len(args.Adds) != 0 || !args.Path {
		return nil, fmt.Errorf("%w: an external commit adds no one and carries a path", errFakeMlsRefused)
	}
	from, _, err := self.world.checkGroupInfo(groupInfo)
	if err != nil {
		return nil, err
	}
	removed := []sidecar.MlsMember{}
	for _, leafIndex := range args.Removes {
		if len(from.roster) <= int(leafIndex) || from.roster[leafIndex] == nil || from.roster[leafIndex].SidecarId != self.sidecarId {
			return nil, fmt.Errorf("%w: an external commit removes only its sender's old leaf", errFakeMlsRefused)
		}
		removed = append(removed, fakeMlsCopyMember(from.roster[leafIndex]))
	}
	roster := fakeMlsRemove(from.roster, args.Removes)
	if (&fakeMlsEpoch{roster: roster}).leafOf(self.sidecarId) != nil {
		return nil, fmt.Errorf("%w: a resync that keeps its old leaf", errFakeMlsRefused)
	}
	roster, joined := fakeMlsAdd(roster, sidecar.MlsMember{SidecarId: self.sidecarId, Credential: self.credential})
	commit := self.world.newCommit(from, roster, joined, nil, removed, args.AuthenticatedData, true)
	return &fakeMlsStagedCommit{engine: self, commit: commit, own: true}, nil
}

func (self *FakeMls) LoadGroup(groupId sidecar.Id) (sidecar.MlsGroup, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	epoch, ok := self.groupIdEpochs[groupId]
	if !ok {
		return nil, sidecar.ErrMlsGroupUnknown
	}
	return &fakeMlsGroup{engine: self, epoch: epoch}, nil
}

// The epoch this engine holds of a group, or nil.
func (self *FakeMls) heldEpoch(groupId sidecar.Id) *fakeMlsEpoch {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.groupIdEpochs[groupId]
}

// Moves the engine from one epoch to the next, or drops the group if the next holds no leaf of it.
func (self *FakeMls) adopt(from *fakeMlsEpoch, to *fakeMlsEpoch) (sidecar.MlsGroup, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	held, ok := self.groupIdEpochs[to.groupId]
	if from != nil && (!ok || held != from) {
		return nil, fmt.Errorf("%w: epoch %d is no longer held", sidecar.ErrMlsGroupUnknown, from.epoch)
	}
	if to.leafOf(self.sidecarId) == nil {
		delete(self.groupIdEpochs, to.groupId)
		return nil, sidecar.ErrMlsNotMember
	}
	self.groupIdEpochs[to.groupId] = to
	return &fakeMlsGroup{engine: self, epoch: to}, nil
}

// A commit by handle.
func (self *FakeMlsWorld) commit(handle []byte) (*fakeMlsCommit, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	commit, ok := self.handleCommits[hex.EncodeToString(handle)]
	if !ok {
		return nil, fmt.Errorf("%w: a commit no engine made", errFakeMlsRefused)
	}
	return commit, nil
}

// The KeyPackages of an Add, each one an engine made.
func (self *FakeMlsWorld) keyPackages(encodeds [][]byte) ([]*fakeMlsKeyPackage, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	keyPackages := []*fakeMlsKeyPackage{}
	for _, encoded := range encodeds {
		refDigest := sha256.Sum256(append([]byte("fake mls KeyPackage ref"), encoded...))
		keyPackage, ok := self.refKeyPackages[hex.EncodeToString(refDigest[:])]
		if !ok || !bytes.Equal(keyPackage.encoded, encoded) {
			return nil, fmt.Errorf("%w: a KeyPackage no engine made", errFakeMlsRefused)
		}
		keyPackages = append(keyPackages, keyPackage)
	}
	return keyPackages, nil
}

// The epoch a GroupInfo names, once its MAC holds, and the leaf that signed it.
func (self *FakeMlsWorld) checkGroupInfo(groupInfo []byte) (*fakeMlsEpoch, uint32, error) {
	reader := &fakeMlsReader{remaining: groupInfo}
	reader.header(fakeMlsWireFormatGroupInfo)
	groupIdBytes := reader.vector()
	epochNumber := reader.uint64()
	epochId := reader.vector()
	signer := reader.uint32()
	tag := reader.vector()
	if err := reader.finish(); err != nil {
		return nil, 0, err
	}
	epoch := func() *fakeMlsEpoch {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.epochIdEpochs[hex.EncodeToString(epochId)]
	}()
	if epoch == nil || !bytes.Equal(epoch.groupId.Bytes(), groupIdBytes) || epoch.epoch != epochNumber {
		return nil, 0, fmt.Errorf("%w: a GroupInfo of no epoch", errFakeMlsRefused)
	}
	if !hmac.Equal(epoch.groupInfo(signer), groupInfo) || len(tag) != sha256.Size {
		return nil, 0, fmt.Errorf("%w: a forged GroupInfo", errFakeMlsRefused)
	}
	if len(epoch.roster) <= int(signer) || epoch.roster[signer] == nil {
		return nil, 0, fmt.Errorf("%w: a GroupInfo signed by no leaf", errFakeMlsRefused)
	}
	return epoch, signer, nil
}

// Registers a commit from one epoch to a new one with roster, and frames its message.
func (self *FakeMlsWorld) newCommit(from *fakeMlsEpoch, roster []*sidecar.MlsMember, committer sidecar.MlsMember, added []sidecar.MlsMember, removed []sidecar.MlsMember, authenticatedData []byte, external bool) *fakeMlsCommit {
	to := &fakeMlsEpoch{
		epochId: fakeMlsRandom(),
		groupId: from.groupId,
		epoch:   from.epoch + 1,
		secret:  fakeMlsRandom(),
		roster:  roster,
	}
	commit := &fakeMlsCommit{
		handle:            fakeMlsRandom(),
		from:              from,
		to:                to,
		committer:         committer,
		added:             added,
		removed:           removed,
		authenticatedData: bytes.Clone(authenticatedData),
		external:          external,
	}
	if external {
		message := fakeMlsAppendHeader(nil, fakeMlsWireFormatPublicMessage)
		message = fakeMlsAppendVector(message, from.groupId.Bytes())
		message = binary.BigEndian.AppendUint64(message, from.epoch)
		message = append(message, fakeMlsSenderNewMemberCommit)
		message = fakeMlsAppendVector(message, authenticatedData)
		message = append(message, fakeMlsContentTypeCommit)
		commit.message = fakeMlsAppendVector(message, commit.handle)
	} else {
		message := fakeMlsAppendHeader(nil, fakeMlsWireFormatPrivate)
		message = fakeMlsAppendVector(message, from.groupId.Bytes())
		message = binary.BigEndian.AppendUint64(message, from.epoch)
		message = append(message, fakeMlsContentTypeCommit)
		message = fakeMlsAppendVector(message, authenticatedData)
		// encrypted_sender_data, which a real one keeps the sender's leaf in
		message = fakeMlsAppendVector(message, fakeMlsRandom()[:16])
		commit.message = fakeMlsAppendVector(message, commit.handle)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.handleCommits[hex.EncodeToString(commit.handle)] = commit
	self.epochIdEpochs[hex.EncodeToString(to.epochId)] = to
	return commit
}

// roster with the leaves at indexes blanked.
func fakeMlsRemove(roster []*sidecar.MlsMember, indexes []uint32) []*sidecar.MlsMember {
	removed := slices.Clone(roster)
	for _, index := range indexes {
		removed[index] = nil
	}
	return removed
}

// roster with member in its leftmost blank leaf, or a new one, as RFC 9420 §12.1.1 places an Add.
func fakeMlsAdd(roster []*sidecar.MlsMember, member sidecar.MlsMember) ([]*sidecar.MlsMember, sidecar.MlsMember) {
	added := slices.Clone(roster)
	index := slices.Index(added, nil)
	if index < 0 {
		index = len(added)
		added = append(added, nil)
	}
	member.LeafIndex = uint32(index)
	member.Credential = bytes.Clone(member.Credential)
	added[index] = &member
	return added, fakeMlsCopyMember(&member)
}

// One group at the epoch this engine adopted.
type fakeMlsGroup struct {
	engine *FakeMls
	epoch  *fakeMlsEpoch
}

// The epoch, while the engine still holds it: an older one's secrets are gone (RFC 9420 §9.2).
func (self *fakeMlsGroup) held() (*fakeMlsEpoch, error) {
	if self.engine.heldEpoch(self.epoch.groupId) != self.epoch {
		return nil, fmt.Errorf("%w: epoch %d is no longer held", sidecar.ErrMlsGroupUnknown, self.epoch.epoch)
	}
	return self.epoch, nil
}

func (self *fakeMlsGroup) Exporter(label string, context []byte, length int) ([]byte, error) {
	epoch, err := self.held()
	if err != nil {
		return nil, err
	}
	return epoch.exporter(label, context, length)
}

func (self *fakeMlsGroup) GroupId() sidecar.Id {
	return self.epoch.groupId
}

func (self *fakeMlsGroup) Epoch() uint64 {
	return self.epoch.epoch
}

func (self *fakeMlsGroup) EpochAuthenticator() []byte {
	return self.epoch.authenticator()
}

func (self *fakeMlsGroup) Self() sidecar.MlsMember {
	return fakeMlsCopyMember(self.epoch.leafOf(self.engine.sidecarId))
}

func (self *fakeMlsGroup) Roster() []sidecar.MlsMember {
	return self.epoch.members()
}

func (self *fakeMlsGroup) GroupInfo() ([]byte, error) {
	epoch, err := self.held()
	if err != nil {
		return nil, err
	}
	return epoch.groupInfo(epoch.leafOf(self.engine.sidecarId).LeafIndex), nil
}

func (self *fakeMlsGroup) Commit(args *sidecar.MlsCommitArgs) (sidecar.MlsStagedCommit, error) {
	from, err := self.held()
	if err != nil {
		return nil, err
	}
	if args == nil || (len(args.Adds) == 0 && len(args.Removes) == 0 && !args.Path) {
		return nil, fmt.Errorf("%w: an empty commit", errFakeMlsRefused)
	}
	if 0 < len(args.Removes) && !args.Path {
		return nil, fmt.Errorf("%w: a Remove carries a path (§10.4)", errFakeMlsRefused)
	}
	keyPackages, err := self.engine.world.keyPackages(args.Adds)
	if err != nil {
		return nil, err
	}

	committer := from.leafOf(self.engine.sidecarId)
	removed := []sidecar.MlsMember{}
	for index, leafIndex := range args.Removes {
		if len(from.roster) <= int(leafIndex) || from.roster[leafIndex] == nil || slices.Contains(args.Removes[:index], leafIndex) {
			return nil, fmt.Errorf("%w: a Remove of no leaf", errFakeMlsRefused)
		}
		if leafIndex == committer.LeafIndex {
			return nil, fmt.Errorf("%w: a committer removing itself (RFC 9420 §12.2)", errFakeMlsRefused)
		}
		removed = append(removed, fakeMlsCopyMember(from.roster[leafIndex]))
	}
	roster := fakeMlsRemove(from.roster, args.Removes)
	added := []sidecar.MlsMember{}
	for _, keyPackage := range keyPackages {
		if (&fakeMlsEpoch{roster: roster}).leafOf(keyPackage.sidecarId) != nil {
			return nil, fmt.Errorf("%w: an Add of a sidecar already a leaf", errFakeMlsRefused)
		}
		var member sidecar.MlsMember
		roster, member = fakeMlsAdd(roster, sidecar.MlsMember{SidecarId: keyPackage.sidecarId, Credential: keyPackage.credential})
		added = append(added, member)
	}
	commit := self.engine.world.newCommit(from, roster, fakeMlsCopyMember(committer), added, removed, args.AuthenticatedData, false)
	if 0 < len(keyPackages) {
		secrets := []byte{}
		for _, keyPackage := range keyPackages {
			secrets = fakeMlsAppendVector(secrets, keyPackage.ref)
			// kem_output, which a real Welcome encrypts the group secrets to
			secrets = fakeMlsAppendVector(secrets, commit.handle)
			secrets = fakeMlsAppendVector(secrets, nil)
		}
		welcome := fakeMlsAppendHeader(nil, fakeMlsWireFormatWelcome)
		welcome = binary.BigEndian.AppendUint16(welcome, fakeMlsCipherSuite)
		welcome = fakeMlsAppendVector(welcome, secrets)
		commit.welcome = fakeMlsAppendVector(welcome, nil)
	}
	return &fakeMlsStagedCommit{engine: self.engine, commit: commit, own: true}, nil
}

func (self *fakeMlsGroup) Process(message []byte) (sidecar.MlsStagedCommit, error) {
	from, err := self.held()
	if err != nil {
		return nil, err
	}
	reader := &fakeMlsReader{remaining: message}
	if reader.uint16() != fakeMlsVersion {
		reader.fail("version")
	}
	wireFormat := reader.uint16()
	groupIdBytes := reader.vector()
	epochNumber := reader.uint64()
	var contentType uint8
	var authenticatedData []byte
	switch wireFormat {
	case fakeMlsWireFormatPrivate:
		contentType = reader.uint8()
		authenticatedData = reader.vector()
		reader.vector()
	case fakeMlsWireFormatPublicMessage:
		if sender := reader.uint8(); sender != fakeMlsSenderNewMemberCommit {
			reader.fail(fmt.Sprintf("sender type %d", sender))
		}
		authenticatedData = reader.vector()
		contentType = reader.uint8()
	default:
		reader.fail(fmt.Sprintf("wire format %d is no commit", wireFormat))
	}
	if reader.err == nil && contentType != fakeMlsContentTypeCommit {
		reader.fail(fmt.Sprintf("content type %d (§10.4 frames commits alone)", contentType))
	}
	handle := reader.vector()
	if err := reader.finish(); err != nil {
		return nil, err
	}
	if !bytes.Equal(groupIdBytes, from.groupId.Bytes()) || epochNumber != from.epoch {
		return nil, fmt.Errorf("%w: a commit of another group or epoch", errFakeMlsRefused)
	}
	commit, err := self.engine.world.commit(handle)
	if err != nil {
		return nil, err
	}
	if commit.from != from {
		return nil, fmt.Errorf("%w: a commit on another branch of epoch %d", errFakeMlsRefused, from.epoch)
	}
	if commit.external != (wireFormat == fakeMlsWireFormatPublicMessage) || !bytes.Equal(commit.authenticatedData, authenticatedData) {
		return nil, fmt.Errorf("%w: a commit that is not what its frame says", errFakeMlsRefused)
	}
	if !commit.external && from.leafOf(commit.committer.SidecarId) == nil {
		return nil, fmt.Errorf("%w: a commit by a leaf its epoch does not hold", errFakeMlsRefused)
	}
	return &fakeMlsStagedCommit{engine: self.engine, commit: commit}, nil
}

// A commit staged on this engine's epoch.
type fakeMlsStagedCommit struct {
	engine *FakeMls
	commit *fakeMlsCommit
	// made by this engine, so it holds the Welcome
	own bool
}

func (self *fakeMlsStagedCommit) Exporter(label string, context []byte, length int) ([]byte, error) {
	if self.commit.to.leafOf(self.engine.sidecarId) == nil {
		return nil, sidecar.ErrMlsNotMember
	}
	return self.commit.to.exporter(label, context, length)
}

func (self *fakeMlsStagedCommit) Message() []byte {
	return bytes.Clone(self.commit.message)
}

func (self *fakeMlsStagedCommit) Epoch() uint64 {
	return self.commit.to.epoch
}

func (self *fakeMlsStagedCommit) EpochAuthenticator() []byte {
	if self.commit.to.leafOf(self.engine.sidecarId) == nil {
		return nil
	}
	return self.commit.to.authenticator()
}

func (self *fakeMlsStagedCommit) Committer() sidecar.MlsMember {
	return fakeMlsCopyMember(&self.commit.committer)
}

func (self *fakeMlsStagedCommit) Added() []sidecar.MlsMember {
	added := []sidecar.MlsMember{}
	for index := range self.commit.added {
		added = append(added, fakeMlsCopyMember(&self.commit.added[index]))
	}
	return added
}

func (self *fakeMlsStagedCommit) Removed() []sidecar.MlsMember {
	removed := []sidecar.MlsMember{}
	for index := range self.commit.removed {
		removed = append(removed, fakeMlsCopyMember(&self.commit.removed[index]))
	}
	return removed
}

func (self *fakeMlsStagedCommit) AuthenticatedData() []byte {
	return bytes.Clone(self.commit.authenticatedData)
}

func (self *fakeMlsStagedCommit) Welcome() []byte {
	if !self.own {
		return nil
	}
	return bytes.Clone(self.commit.welcome)
}

func (self *fakeMlsStagedCommit) GroupInfo() ([]byte, error) {
	leaf := self.commit.to.leafOf(self.engine.sidecarId)
	if leaf == nil {
		return nil, sidecar.ErrMlsNotMember
	}
	return self.commit.to.groupInfo(leaf.LeafIndex), nil
}

func (self *fakeMlsStagedCommit) Adopt() (sidecar.MlsGroup, error) {
	from := self.commit.from
	if self.commit.external && self.own {
		// the joiner holds no epoch of the group, or an older one it is resyncing from
		from = nil
	}
	return self.engine.adopt(from, self.commit.to)
}

func (self *fakeMlsStagedCommit) Discard() {}

// A Welcome opened, its epoch's exporter reachable, and its group not yet joined.
type fakeMlsPendingJoin struct {
	engine *FakeMls
	epoch  *fakeMlsEpoch
}

func (self *fakeMlsPendingJoin) Exporter(label string, context []byte, length int) ([]byte, error) {
	return self.epoch.exporter(label, context, length)
}

func (self *fakeMlsPendingJoin) GroupId() sidecar.Id {
	return self.epoch.groupId
}

func (self *fakeMlsPendingJoin) Epoch() uint64 {
	return self.epoch.epoch
}

func (self *fakeMlsPendingJoin) Complete(groupInfo []byte) (sidecar.MlsGroup, error) {
	epoch, _, err := self.engine.world.checkGroupInfo(groupInfo)
	if err != nil {
		return nil, err
	}
	if epoch != self.epoch {
		return nil, fmt.Errorf("%w: a GroupInfo of another epoch than the Welcome's", errFakeMlsRefused)
	}
	return self.engine.adopt(nil, epoch)
}

// MLSMessage's version and wire format.
func fakeMlsAppendHeader(encoded []byte, wireFormat uint16) []byte {
	encoded = binary.BigEndian.AppendUint16(encoded, fakeMlsVersion)
	return binary.BigEndian.AppendUint16(encoded, wireFormat)
}

// opaque value<V>, its length header in RFC 9420 §2.1.2's shortest form.
func fakeMlsAppendVector(encoded []byte, value []byte) []byte {
	switch length := len(value); {
	case length < 64:
		encoded = append(encoded, byte(length))
	case length < 16384:
		encoded = binary.BigEndian.AppendUint16(encoded, 0x4000|uint16(length))
	default:
		encoded = binary.BigEndian.AppendUint32(encoded, 0x80000000|uint32(length))
	}
	return append(encoded, value...)
}

// Reads what FakeMls framed, keeping its first failure.
type fakeMlsReader struct {
	remaining []byte
	err       error
}

func (self *fakeMlsReader) fail(reason string) {
	if self.err == nil {
		self.err = fmt.Errorf("%w: %s", errFakeMlsRefused, reason)
	}
	self.remaining = nil
}

func (self *fakeMlsReader) take(length int) []byte {
	if self.err != nil {
		return nil
	}
	if length < 0 || len(self.remaining) < length {
		self.fail("input ends inside a value")
		return nil
	}
	taken := self.remaining[:length]
	self.remaining = self.remaining[length:]
	return taken
}

func (self *fakeMlsReader) uint8() uint8 {
	taken := self.take(1)
	if taken == nil {
		return 0
	}
	return taken[0]
}

func (self *fakeMlsReader) uint16() uint16 {
	taken := self.take(2)
	if taken == nil {
		return 0
	}
	return binary.BigEndian.Uint16(taken)
}

func (self *fakeMlsReader) uint32() uint32 {
	taken := self.take(4)
	if taken == nil {
		return 0
	}
	return binary.BigEndian.Uint32(taken)
}

func (self *fakeMlsReader) uint64() uint64 {
	taken := self.take(8)
	if taken == nil {
		return 0
	}
	return binary.BigEndian.Uint64(taken)
}

func (self *fakeMlsReader) vector() []byte {
	if self.err != nil || len(self.remaining) == 0 {
		self.fail("input ends before a vector")
		return nil
	}
	var length int
	switch self.remaining[0] >> 6 {
	case 0:
		length = int(self.uint8())
	case 1:
		length = int(self.uint16() & 0x3fff)
	case 2:
		length = int(self.uint32() & 0x3fffffff)
	default:
		self.fail("vector header prefix 0b11")
		return nil
	}
	return bytes.Clone(self.take(length))
}

// The version and wire format an MLSMessage of this kind starts with.
func (self *fakeMlsReader) header(wireFormat uint16) {
	if self.uint16() != fakeMlsVersion || self.uint16() != wireFormat {
		self.fail("not this kind of MLSMessage")
	}
}

func (self *fakeMlsReader) finish() error {
	if self.err != nil {
		return self.err
	}
	if len(self.remaining) != 0 {
		return fmt.Errorf("%w: %d bytes past the value", errFakeMlsRefused, len(self.remaining))
	}
	return nil
}
