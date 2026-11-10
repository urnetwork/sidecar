//go:build !sidecar_http

// gkm's routes as the group flows' tests need them (sidecar.GkmGroupApi): one store every device's api shares, each
// object an If-None-Match create as gkm's is, with the winner on a 412 or 409, and faults a test plants before or
// after a call, so a kill and a lost answer are deterministic. It runs none of gkm's own checks, which gkmservice's
// tests hold; a keychain over a map stands in for keychain.ur.

package sidecar_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A SidecarSecrets over a map.
type gkmFakeSecrets struct {
	stateLock  sync.Mutex
	nameValues map[string][]byte
}

func newGkmFakeSecrets() *gkmFakeSecrets {
	return &gkmFakeSecrets{nameValues: map[string][]byte{}}
}

func (self *gkmFakeSecrets) Get(name string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.nameValues[name]
	if !ok {
		return nil, sidecar.ErrSidecarStoreAbsent
	}
	return bytes.Clone(value), nil
}

func (self *gkmFakeSecrets) Put(name string, value []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nameValues[name] = bytes.Clone(value)
	return nil
}

func (self *gkmFakeSecrets) Delete(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.nameValues, name)
	return nil
}

func (self *gkmFakeSecrets) List(prefix string) ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	names := []string{}
	for name := range self.nameValues {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names, nil
}

// One stored epoch.
type gkmFakeEpoch struct {
	object *protocol.GkmEpochObject
}

// Everything gkm holds in a test.
type gkmFakeStore struct {
	t     *testing.T
	clock sidecar.Clock

	stateLock sync.Mutex
	// each call, in order: "<sidecar label>:<route>"
	calls []string
	// a fault a test planted, by route: before it acts, a kill before the write; after it, a lost answer
	beforeFaults map[string]error
	afterFaults  map[string]error
	// what a test runs once just before the next call of a route acts, with no lock held: another device's flow, so
	// two race at one object in the order the test chose
	routeHooks map[string]func()

	groupOwnerRepoIds map[sidecar.Id]sidecar.Id
	repoForms         map[sidecar.Id][]*bridge.Signed
	groupGenerations  map[sidecar.Id][]*bridge.Signed
	groupEpochs       map[sidecar.Id][]*protocol.GkmEpochObject
	pathWraps         map[string][]byte
	pathRecoveryWraps map[string][]byte
	readerKeys        map[sidecar.Id]*bridge.Signed
	keyPackages       map[sidecar.Id][]*sidecar.MlsKeyPackage
	groupWelcomes     map[string][]byte
	welcomeEntries    map[sidecar.Id][]*protocol.GkmWelcomeEntry
	// every late ask: "<recipient>:<g>"
	lateAsks []string
}

func newGkmFakeStore(t *testing.T, clock sidecar.Clock) *gkmFakeStore {
	return &gkmFakeStore{
		t:                 t,
		clock:             clock,
		beforeFaults:      map[string]error{},
		afterFaults:       map[string]error{},
		routeHooks:        map[string]func(){},
		groupOwnerRepoIds: map[sidecar.Id]sidecar.Id{},
		repoForms:         map[sidecar.Id][]*bridge.Signed{},
		groupGenerations:  map[sidecar.Id][]*bridge.Signed{},
		groupEpochs:       map[sidecar.Id][]*protocol.GkmEpochObject{},
		pathWraps:         map[string][]byte{},
		pathRecoveryWraps: map[string][]byte{},
		readerKeys:        map[sidecar.Id]*bridge.Signed{},
		keyPackages:       map[sidecar.Id][]*sidecar.MlsKeyPackage{},
		groupWelcomes:     map[string][]byte{},
		welcomeEntries:    map[sidecar.Id][]*protocol.GkmWelcomeEntry{},
	}
}

// The error a planted kill returns: the process died before or after the call, as its caller sees it.
var errGkmFakeFault = errors.New("fake gkm: a planted fault")

// Plants a fault that fires once at the next call of route: before it acts when before, else after it has.
func (self *gkmFakeStore) plant(route string, before bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if before {
		self.beforeFaults[route] = errGkmFakeFault
	} else {
		self.afterFaults[route] = errGkmFakeFault
	}
}

// Runs hook once, just before the next call of route by the device labelled label acts.
func (self *gkmFakeStore) plantHook(label string, route string, hook func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.routeHooks[label+":"+route] = hook
}

// How many calls of route the store has seen.
func (self *gkmFakeStore) callCount(route string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, call := range self.calls {
		if strings.HasSuffix(call, ":"+route) {
			count += 1
		}
	}
	return count
}

// The newest generation a group holds, 0 for none.
func (self *gkmFakeStore) newestGeneration(groupId sidecar.Id) uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return uint64(len(self.groupGenerations[groupId]))
}

// The newest epoch a group holds; false for a group with none.
func (self *gkmFakeStore) newestEpoch(groupId sidecar.Id) (uint64, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	epochs := self.groupEpochs[groupId]
	return uint64(len(epochs)) - 1, 0 < len(epochs)
}

// The wrap paths a group holds for one generation, sorted.
func (self *gkmFakeStore) wrapPaths(groupId sidecar.Id, generation uint64) []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	prefix := sidecar.GkmGenerationPath(groupId, generation)
	prefix = strings.Replace(prefix, "/gen/", "/wrap/", 1) + "/"
	paths := []string{}
	for path := range self.pathWraps {
		if strings.HasPrefix(path, prefix) {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	return paths
}

// The recovery wrap paths the store holds for one group and generation.
func (self *gkmFakeStore) recoveryWrapPaths(groupId sidecar.Id, generation uint64) []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	paths := []string{}
	for path := range self.pathRecoveryWraps {
		if strings.Contains(path, "/"+hex.EncodeToString(groupId.Bytes())+"/"+fmt.Sprintf("%020d", generation)+"/") {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	return paths
}

// One device's api on the store.
type gkmFakeApi struct {
	store     *gkmFakeStore
	label     string
	sidecarId sidecar.Id
}

var _ sidecar.GkmGroupApi = (*gkmFakeApi)(nil)

func (self *gkmFakeStore) api(label string, sidecarId sidecar.Id) *gkmFakeApi {
	return &gkmFakeApi{store: self, label: label, sidecarId: sidecarId}
}

// Runs one call under the store's lock, between its planted faults.
func (self *gkmFakeApi) call(route string, act func() error) error {
	store := self.store
	var hook func()
	func() {
		store.stateLock.Lock()
		defer store.stateLock.Unlock()
		hook = store.routeHooks[self.label+":"+route]
		delete(store.routeHooks, self.label+":"+route)
	}()
	if hook != nil {
		hook()
	}
	store.stateLock.Lock()
	defer store.stateLock.Unlock()
	store.calls = append(store.calls, self.label+":"+route)
	if fault, ok := store.beforeFaults[route]; ok {
		delete(store.beforeFaults, route)
		return fault
	}
	if err := act(); err != nil {
		return err
	}
	if fault, ok := store.afterFaults[route]; ok {
		delete(store.afterFaults, route)
		return fault
	}
	return nil
}

// gkm's refusal with status, carrying a winner's bytes.
func gkmFakeRefusal(status int, winner proto.Message) error {
	refusal := &sidecar.GkmError{Status: status}
	if winner != nil {
		refusal.Winner, _ = proto.MarshalOptions{Deterministic: true}.Marshal(winner)
	}
	return refusal
}

func (self *gkmFakeApi) CreateGroup(ctx context.Context, repoId sidecar.Id, request *protocol.GkmGroupCreateRequest) error {
	return self.call("CreateGroup", func() error {
		store := self.store
		form := &protocol.GroupForm{}
		if err := proto.Unmarshal(request.GetForm().GetBody(), form); err != nil {
			return gkmFakeRefusal(http.StatusBadRequest, nil)
		}
		groupId := sidecar.Id(form.GetGroupId())
		// the owner marker first: a group belongs to one repo
		if ownerRepoId, taken := store.groupOwnerRepoIds[groupId]; taken && ownerRepoId != repoId {
			return gkmFakeRefusal(http.StatusConflict, nil)
		}
		store.groupOwnerRepoIds[groupId] = repoId
		if forms := store.repoForms[repoId]; len(forms) == 0 {
			store.repoForms[repoId] = []*bridge.Signed{request.GetForm()}
		} else if !proto.Equal(forms[0], request.GetForm()) {
			return gkmFakeRefusal(http.StatusConflict, forms[0])
		}
		rotate := &protocol.GenRotate{}
		if err := proto.Unmarshal(request.GetGenRotate().GetBody(), rotate); err != nil {
			return gkmFakeRefusal(http.StatusBadRequest, nil)
		}
		epochZero := &protocol.GkmEpochObject{
			Header:              &protocol.GkmCommitHeader{Generation: 1, Auth: rotate.GetAuth()},
			Uploader:            self.sidecarId.Bytes(),
			TimeMs:              store.clock.Now().UnixMilli(),
			GenWrap:             request.GetGenWrap(),
			SealedGroupInfo:     request.GetSealedGroupInfo(),
			GroupInfoGeneration: 1,
			CipherSuite:         request.GetCipherSuite(),
		}
		if epochs := store.groupEpochs[groupId]; len(epochs) == 0 {
			store.groupEpochs[groupId] = []*protocol.GkmEpochObject{epochZero}
		} else if !bytes.Equal(epochs[0].GetGenWrap(), epochZero.GetGenWrap()) || !bytes.Equal(epochs[0].GetSealedGroupInfo(), epochZero.GetSealedGroupInfo()) {
			return gkmFakeRefusal(http.StatusConflict, epochs[0])
		}
		if generations := store.groupGenerations[groupId]; len(generations) == 0 {
			store.groupGenerations[groupId] = []*bridge.Signed{request.GetGenRotate()}
		} else if !proto.Equal(generations[0], request.GetGenRotate()) {
			return gkmFakeRefusal(http.StatusConflict, generations[0])
		}
		return nil
	})
}

func (self *gkmFakeApi) Forms(ctx context.Context, repoId sidecar.Id) (*protocol.GkmFormsReply, error) {
	reply := &protocol.GkmFormsReply{}
	err := self.call("Forms", func() error {
		reply.Forms = slices.Clone(self.store.repoForms[repoId])
		return nil
	})
	return reply, err
}

func (self *gkmFakeApi) Epochs(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, after uint64) (*protocol.GkmEpochsReply, error) {
	reply := &protocol.GkmEpochsReply{}
	err := self.call("Epochs", func() error {
		for epoch, object := range self.store.groupEpochs[groupId] {
			if after < uint64(epoch) {
				reply.Epochs = append(reply.Epochs, &protocol.GkmEpochEntry{Epoch: uint64(epoch), Object: object})
			}
		}
		return nil
	})
	return reply, err
}

func (self *gkmFakeApi) CommitEpoch(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, epoch uint64, request *protocol.GkmEpochRequest) error {
	return self.call("CommitEpoch", func() error {
		store := self.store
		epochs := store.groupEpochs[groupId]
		switch {
		case uint64(len(epochs)) < epoch || epoch == 0:
			return gkmFakeRefusal(http.StatusForbidden, nil)
		case epoch < uint64(len(epochs)):
			if bytes.Equal(epochs[epoch].GetCommit(), request.GetCommit()) {
				return nil
			}
			return gkmFakeRefusal(http.StatusConflict, epochs[epoch])
		}
		store.groupEpochs[groupId] = append(epochs, &protocol.GkmEpochObject{
			Commit:              request.GetCommit(),
			Uploader:            self.sidecarId.Bytes(),
			TimeMs:              store.clock.Now().UnixMilli(),
			GenWrap:             request.GetGenWrap(),
			SealedGroupInfo:     request.GetSealedGroupInfo(),
			GroupInfoGeneration: request.GetGroupInfoGeneration(),
		})
		return nil
	})
}

func (self *gkmFakeApi) Generations(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, since uint64) (*protocol.GkmGenerationsReply, error) {
	reply := &protocol.GkmGenerationsReply{}
	err := self.call("Generations", func() error {
		generations := self.store.groupGenerations[groupId]
		if since < uint64(len(generations)) {
			reply.Generations = slices.Clone(generations[since:])
		}
		return nil
	})
	return reply, err
}

func (self *gkmFakeApi) ClaimGeneration(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, generation uint64, rotate *bridge.Signed) error {
	return self.call("ClaimGeneration", func() error {
		store := self.store
		generations := store.groupGenerations[groupId]
		switch {
		case generation == 0 || uint64(len(generations))+1 < generation:
			return gkmFakeRefusal(http.StatusForbidden, nil)
		case generation <= uint64(len(generations)):
			held := generations[generation-1]
			if proto.Equal(held, rotate) {
				return nil
			}
			return gkmFakeRefusal(http.StatusPreconditionFailed, held)
		}
		store.groupGenerations[groupId] = append(generations, rotate)
		return nil
	})
}

// The recipient a stored delivery names, as a wrap path writes it.
func gkmFakeDeliveryBody(deliveryBytes []byte) (*protocol.KeyDelivery, sidecar.GkmWrapType, string, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(deliveryBytes, signed); err != nil {
		return nil, 0, "", err
	}
	if signed.GetType() == uint32(bridge.SignedType_SIGNED_DELEGATION_WRAP) {
		wrap := &protocol.DelegationWrap{}
		if err := proto.Unmarshal(signed.GetBody(), wrap); err != nil {
			return nil, 0, "", err
		}
		return wrap.GetWrap(), sidecar.GkmWrapTypeDelegation, "d:" + hex.EncodeToString(wrap.GetWrap().GetRecipient()), nil
	}
	wrap := &protocol.ReaderWrap{}
	if err := proto.Unmarshal(signed.GetBody(), wrap); err != nil {
		return nil, 0, "", err
	}
	return wrap.GetWrap(), sidecar.GkmWrapTypeReader, "s:" + hex.EncodeToString(wrap.GetWrap().GetRecipient()), nil
}

func (self *gkmFakeApi) Wraps(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, generation uint64, query *sidecar.GkmWrapsQuery) (*protocol.GkmWrapsReply, error) {
	reply := &protocol.GkmWrapsReply{}
	err := self.call("Wraps", func() error {
		store := self.store
		if query != nil && query.Want != nil {
			store.lateAsks = append(store.lateAsks, fmt.Sprintf("%s:%d", query.Recipient, generation))
		}
		paths := []string{}
		for path := range store.pathWraps {
			paths = append(paths, path)
		}
		slices.Sort(paths)
		for _, path := range paths {
			body, _, recipient, err := gkmFakeDeliveryBody(store.pathWraps[path])
			if err != nil || !bytes.Equal(body.GetGroupId(), groupId.Bytes()) || body.GetGeneration() != generation {
				continue
			}
			if query != nil && query.Recipient != "" && query.Recipient != recipient {
				continue
			}
			signed := &bridge.Signed{}
			if err := proto.Unmarshal(store.pathWraps[path], signed); err == nil {
				reply.Wraps = append(reply.Wraps, signed)
			}
		}
		return nil
	})
	return reply, err
}

func (self *gkmFakeApi) UploadWraps(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, generation uint64, commitment []byte, batch *protocol.GkmWrapBatch) (*protocol.GkmWrapBatchReply, error) {
	reply := &protocol.GkmWrapBatchReply{}
	err := self.call("UploadWraps", func() error {
		store := self.store
		for _, deliveryBytes := range batch.GetDeliveries() {
			body, wrapType, _, err := gkmFakeDeliveryBody(deliveryBytes)
			if err != nil {
				reply.Results = append(reply.Results, &protocol.GkmWrapResult{Status: http.StatusBadRequest})
				continue
			}
			path, err := sidecar.GkmWrapPath(groupId, generation, commitment, wrapType, body.GetRecipient(), body.GetRecipientKeySha256())
			if err != nil || body.GetGeneration() != generation || !bytes.Equal(body.GetCommitment(), commitment) {
				reply.Results = append(reply.Results, &protocol.GkmWrapResult{Status: http.StatusBadRequest})
				continue
			}
			if body.GetDeliveryKind() == uint32(sidecar.GkmDeliveryLate) && generation != uint64(len(store.groupGenerations[groupId])) {
				// a late delivery only of the newest generation
				reply.Results = append(reply.Results, &protocol.GkmWrapResult{Status: http.StatusConflict})
				continue
			}
			if held, ok := store.pathWraps[path]; ok {
				if bytes.Equal(held, deliveryBytes) {
					reply.Results = append(reply.Results, &protocol.GkmWrapResult{Status: http.StatusCreated})
				} else {
					reply.Results = append(reply.Results, &protocol.GkmWrapResult{Status: http.StatusPreconditionFailed, Winner: held})
				}
				continue
			}
			store.pathWraps[path] = bytes.Clone(deliveryBytes)
			reply.Results = append(reply.Results, &protocol.GkmWrapResult{Status: http.StatusCreated})
		}
		return nil
	})
	return reply, err
}

func (self *gkmFakeApi) UploadRecoveryWraps(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, generation uint64, commitment []byte, batch *protocol.GkmRecoveryWrapBatch) (*protocol.GkmWrapBatchReply, error) {
	reply := &protocol.GkmWrapBatchReply{}
	err := self.call("UploadRecoveryWraps", func() error {
		store := self.store
		for _, item := range batch.GetItems() {
			path := fmt.Sprintf("gkm/recovery/%s/%s/%020d/%s/%s", hex.EncodeToString(item.GetMemberId()), hex.EncodeToString(groupId.Bytes()),
				generation, hex.EncodeToString(commitment[:8]), hex.EncodeToString(item.GetBindingPrefix()))
			if held, ok := store.pathRecoveryWraps[path]; ok && !bytes.Equal(held, item.GetCiphertext()) {
				reply.Results = append(reply.Results, &protocol.GkmWrapResult{Status: http.StatusPreconditionFailed, Winner: held})
				continue
			}
			store.pathRecoveryWraps[path] = bytes.Clone(item.GetCiphertext())
			reply.Results = append(reply.Results, &protocol.GkmWrapResult{Status: http.StatusCreated})
		}
		return nil
	})
	return reply, err
}

func (self *gkmFakeApi) ReaderKey(ctx context.Context, sidecarId sidecar.Id) (*bridge.Signed, error) {
	var readerKey *bridge.Signed
	err := self.call("ReaderKey", func() error {
		held, ok := self.store.readerKeys[sidecarId]
		if !ok {
			return gkmFakeRefusal(http.StatusNotFound, nil)
		}
		readerKey = held
		return nil
	})
	return readerKey, err
}

func (self *gkmFakeApi) ReaderKeys(ctx context.Context, sidecarIds []sidecar.Id) ([]*bridge.Signed, error) {
	readerKeys := []*bridge.Signed{}
	err := self.call("ReaderKeys", func() error {
		for _, sidecarId := range sidecarIds {
			if held, ok := self.store.readerKeys[sidecarId]; ok {
				readerKeys = append(readerKeys, held)
			} else {
				readerKeys = append(readerKeys, &bridge.Signed{})
			}
		}
		return nil
	})
	return readerKeys, err
}

func (self *gkmFakeApi) ClaimKeyPackage(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, target sidecar.Id) (*protocol.GkmKeyPackageClaimReply, error) {
	reply := &protocol.GkmKeyPackageClaimReply{}
	err := self.call("ClaimKeyPackage", func() error {
		store := self.store
		keyPackages := store.keyPackages[target]
		// a one-time KeyPackage first, then the last-resort one, which is never deleted
		index := slices.IndexFunc(keyPackages, func(keyPackage *sidecar.MlsKeyPackage) bool { return !keyPackage.LastResort })
		if index < 0 {
			index = slices.IndexFunc(keyPackages, func(keyPackage *sidecar.MlsKeyPackage) bool { return keyPackage.LastResort })
		}
		if index < 0 {
			return gkmFakeRefusal(http.StatusNotFound, nil)
		}
		keyPackage := keyPackages[index]
		reply.KeyPackageRef = keyPackage.Ref
		reply.KeyPackage = keyPackage.Encoded
		if !keyPackage.LastResort {
			store.keyPackages[target] = slices.Delete(slices.Clone(keyPackages), index, index+1)
		}
		return nil
	})
	return reply, err
}

func (self *gkmFakeApi) UploadWelcome(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, epoch uint64, request *protocol.GkmWelcomeRequest) error {
	return self.call("UploadWelcome", func() error {
		store := self.store
		epochs := store.groupEpochs[groupId]
		if uint64(len(epochs)) <= epoch {
			return gkmFakeRefusal(http.StatusNotFound, nil)
		}
		if !bytes.Equal(epochs[epoch].GetUploader(), self.sidecarId.Bytes()) {
			return gkmFakeRefusal(http.StatusForbidden, nil)
		}
		key := fmt.Sprintf("%s/%d", hex.EncodeToString(groupId.Bytes()), epoch)
		if held, ok := store.groupWelcomes[key]; ok && !bytes.Equal(held, request.GetWelcome()) {
			return gkmFakeRefusal(http.StatusConflict, nil)
		}
		store.groupWelcomes[key] = bytes.Clone(request.GetWelcome())
		for _, recipient := range request.GetRecipients() {
			recipientId := sidecar.Id(recipient.GetSidecarId())
			pointer := &protocol.GkmWelcomePointer{GroupId: groupId.Bytes(), Epoch: epoch, KeyPackageRef: recipient.GetKeyPackageRef()}
			// one pointer per (recipient, group, epoch), whatever KeyPackage the Add used
			if slices.ContainsFunc(store.welcomeEntries[recipientId], func(entry *protocol.GkmWelcomeEntry) bool {
				return bytes.Equal(entry.GetPointer().GetGroupId(), groupId.Bytes()) && entry.GetPointer().GetEpoch() == epoch
			}) {
				continue
			}
			store.welcomeEntries[recipientId] = append(store.welcomeEntries[recipientId], &protocol.GkmWelcomeEntry{
				KeyPackageRef: recipient.GetKeyPackageRef(), Pointer: pointer, Welcome: bytes.Clone(request.GetWelcome()),
			})
		}
		return nil
	})
}

func (self *gkmFakeApi) Welcomes(ctx context.Context) ([]*protocol.GkmWelcomeEntry, error) {
	entries := []*protocol.GkmWelcomeEntry{}
	err := self.call("Welcomes", func() error {
		entries = slices.Clone(self.store.welcomeEntries[self.sidecarId])
		return nil
	})
	return entries, err
}
