// A store the oracle's view must read whole, written once in a non-test file so T2's test here and server's T3
// test in sidecart3 write the same objects and check the same decode (TEST-M2-01; plan-TEST-small-readings reading
// 1): one repo placed, a head, a log page, a slot, a batch holding one of its records, and its group's gen/1, each
// through the Net's host as an engine writes it. Run inside an actor's step, the RK_g it makes is that actor's.

package fault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What the fixture wrote, for its check.
type StoreViewFixture struct {
	RepoId    sidecar.Id
	GroupId   sidecar.Id
	RefId     sidecar.Id
	SlotId    sidecar.Id
	PushId    sidecar.Id
	ClusterId string
	BatchKey  string
	HeadKey   string
	RepoKey   *sidecar.EvsRepoKey
}

// A fresh fixture's ids.
func NewStoreViewFixture() *StoreViewFixture {
	return &StoreViewFixture{RepoId: sidecar.NewId(), GroupId: sidecar.NewId(), RefId: sidecar.NewId(), SlotId: sidecar.NewId(), PushId: sidecar.NewId()}
}

// A synthetic signer for a GenRotate: the view decodes and checks no signature.
func storeViewFixtureSign(sidecarId sidecar.Id, identityKey ed25519.PrivateKey) sidecar.GkmSignFunction {
	return func(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body:      body,
			SignerId:  sidecarId[:],
			Signature: ed25519.Sign(identityKey, bridge.SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		}, nil
	}
}

// gen/<g>'s bytes for rotate, signed by a fresh synthetic key.
func StoreViewFixtureGeneration(rotate *protocol.GenRotate) ([]byte, error) {
	_, seed, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	signed, err := sidecar.SignGenRotate(rotate, storeViewFixtureSign(sidecar.NewId(), seed))
	if err != nil {
		return nil, err
	}
	return proto.Marshal(signed)
}

// Writes the fixture through net's host, on its first metadata cluster.
func (self *StoreViewFixture) Write(ctx context.Context, net *Net) error {
	first, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		return err
	}
	self.ClusterId = first.ClusterId()
	put := func(key string, body []byte) error {
		_, err := first.PutIfNoneMatch(ctx, key, body, nil)
		return err
	}
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: self.ClusterId, CreatorSidecarId: sidecar.NewId()}).Marshal()
	if err != nil {
		return err
	}
	if err := put(sidecar.EvsPlaceKey(self.RepoId), placeBytes); err != nil {
		return err
	}

	holders := sha256.Sum256([]byte("the holders"))
	repoKey, rotate, err := sidecar.NewGkmFirstGeneration(self.RepoId, self.GroupId, &sidecar.GkmGenerationArgs{
		Cause:         sidecar.GkmCauseRequest,
		Auth:          &bridge.AuthPin{Version: 1, Chain: bytes.Repeat([]byte{7}, 32)},
		Time:          net.Clock().Now(),
		HoldersSha256: holders[:],
	})
	if err != nil {
		return err
	}
	self.RepoKey = repoKey
	generationBytes, err := StoreViewFixtureGeneration(rotate)
	if err != nil {
		return err
	}
	if err := put(sidecar.GkmGenerationPath(self.GroupId, 1), generationBytes); err != nil {
		return err
	}

	self.HeadKey = "head/" + sidecar.EvsKeyId(self.RepoId) + "/" + sidecar.EvsKeyId(self.RefId)
	headBytes, err := proto.Marshal(&protocol.EvsHead{Version: 3, Chain: bytes.Repeat([]byte{3}, 32), PushId: self.PushId[:]})
	if err != nil {
		return err
	}
	if err := put(self.HeadKey, headBytes); err != nil {
		return err
	}
	pageBytes, err := proto.Marshal(&protocol.EvsLogPage{Page: 0, FirstChain: bytes.Repeat([]byte{0}, 32)})
	if err != nil {
		return err
	}
	if err := put("log/"+sidecar.EvsKeyId(self.RepoId)+"/"+sidecar.EvsKeyId(self.RefId)+"/"+storeKeyNumber(0), pageBytes); err != nil {
		return err
	}

	fekKey, err := sidecar.NewEvsFekKey(repoKey)
	if err != nil {
		return err
	}
	wrapped, err := sidecar.EvsWrapObjectKey(fekKey, sidecar.NewEvsObjectKey())
	if err != nil {
		return err
	}
	slotBytes, err := sidecar.EvsEncodeSlotObject(&protocol.EvsSlotObject{Keys: []*protocol.EvsSlotKey{{KeyIndex: 0, Generation: 1, Wrapped: wrapped}}})
	if err != nil {
		return err
	}
	if err := put("slot/"+sidecar.EvsKeyId(self.RepoId)+"/"+sidecar.EvsKeyId(self.SlotId), slotBytes); err != nil {
		return err
	}

	// §11.8's batch key: pb/<yyyymmddhh>/<mm>/<instance>-<seq>, the UTC hour and minute it opened
	minute := uint32(net.Clock().Now().Unix() / 60)
	instance, seq := uint32(0x0a0b0c0d), uint32(1)
	writer := sidecar.NewEvsBatchWriter(instance, minute, seq, net.Clock().Now().UnixMilli())
	if _, err := writer.Add(&sidecar.EvsBatchRecord{
		Type:            protocol.EvsBatchRecordType_EVS_BATCH_PUSH,
		RepoId:          self.RepoId,
		RefId:           self.RefId,
		PushId:          self.PushId,
		SignerSidecarId: sidecar.NewId(),
		TimeMs:          net.Clock().Now().UnixMilli(),
		Body:            []byte("a push's items"),
	}); err != nil {
		return err
	}
	batchBytes, err := writer.Bytes()
	if err != nil {
		return err
	}
	at := time.Unix(int64(minute)*60, 0).UTC()
	self.BatchKey = "pb/" + at.Format("2006010215") + "/" + at.Format("04") + "/" + fmt.Sprintf("%08x-%08x", instance, seq)
	return put(self.BatchKey, batchBytes)
}

// What view must read of the fixture, on whichever tier wrote it: every family decoded at the cluster place/
// names, and nothing where nothing was written.
func (self *StoreViewFixture) Check(ctx context.Context, view *StoreView) error {
	findings := []error{}
	fail := func(format string, arguments ...any) {
		findings = append(findings, fmt.Errorf(format, arguments...))
	}
	if clusterId, err := view.RepoClusterId(ctx, self.RepoId); err != nil || clusterId != self.ClusterId {
		fail("the repo's cluster: %q, %v", clusterId, err)
	}
	heads, err := view.Heads(ctx, self.RepoId)
	if err != nil || len(heads) != 1 || heads[0].Head.GetVersion() != 3 || !bytes.Equal(heads[0].RefId, self.RefId[:]) || !bytes.Equal(heads[0].Head.GetPushId(), self.PushId[:]) || heads[0].Etag == "" {
		fail("heads %v, %v", heads, err)
	}
	pages, err := view.Log(ctx, self.RepoId, self.RefId[:])
	if err != nil || len(pages) != 1 || pages[0].GetPage() != 0 {
		fail("log %v, %v", pages, err)
	}
	slot, err := view.Slot(ctx, self.RepoId, self.SlotId)
	if err != nil || len(slot.GetKeys()) != 1 || slot.GetKeys()[0].GetGeneration() != 1 {
		fail("slot %v, %v", slot, err)
	}
	batch, err := view.Batch(ctx, self.ClusterId, self.BatchKey)
	if err != nil || batch == nil || len(batch.Records) != 1 || batch.Records[0].RepoId != self.RepoId || batch.Records[0].PushId != self.PushId || string(batch.Records[0].Body) != "a push's items" {
		fail("batch %v, %v", batch, err)
	}
	batches, err := view.Batches(ctx, self.ClusterId)
	if err != nil || batches[self.BatchKey] == nil {
		fail("batches %v, %v", batches, err)
	}
	generations, err := view.Generations(ctx, self.GroupId)
	if err != nil || len(generations) != 1 || !bytes.Equal(generations[0].Rotate.GetCommitment(), self.RepoKey.Commitment()) || !bytes.Equal(generations[0].Rotate.GetRepoId(), self.RepoId[:]) {
		fail("generations %v, %v", generations, err)
	}
	if missing, err := view.Slot(ctx, self.RepoId, sidecar.NewId()); err != nil || missing != nil {
		fail("a slot nobody wrote: %v, %v", missing, err)
	}
	authorizationLog, err := view.AuthorizationLog(ctx, sidecar.NewId())
	if err != nil || authorizationLog.SignedGenesis != nil || len(authorizationLog.Entries) != 0 {
		fail("a network with no log: %v, %v", authorizationLog, err)
	}
	return errors.Join(findings...)
}
