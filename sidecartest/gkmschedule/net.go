package gkmschedule

// The world on a fault schedule's Net, which sidecartest/fault's fs_keys.go registers gkm's rows through (§22.8's
// rules, D-TEST-10): the Net's clock and fake host, and its engines' stores, the fakes' on T2 and server's on T3,
// so every one of gkm's store requests passes the Net's fault queue and its blob recorder, and every barrier the
// client and the engine name reaches the Net's driver, whose seeds are the explorer's.
//
// §22.8's unknown rule loses one write's answer a run (EveryWrite, ApplyThenDrop at the store): gkm answers its
// caller 503, and the flow either resolves the unknown outcome by rereading, as it is built to, or answers the
// error, which the daemon's next pass, a hint or upkeep, runs again. Again is that next pass: a flow that answers
// what a lost answer leaves runs once more, at most three times, and any other answer fails the schedule. What a
// schedule checks after it, one generation, each holder's convergence, the removed device's reach, is what the
// rule holds the system to.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// How many times Again runs a flow.
const fsKeysAgainCount = 3

// A world of one repo of kind on net: see the file header. A wait for a hint or a reconciler's pass tells the Net's
// barrier driver it blocks, so the actor waiting does not count as stalled.
func NewFsKeysWorldOnNet(t FsKeysT, kind protocol.RepoKind, net *sidecartest.Net) *FsKeysWorld {
	engineHost := net.Host()
	world := NewFsKeysWorldOn(t, kind, net.Clock(), net.Fakes(), func(serviceHost *sidecar.ServiceHost) {
		serviceHost.Blobs = engineHost.Blobs
		serviceHost.Redis = engineHost.Redis
	})
	world.blocking = net.Barriers().Blocking
	return world
}

// Runs wait, telling the Net's barrier driver it blocks where the world runs on one.
func (self *FsKeysWorld) block(wait func()) {
	if self.blocking == nil {
		wait()
		return
	}
	self.blocking(wait)
}

// Whether err is what a lost answer leaves a flow with: gkm's 503 or 429, or the transport's or the store's lost
// answer.
func FsKeysTransient(err error) bool {
	if errors.Is(err, errFsKeysTransport) || errors.Is(err, errFsKeysStore) {
		return true
	}
	if gkmError, ok := sidecar.GkmErrorOf(err); ok {
		return gkmError.RefusesNothing()
	}
	return false
}

// Runs flow, again while it answers what a lost answer leaves, at most three times: the daemon's next pass. Any
// other error, or the third, fails the schedule as label.
func (self *FsKeysWorld) Again(label string, flow func() error) {
	self.t.Helper()
	var err error
	for attempt := 0; attempt < fsKeysAgainCount; attempt += 1 {
		if err = flow(); err == nil || !FsKeysTransient(err) {
			break
		}
	}
	if err != nil {
		self.t.Fatalf("%s: %v", label, err)
	}
}

// FI-4's stand-in until TEST-M2-05's oracle binds it: one ladder per group. Each group the world formed holds gen/1
// to gen/<n> with none missing, each verifying under its signer's admitted identity key, gen/1 with no parent and
// every later one naming its predecessor's commitment, whatever writes were lost on the way. Reads the store
// directly under ctx, an oracle's inspecting one, so a schedule's invariant may call it after any step; it fails
// nothing itself.
func (self *FsKeysWorld) CheckLadders(ctx context.Context) error {
	cluster, err := self.serviceHost().Blobs.FirstCluster()
	if err != nil {
		return err
	}
	tip := self.Log.Tip()
	if tip == nil {
		return nil
	}
	for _, groupId := range []sidecar.Id{self.GroupId, self.ConfigGroupId} {
		if groupId == (sidecar.Id{}) {
			continue
		}
		infos, _, err := cluster.List(ctx, gkmservice.GkmGenerationPrefix(groupId), "", 1000)
		if err != nil {
			return err
		}
		var previous []byte
		for index, info := range infos {
			generation := uint64(index + 1)
			if info.Key != gkmservice.GkmGenerationKey(groupId, generation) {
				return fmt.Errorf("group %s: gen/ holds %s where gen/%d belongs", groupId, info.Key, generation)
			}
			object, err := cluster.Get(ctx, info.Key)
			if err != nil {
				return err
			}
			body, err := io.ReadAll(object.Body)
			object.Body.Close()
			if err != nil {
				return err
			}
			parsed, err := sidecar.ParseGenRotate(body, groupId, generation, sidecar.GkmIdentityKeys(tip))
			if err != nil {
				return fmt.Errorf("group %s: gen/%d: %w", groupId, generation, err)
			}
			if !bytes.Equal(parsed.Rotate.GetParentCommitment(), previous) {
				return fmt.Errorf("group %s: gen/%d names another parent than gen/%d's commitment", groupId, generation, generation-1)
			}
			previous = parsed.Rotate.GetCommitment()
		}
	}
	return nil
}

// Creates key with body, If-None-Match, as evs's placement does, retrying a write whose answer was lost: an object
// that holds these bytes already is this write's.
func (self *FsKeysWorld) putOnce(cluster sidecar.BlobCluster, key string, body []byte) error {
	for attempt := 0; ; attempt += 1 {
		_, err := cluster.PutIfNoneMatch(self.Ctx, key, body, nil)
		if err == nil {
			return nil
		}
		if held, readErr := self.readObject(cluster, key); readErr == nil && bytes.Equal(held, body) {
			return nil
		}
		if fsKeysAgainCount <= attempt+1 {
			return err
		}
	}
}

// One object's bytes.
func (self *FsKeysWorld) readObject(cluster sidecar.BlobCluster, key string) ([]byte, error) {
	object, err := cluster.Get(self.Ctx, key)
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	return io.ReadAll(object.Body)
}

// Replaces or creates key with body, as evs's routes move repo/, retrying a write whose answer was lost: an object
// that holds these bytes already is this write's.
func (self *FsKeysWorld) putOver(cluster sidecar.BlobCluster, key string, body []byte) error {
	for attempt := 0; ; attempt += 1 {
		info, err := cluster.Head(self.Ctx, key)
		switch {
		case errors.Is(err, sidecar.ErrBlobNotFound):
			_, err = cluster.PutIfNoneMatch(self.Ctx, key, body, nil)
		case err == nil:
			_, err = cluster.PutIfMatch(self.Ctx, key, info.Etag, body, nil)
		}
		if err == nil {
			return nil
		}
		if held, readErr := self.readObject(cluster, key); readErr == nil && bytes.Equal(held, body) {
			return nil
		}
		if fsKeysAgainCount <= attempt+1 {
			return err
		}
	}
}

// Fails the schedule at the end of the step it runs in, as Errorf does a test.
func (self *FsKeysWorld) Fail(format string, args ...any) {
	self.t.Errorf(format, args...)
}
