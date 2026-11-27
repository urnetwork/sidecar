//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The kept response across restarts (DESIGN-COMPUTE §8.5's retries and crash paragraphs; D-GW-5, IC-19, R2-04;
// GW-M12-05): each call's answer is kept from its first byte in the network's sealed store, whose files are sealed
// under XChaCha20-Poly1305 with a key the network's keychain derives (state_seal.go), so a restart keeps it.
//
//	write      a call's file is written when it is recorded and sent, again at each response item the call journals
//	           (IC-19's points), as a caller's answer arrives whole or is abandoned, and at its end with its terminal,
//	           which makes it whole; each write replaces the file whole, never a part. The answer's frames go only while
//	           they fit KeptResponseByteCount, the rest of the file staying, so a crash still finds the call
//	life       a whole call's file is dropped KeptResponseLife after its end, at the drop its table arms then, or at the
//	           first read past it after a restart
//	restart    the table reads its network's files at its first call after a restart: a call journaled whole is whole,
//	           and its retry, by the call table's rules, is answered from its kept answer; any other call is cut by the
//	           crash: the recorder's Cut writes its model_call, its output as far as it was journaled, the rest a gap,
//	           and its kept part is never replayed, so its retry is a new call, charged and recorded as a second call on
//	           the same context node. Whole or cut is the file's word, written in the journal's order, never a time's
//	planned    a planned restart drains first (GatewayFronts.Drain), so its calls end whole
//
// Nothing here is read back to answer a call beyond the call table's rules (D-GW-2), and nothing reaches a server.
// Safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
)

// The kept files' place and format: identifiers.
const (
	gatewayKeptPrefix      = "kept/"
	gatewayKeptFileVersion = 1
)

// What keeps a network's calls across restarts: its sealed store's gateway directory. *Sidecar is one.
type GatewayKeptNetwork interface {
	GatewayKeptStore() (SidecarStore, error)
}

// See GatewayKeptNetwork: the gateway's sealed directory, beside its grants (gateway_grant.go).
func (self *Sidecar) GatewayKeptStore() (SidecarStore, error) {
	return self.LocalStore().Directory(gatewayGrantDirectoryName, gatewayGrantClass)
}

// One call's kept file.
type gatewayKeptFile struct {
	Version        int    `json:"version"`
	Handle         string `json:"handle,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	BodySha256     []byte `json:"body_sha256"`
	BeganMillis    int64  `json:"began_millis"`
	EndedMillis    int64  `json:"ended_millis,omitempty"`
	// the terminal is in the answer: the call was journaled whole
	Whole      bool `json:"whole,omitempty"`
	Delivered  bool `json:"delivered,omitempty"`
	Abandoned  bool `json:"abandoned,omitempty"`
	Unjoinable bool `json:"unjoinable,omitempty"`
	// what Cut records of it after a crash, its node ids those journaled
	Cut *GatewayRecordCut `json:"cut,omitempty"`
	// nil once the answer passed KeptResponseByteCount
	Answer *gatewayAnswerSnapshot `json:"answer,omitempty"`
}

// The file as the entry stands, pending frames about to follow its answer: its answer while it fits, and whole once
// the call ended, its terminal among the frames.
func (self *gatewayCallEntry) keptFile(pending [][]byte) (*gatewayKeptFile, int) {
	snapshot := self.answer.snapshot()
	snapshot.Frames = append(snapshot.Frames, pending...)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	file := &gatewayKeptFile{
		Version:        gatewayKeptFileVersion,
		Handle:         self.handle,
		IdempotencyKey: self.idempotencyKey,
		BodySha256:     slices.Clone(self.bodySha256[:]),
		BeganMillis:    self.began.UnixMilli(),
		Delivered:      self.delivered,
		Abandoned:      self.abandoned,
		Unjoinable:     self.unjoinable,
	}
	if !self.ended.IsZero() {
		file.EndedMillis = self.ended.UnixMilli()
		file.Whole = true
		snapshot.Ended = true
	}
	if self.cut != nil {
		cut := *self.cut
		cut.NodeIds = slices.Clone(self.nodeIds)
		file.Cut = &cut
	}
	if !self.unjoinable {
		file.Answer = snapshot
	}
	return file, len(self.nodeIds)
}

// Writes the entry's file whole, pending frames after its answer, under writeLock; a table with no store, or fronts a
// crash stopped, writes nothing. A write that fails is logged and the call goes on: its retry may then be a new call,
// never a wrong one.
func (self *gatewayCallEntry) write(pending [][]byte) {
	table := self.table
	if table.store == nil || table.fronts.tables.stopped.Load() {
		return
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	testHookBarrier("gateway.kept.write.before", self.name)
	defer testHookBarrier("gateway.kept.write.after", self.name)
	file, items := self.keptFile(pending)
	err := func() error {
		store, err := table.store()
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(file)
		if err != nil {
			return err
		}
		writer, err := store.Create(self.name)
		if err != nil {
			return err
		}
		defer writer.Close()
		if _, err := writer.Write(encoded); err != nil {
			return err
		}
		return writer.Commit()
	}()
	if err != nil {
		table.fronts.log.Warningf("[gateway]a call's kept answer was not written: %s", err)
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.writtenItems = items
}

// Removes the entry's file and stops its drop.
func (self *gatewayCallEntry) remove() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.stopDrop != nil {
			self.stopDrop()
		}
	}()
	table := self.table
	if table.store == nil || table.fronts.tables.stopped.Load() {
		return
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	store, err := table.store()
	if err == nil {
		err = store.Remove(self.name)
	}
	if err != nil {
		table.fronts.log.Warningf("[gateway]a call's kept answer was not removed: %s", err)
	}
}

// Reads the network's kept files once, at the table's first use after a start (see the file header's restart row),
// and writes the Cut of each call a crash cut once a recorder is set, a file whose Cut is not written read again at the
// next use. A store that does not read now, a locked network say, is read again at the next call.
func (self *gatewayCallTable) load(ctx context.Context) {
	if self.store == nil {
		return
	}
	loaded := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.loaded
	}()
	if !loaded {
		self.loadOnce()
	}
	self.writeCuts(ctx)
}

// The pass over the files a start makes: whole calls within their life join the table, cut ones wait for their Cut.
func (self *gatewayCallTable) loadOnce() {
	store, err := self.store()
	if err != nil {
		return
	}
	listed, err := store.List(gatewayKeptPrefix)
	if err != nil {
		return
	}
	fronts := self.fronts
	now := fronts.clock.Now()
	life := fronts.settings.KeptResponseLife
	kept := []*gatewayCallEntry{}
	cutNames := []string{}
	for _, listing := range listed {
		name := listing.Name
		file, err := gatewayReadKept(store, name, fronts.settings)
		if err != nil {
			// a file that does not read keeps nothing: removed, its call's retry a new call
			store.Remove(name)
			continue
		}
		if !file.Whole {
			// cut by a crash: its model_call is written, and its part is never replayed
			if file.Cut == nil {
				store.Remove(name)
				continue
			}
			cutNames = append(cutNames, name)
			continue
		}
		ended := time.UnixMilli(file.EndedMillis)
		if life <= 0 || !now.Before(ended.Add(life)) || file.Answer == nil || file.Unjoinable || len(file.BodySha256) != 32 {
			store.Remove(name)
			continue
		}
		entry := &gatewayCallEntry{
			table:          self,
			name:           name,
			handle:         file.Handle,
			idempotencyKey: file.IdempotencyKey,
			bodySha256:     [32]byte(file.BodySha256),
			answer:         gatewayAnswerOf(file.Answer),
			cut:            file.Cut,
			began:          time.UnixMilli(file.BeganMillis),
			ended:          ended,
			delivered:      file.Delivered,
			abandoned:      file.Abandoned,
			writtenItems:   -1,
		}
		if file.Cut != nil {
			entry.nodeIds = slices.Clone(file.Cut.NodeIds)
			entry.writtenItems = len(entry.nodeIds)
		}
		entry.stopDrop = fronts.clock.AfterFunc(ended.Add(life).Sub(now), func() {
			self.drop(entry)
		})
		kept = append(kept, entry)
	}
	slices.SortFunc(kept, func(a *gatewayCallEntry, b *gatewayCallEntry) int { return a.began.Compare(b.began) })
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.loaded {
		return
	}
	self.loaded = true
	self.entries = append(kept, self.entries...)
	self.cutNames = cutNames
}

// Writes the Cut of each call a crash cut, once a recorder is set, and removes its file; one that fails waits for the
// next use.
func (self *gatewayCallTable) writeCuts(ctx context.Context) {
	fronts := self.fronts
	recorder := fronts.currentRecorder()
	if recorder == nil || fronts.tables.stopped.Load() {
		return
	}
	cutNames := func() []string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		cutNames := self.cutNames
		self.cutNames = nil
		return cutNames
	}()
	if len(cutNames) == 0 {
		return
	}
	store, err := self.store()
	if err != nil {
		self.stateLock.Lock()
		self.cutNames = append(self.cutNames, cutNames...)
		self.stateLock.Unlock()
		return
	}
	pending := []string{}
	for _, name := range cutNames {
		file, err := gatewayReadKept(store, name, fronts.settings)
		if err != nil || file.Cut == nil {
			store.Remove(name)
			continue
		}
		if err := recorder.Cut(ctx, file.Cut); err != nil {
			fronts.log.Warningf("[gateway]a cut call's record was not written, and is tried again: %s", err)
			pending = append(pending, name)
			continue
		}
		store.Remove(name)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.cutNames = append(self.cutNames, pending...)
}

// One kept file, held to its format and KeptFileByteCount.
func gatewayReadKept(store SidecarStore, name string, settings *GatewaySettings) (*gatewayKeptFile, error) {
	reader, err := store.Open(name)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	bound := int64(max(settings.KeptFileByteCount, 0))
	encoded, err := io.ReadAll(io.LimitReader(reader, bound+1))
	if err != nil {
		return nil, err
	}
	if bound < int64(len(encoded)) {
		return nil, errors.New("a kept file past its bound")
	}
	file := &gatewayKeptFile{}
	if err := json.Unmarshal(encoded, file); err != nil || file.Version != gatewayKeptFileVersion {
		return nil, fmt.Errorf("a kept file that does not read")
	}
	return file, nil
}

// Reads every hosted network's kept files now, writing the Cut of each call a crash cut: the daemon's start, once its
// recorder is set (SetRecorder calls it). A network that does not read now is read at its first call.
func (self *GatewayFronts) Recover(ctx context.Context) {
	hosts := self.server.gatewayHosts()
	if hosts == nil {
		return
	}
	for _, hosted := range hosts.GatewayNetworks() {
		self.tableOf(ctx, &GatewayCaller{NetworkId: hosted.NetworkId, Network: hosted.Network})
	}
}
