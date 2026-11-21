//go:build !ios_extension

// The local write-ahead file of one multi-log or spooled capture. Its commit is the durable decision to install every
// signed destination. Each destination keeps its original entry, key and salt. A restart recognizes a destination
// by its journal and finishes the rest before any further seal, so the team's projection always names its original
// vault entry and the vault's copy opens the original team entry. No server sees this file.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

const recordCaptureFile = "capture"
const recordCaptureVersion = 1

// The first value in the capture file. Exactly EntryCount sealed entries follow in destination order.
type recordCaptureHeader struct {
	Version    int            `json:"version"`
	EntryCount int            `json:"entry_count"`
	SpoolId    *SpoolRecordId `json:"spool_id,omitempty"`
}

// A private view of the affected heads until the entire capture commits.
type recordCapture struct {
	chain    *RecordChainStore
	file     SidecarStoreWriter
	encoder  *json.Encoder
	logHeads map[Id]RecordChainHead
}

// Starts an atomic capture in the record's sealed store. Closing without a commit abandons all destinations.
func (self *recordWriter) beginCapture(captureId []byte, count int) (*recordCapture, error) {
	header := &recordCaptureHeader{Version: recordCaptureVersion, EntryCount: count}
	if id, ok := decodeSpoolRecordId(captureId); ok {
		header.SpoolId = &id
	}
	file, err := self.store.Create(recordCaptureFile)
	if err != nil {
		return nil, err
	}
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(header); err != nil {
		file.Close()
		return nil, err
	}
	return &recordCapture{chain: self.chain, file: file, encoder: encoder, logHeads: map[Id]RecordChainHead{}}, nil
}

// Takes the next sequence in this capture and writes the signed destination to the uncommitted file.
func (self *recordCapture) stage(logId Id, build func(uint64, [sha256.Size]byte) (*RecordSealedEntry, error)) (*RecordSealedEntry, error) {
	head, held := self.logHeads[logId]
	if !held {
		var err error
		head, err = self.chain.Head(logId)
		if err != nil {
			return nil, err
		}
	}
	if head.Seq == ^uint64(0) {
		return nil, fmt.Errorf("%w: the chain has no sequence left", ErrRecordSealInvalid)
	}
	entry, err := build(head.Seq+1, head.Leaf)
	if err != nil {
		return nil, err
	}
	if err := self.encoder.Encode(entry); err != nil {
		entry.Clear()
		return nil, err
	}
	self.logHeads[logId] = RecordChainHead{Seq: entry.Seq, Leaf: entry.Leaf}
	return entry, nil
}

// Finishes a committed capture with the writer's sealLock held. The capture disappears only after every destination
// and its optional spool cursor are durable. The pump can then send and compact the individual chain journals.
func (self *recordWriter) finishCaptureWithLock() error {
	if !self.capturePending {
		return nil
	}
	reader, err := self.store.Open(recordCaptureFile)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		self.capturePending = false
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		if reader != nil {
			reader.Close()
		}
	}()
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var capture recordCaptureHeader
	if err := decoder.Decode(&capture); err != nil || capture.Version != recordCaptureVersion || capture.EntryCount <= 0 {
		return fmt.Errorf("%w: capture header", ErrRecordChainCorrupt)
	}
	entries := []*RecordSealedEntry{}
	defer func() {
		for _, entry := range entries {
			entry.Clear()
		}
	}()
	for range capture.EntryCount {
		entry := &RecordSealedEntry{}
		if err := decoder.Decode(entry); err != nil {
			return fmt.Errorf("%w: capture destination: %v", ErrRecordChainCorrupt, err)
		}
		entries = append(entries, entry)
		if err := self.installCaptureEntry(entry); err != nil {
			return err
		}
	}
	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing capture data", ErrRecordChainCorrupt)
	}
	if err := reader.Close(); err != nil {
		return err
	}
	reader = nil
	if capture.SpoolId != nil {
		if err := self.writeMark(*capture.SpoolId); err != nil {
			return err
		}
	}
	if err := self.store.Remove(recordCaptureFile); err != nil {
		return err
	}
	self.capturePending = false
	loaded := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.loaded
	}()
	if loaded {
		for _, entry := range entries {
			header, _ := entry.Header() // installCaptureEntry checked it
			self.enqueue(&recordRoute{logId: entry.LogId}, entry, header.Kind())
		}
		// The queues own the keys now. On first load they instead take the entries from the journals.
		entries = nil
	}
	return nil
}

// Checks the stored destination against its chain and installs its exact signed bytes if recovery has yet to reach it.
func (self *recordWriter) installCaptureEntry(entry *RecordSealedEntry) error {
	header, err := entry.Header()
	if err != nil || entry.Seq == 0 || header.LeafHash() != entry.Leaf || header.Header.GetSeq() != entry.Seq ||
		!bytes.Equal(header.Header.GetWriterSidecarId(), self.sidecarId[:]) || !bytes.Equal(header.Header.GetLogId(), entry.LogId[:]) ||
		!bytes.Equal(header.Header.GetEntryId(), entry.EntryId[:]) || len(entry.Key) != RecordKeyByteCount || len(entry.Salt) != RecordSaltByteCount {
		return fmt.Errorf("%w: invalid capture destination", ErrRecordChainCorrupt)
	}
	testHookSecret("record_entry_key", entry.Key)
	testHookSecret("record_entry_salt", entry.Salt)
	head, err := self.chain.Head(entry.LogId)
	if err != nil {
		return err
	}
	if entry.Seq <= head.Seq {
		content, err := self.chain.readFile(recordJournalName(entry.LogId, entry.Seq))
		if err != nil {
			return err
		}
		defer clear(content)
		stored, err := self.chain.decodeJournal(entry.LogId, entry.Seq, content)
		if err != nil {
			return err
		}
		defer clear(stored.Key)
		defer clear(stored.Salt)
		if !bytes.Equal(stored.Signed, entry.Signed) || !bytes.Equal(stored.SealedBody, entry.SealedBody) ||
			!bytes.Equal(stored.Key, entry.Key) || !bytes.Equal(stored.Salt, entry.Salt) || stored.EntryVersion != recordJournalEntryVersion(entry.Version) {
			return fmt.Errorf("%w: capture conflicts with journal at %s/%d", ErrRecordChainCorrupt, entry.LogId, entry.Seq)
		}
		return nil
	}
	_, err = self.chain.append(entry.LogId, func(seq uint64, prev [sha256.Size]byte) (*RecordSealedEntry, error) {
		if entry.Seq != seq || !bytes.Equal(header.Header.GetPrevSha256(), prev[:]) {
			return nil, fmt.Errorf("%w: capture does not extend %s at %d", ErrRecordChainCorrupt, entry.LogId, seq)
		}
		return entry, nil
	})
	return err
}

// Seals a draft's entries by its routes (record_team.go), in order: the vault's, T's, T's copy in the vault, the
// directory's. A capture with multiple destinations or a spool cursor commits through one write-ahead file.
func (self *recordWriter) sealRoutes(draft *recordSpoolDraft, routes *recordRoutes, captureId []byte) ([]*RecordEntryRef, error) {
	kind := RecordKind(draft.Kind)
	remaining := 0
	if routes.vault != nil && routes.vaultEntry {
		remaining += 1
	}
	if routes.team != nil {
		remaining += 1 + len(routes.ledgers)
		if routes.copy && routes.vault != nil {
			remaining += 1
		}
	}
	if routes.directory != nil {
		remaining += 1
	}
	if remaining == 0 {
		return nil, fmt.Errorf("%w: %s routes nowhere", ErrRecordRouteTeamOnly, kind)
	}
	self.sealLock.Lock()
	defer self.sealLock.Unlock()
	if err := self.finishCaptureWithLock(); err != nil {
		return nil, err
	}
	if err := self.readyToSeal(routes); err != nil {
		return nil, err
	}
	env := &RecordSealEnv{Chain: self.chain, Sign: self.sign, Random: self.random}
	var capture *recordCapture
	if remaining > 1 || captureId != nil {
		var err error
		capture, err = self.beginCapture(captureId, remaining)
		if err != nil {
			return nil, err
		}
		defer capture.file.Close()
		env.stage = capture.stage
	}
	// T's body first, so a draft that cannot project seals nothing at all
	var teamBody []byte
	if routes.team != nil {
		projected, err := recordTeamBodyBytes(kind, routes.teamBody, draft.Body, draft.Projection)
		if err != nil {
			return nil, err
		}
		teamBody = projected
	}
	refs := []*RecordEntryRef{}
	var vaultRef *RecordEntryRef
	if routes.vault != nil && routes.vaultEntry {
		sealed, err := self.sealOne(env, draft, routes.vault, kind, draft.Body, draft.contentRefs(), nil)
		if err != nil {
			return refs, err
		}
		vaultRef = sealed.ref
		refs = append(refs, sealed.ref)
	}
	if routes.team != nil {
		var content []*protocol.ContentRef
		if routes.teamBody == recordTeamBodyProjection && vaultRef != nil {
			// one ContentRef to the vault entry, whose salt stays in its slot row (RECORD.md section 5.1)
			content = []*protocol.ContentRef{{RepoId: vaultRef.LogId.Bytes(), ObjectId: vaultRef.EntryId.Bytes(), Commitment: bytes.Clone(vaultRef.Commitment[:])}}
		}
		sealed, err := self.sealOne(env, draft, routes.team, kind, teamBody, append(content, draft.contentRefs()...), nil)
		if err != nil {
			return refs, err
		}
		refs = append(refs, sealed.ref)
		if routes.copy && routes.vault != nil {
			// what the header's commitment opens with: T's body, or the AgentSignedBody holding it (version 2)
			copiedBody := teamBody
			if sealed.committed != nil {
				copiedBody = sealed.committed
			}
			copyBody, err := NewRecordCopyBody([]*RecordOpened{{SignedBytes: sealed.signed, Salt: sealed.salt, Body: copiedBody, Version: sealed.version}})
			clear(sealed.salt)
			if err != nil {
				return refs, err
			}
			copyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(copyBody)
			if err != nil {
				return refs, err
			}
			// an accounting entry of the run that filed T's, about no action of its own
			copyDraft := *draft
			copyDraft.Kind = uint32(RecordKindCopy)
			copyDraft.Source = uint32(RecordSourceObserved)
			copyDraft.ActionId = nil
			copyDraft.GrantId = nil
			copied, err := self.sealOne(env, &copyDraft, routes.vault, RecordKindCopy, copyBytes, nil, nil)
			clear(copyBytes)
			if err != nil {
				return refs, err
			}
			refs = append(refs, copied.ref)
		}
		clear(sealed.salt)
		// T's body again as each in-scope ledger's own entry: its own id, chain position, key and commitment
		for _, ledger := range routes.ledgers {
			copied, err := self.sealOne(env, draft, ledger, kind, teamBody, nil, nil)
			if err != nil {
				return refs, err
			}
			clear(copied.salt)
			refs = append(refs, copied.ref)
		}
	}
	if routes.directory != nil {
		sealed, err := self.sealOne(env, draft, routes.directory, kind, draft.Body, nil, nil)
		if err != nil {
			return refs, err
		}
		refs = append(refs, sealed.ref)
	}
	if capture != nil {
		testHookBarrier("record.capture.commit.before", recordChainIdText(self.sidecarId))
		if err := capture.file.Commit(); err != nil {
			return nil, err
		}
		self.capturePending = true
		testHookBarrier("record.capture.commit.after", recordChainIdText(self.sidecarId))
		if err := self.finishCaptureWithLock(); err != nil {
			// The whole capture is durable. A later pump installs these exact entries.
			self.log.Warningf("[record]a committed capture still needs installation: %s", err)
			self.signal()
		}
	}
	return refs, nil
}
