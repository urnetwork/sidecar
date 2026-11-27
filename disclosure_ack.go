//go:build !ios_extension && !sidecar_http

// The person's acknowledgment of a disclosure (DESIGN-COMPUTE §2.8's acknowledgment and new-version rows; R-CCTX-25,
// D-CTRUST-3, IC-21, IC-22; CTRUST-M12-01):
//
//	key       compute.disclosures in the member's harness/config.json, {"<id>": <version>}, through CACL-M11-01's
//	          MemberHarnessConfig, per network (Q-CTRUST-1): sealed in the network's vault, each of the member's
//	          devices reads it, and nothing copies it across the person's networks. Unknown ids are kept, a value that
//	          is no version is ignored with a config_unreadable gap for the key, and versions only rise. A version an
//	          enclave or a tagged sidecar writes is one the store never takes (its writers rule, IC-23)
//	who       only the person: the act's origin SidecarActConfirmed, no harness process among the caller's ancestors,
//	          on an approval-capable device, for an id the newest verified policy carries and at the version the
//	          person was shown, else disclosure_changed with nothing written. Never through MCP (its guard refuses the
//	          vault's harness/), a Harness tool, a run, an RPC ui_response or a server; and no acknowledgment state
//	          leaves the device but sealed in the vault, so the broker checks none (Q-CTRUST-2)
//	locale    an acknowledgment is of a version, so it covers that version in every locale
//	await     Await returns once the key holds the version, made here or synced from another of the member's devices;
//	          only the key's value ends it: this device's own act and a change of the vault wake it to read again, and
//	          AwaitRecheckInterval reads it again for a change no listener announced. An answer to a request never
//	          ends it, so a ui_response cannot acknowledge for the person
//	marks     a version newer than the one the person acknowledged, or last opened, or first listed on this device,
//	          marks the id's lines "changed" until the person opens its text (Opened); a revision marks nothing. The
//	          marks are the sidecar's own, in its sealed store, since the design names no vault key for them
//
// The check that reads these is disclosure_check.go's. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"sync"
	"time"
)

// compute.disclosures' path in the member's harness config.
const (
	computeDisclosureAckKeyCompute     = "compute"
	computeDisclosureAckKeyDisclosures = "disclosures"
)

// The marks' directory and sealing class in the sidecar's own store, and their file.
const (
	computeDisclosureMarksDirectory = "disclosure"
	computeDisclosureMarksClass     = "disclosure"
	computeDisclosureMarksName      = "marks.json"
	computeDisclosureMarksFormat    = 1
)

var (
	// A disclosure is acknowledged only by the person's own act, after its whole text was shown, on an approval-capable
	// device. Nothing was recorded.
	ErrDisclosureAckRefused = errors.New("a disclosure is acknowledged only by the person's own act on an approval-capable device, never through MCP, a hook, a harness, a run or a server")
)

// The acknowledgments one read of the member's harness config holds.
type ComputeDisclosureAckRead struct {
	// Where the config's values came from: no_vault on a sidecar that reads no vault, a tagged or cloud one.
	Source MemberHarnessConfigSource
	// By id, the version acknowledged; an id outside §2.8's families is kept as read.
	Versions map[string]uint32
	// config_unreadable where the file or the key does not read, or a value in it is no version; else empty.
	Gap string
	// Why, naming no value.
	Reason string
	// The vault read, zero for none.
	VaultId Id
}

// The acknowledgments config holds (the file header's key row).
func readComputeDisclosureAcks(config *MemberHarnessConfigRead) *ComputeDisclosureAckRead {
	read := &ComputeDisclosureAckRead{Source: config.Source, Versions: map[string]uint32{}, VaultId: config.VaultId}
	if config.Source == MemberHarnessConfigSourceUnreadable {
		read.Gap, read.Reason = config.Gap, config.Reason
		return read
	}
	raw, held := config.Key(computeDisclosureAckKeyCompute, computeDisclosureAckKeyDisclosures)
	if !held {
		return read
	}
	object, err := parseHarnessJsonObject(raw, 0, len(raw))
	if err != nil {
		read.Gap, read.Reason = MemberHarnessConfigGapUnreadable, "compute.disclosures is no object"
		return read
	}
	ignored := 0
	for _, member := range object.members {
		value := raw[member.valueStart:member.valueEnd]
		var version uint32
		// an integer from 1 within uint32: a string, a fraction, an exponent or a negative is no version
		if bytes.ContainsAny(value, `".eE-`) || json.Unmarshal(value, &version) != nil || version == 0 {
			ignored += 1
			continue
		}
		read.Versions[member.key] = version
	}
	if 0 < ignored {
		read.Gap, read.Reason = MemberHarnessConfigGapUnreadable, fmt.Sprintf("%d of compute.disclosures' values are no version", ignored)
	}
	return read
}

// The change that records version for id: its value set where the key reads as an object and holds a lower version or
// none, the whole key written where it does not read, and nothing where it holds this version or a higher one.
func computeDisclosureAckChange(id string, version uint32) MemberHarnessConfigChange {
	return func(config *MemberHarnessConfigRead) ([]*MemberHarnessConfigEdit, error) {
		value := json.RawMessage(strconv.FormatUint(uint64(version), 10))
		path := []string{computeDisclosureAckKeyCompute, computeDisclosureAckKeyDisclosures}
		raw, held := config.Key(path...)
		if held {
			if _, err := parseHarnessJsonObject(raw, 0, len(raw)); err != nil {
				// nothing of a key that does not read can be kept
				whole, err := json.Marshal(map[string]uint32{id: version})
				if err != nil {
					return nil, err
				}
				return []*MemberHarnessConfigEdit{{Path: path, Value: whole}}, nil
			}
			if version <= readComputeDisclosureAcks(config).Versions[id] {
				// versions only rise
				return nil, nil
			}
		}
		return []*MemberHarnessConfigEdit{{Path: append(path, id), Value: value}}, nil
	}
}

// What a person's acknowledgment records (Sidecar.AckComputeDisclosure).
type ComputeDisclosureAckArgs struct {
	// The disclosure, family:slug.
	Id string
	// The version the person was shown: the newest verified policy's current one, else disclosure_changed with nothing
	// written.
	Version uint32
	// The act's origin: only SidecarActConfirmed records.
	Origin SidecarActOrigin
	// A harness process is among the caller's ancestors (Sidecar.HarnessAncestor), which refuses the act.
	HarnessAncestor bool
}

// What the acknowledgments are built on.
type ComputeDisclosureAcksArgs struct {
	// The member's harness config store, read at each call: CACL-M11-01's. Required.
	Store func() (*MemberHarnessConfig, error)
	// The texts, whose current version an acknowledgment must match. Required.
	Registry *ComputeDisclosureRegistry
	// Calls notify at each change of the vault's repo, until remove; nil watches nothing, the recheck alone reading
	// again.
	Watch func(vaultId Id, notify func()) (remove func())
	// Nil takes the registry's.
	Settings *ComputeDisclosureSettings
	// Nil reads real time.
	Clock Clock
}

// The person's acknowledgments in the member's harness config: see the file header.
type ComputeDisclosureAcks struct {
	store    func() (*MemberHarnessConfig, error)
	registry *ComputeDisclosureRegistry
	watch    func(vaultId Id, notify func()) (remove func())
	settings *ComputeDisclosureSettings
	clock    Clock

	stateLock sync.Mutex
	// closed and replaced at each notice that the key may have changed
	changed chan struct{}
}

// The acknowledgments over args.
func NewComputeDisclosureAcks(args *ComputeDisclosureAcksArgs) (*ComputeDisclosureAcks, error) {
	if args == nil || args.Store == nil || args.Registry == nil {
		return nil, errors.New("compute disclosure acknowledgments: a store and a registry")
	}
	settings := args.Settings
	if settings == nil {
		settings = args.Registry.Settings()
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	return &ComputeDisclosureAcks{
		store:    args.Store,
		registry: args.Registry,
		watch:    args.Watch,
		settings: settings,
		clock:    clock,
		changed:  make(chan struct{}),
	}, nil
}

// The acknowledgments as this sidecar reads them now. An error reads nothing: no store, no verified state or evs client,
// or a read of the vault that failed.
func (self *ComputeDisclosureAcks) Read(ctx context.Context) (*ComputeDisclosureAckRead, error) {
	store, err := self.store()
	if err != nil {
		return nil, err
	}
	config, err := store.Read(ctx)
	if err != nil {
		return nil, err
	}
	return readComputeDisclosureAcks(config), nil
}

// Records the person's acknowledgment of args.Id at args.Version: see the file header's who row. Nothing is written
// where the act is not the person's, the id is not the newest verified policy's, or the version is not its current one
// (ErrDisclosureChanged); a version already held, or a higher one, writes nothing and answers nil.
func (self *ComputeDisclosureAcks) Ack(ctx context.Context, args *ComputeDisclosureAckArgs) error {
	if args == nil || args.Origin != SidecarActConfirmed {
		return fmt.Errorf("%w: the act's origin is no person's confirmation", ErrDisclosureAckRefused)
	}
	if args.HarnessAncestor {
		return fmt.Errorf("%w: a harness process is among the caller's ancestors", ErrDisclosureAckRefused)
	}
	disclosure, err := self.registry.Disclosure(args.Id)
	if err != nil {
		return err
	}
	if args.Version != disclosure.Version() {
		return ErrDisclosureChanged
	}
	store, err := self.store()
	if err != nil {
		return err
	}
	testHookBarrier("disclosure.ack.write.before", args.Id)
	_, err = store.Update(ctx, &MemberHarnessConfigUpdateArgs{Origin: args.Origin, HarnessAncestor: args.HarnessAncestor},
		computeDisclosureAckChange(disclosure.Id.String(), args.Version))
	if errors.Is(err, ErrHarnessConfigRefused) {
		return fmt.Errorf("%w: %w", ErrDisclosureAckRefused, err)
	}
	if err != nil {
		return err
	}
	testHookBarrier("disclosure.ack.write.after", args.Id)
	self.Notify()
	return nil
}

// Tells every Await the key may have changed, so each reads it again: this device's own act, or a change of the
// member's vault.
func (self *ComputeDisclosureAcks) Notify() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	close(self.changed)
	self.changed = make(chan struct{})
}

// The channel the next Notify closes.
func (self *ComputeDisclosureAcks) changedChannel() chan struct{} {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.changed
}

// Returns once the acknowledgments hold version of id, or a higher one, made here or synced from another of the
// member's devices; at once where they already do. An error once ctx ends. Only the key ends it (the file header's
// await row).
func (self *ComputeDisclosureAcks) Await(ctx context.Context, id string, version uint32) error {
	var removeWatch func()
	defer func() {
		if removeWatch != nil {
			removeWatch()
		}
	}()
	for {
		// subscribed immediately before the read, so a change between them wakes the next wait
		changed := self.changedChannel()
		read, err := self.Read(ctx)
		if err == nil {
			if version <= read.Versions[id] {
				return nil
			}
			if removeWatch == nil && self.watch != nil && read.VaultId != (Id{}) {
				removeWatch = self.watch(read.VaultId, self.Notify)
			}
		}
		testHookBarrier("disclosure.await.read", id)
		var recheck <-chan time.Time
		if 0 < self.settings.AwaitRecheckInterval {
			recheck = self.clock.After(self.settings.AwaitRecheckInterval)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		case <-recheck:
		}
	}
}

// One id's mark state on this device.
type computeDisclosureMark struct {
	Id string `json:"id"`
	// The version this device first listed it at: new to the person then, not changed.
	First uint32 `json:"first"`
	// The newest version the person opened, 0 for none.
	Opened uint32 `json:"opened"`
}

// The marks file.
type computeDisclosureMarksFile struct {
	Format int `json:"format"`
	// Least recently touched first.
	Marks []*computeDisclosureMark `json:"marks"`
}

// The "changed" marks in the sidecar's own sealed store (the file header's marks row). A store that cannot be read or
// written, as before enrollment or while locked, keeps no marks: an id then shows changed where the acknowledged
// version is older than the current one, its one reference left.
type computeDisclosureMarks struct {
	store    func() (SidecarStore, error)
	settings *ComputeDisclosureSettings

	// serializes each read and write of the file, held across its I/O
	fileLock sync.Mutex
}

// The file's marks, none where it is absent or does not read; an error where the store cannot be reached.
func (self *computeDisclosureMarks) readWithLock() (*computeDisclosureMarksFile, SidecarStore, error) {
	store, err := self.store()
	if err != nil {
		return nil, nil, err
	}
	file := &computeDisclosureMarksFile{Format: computeDisclosureMarksFormat}
	reader, err := store.Open(computeDisclosureMarksName)
	if err != nil {
		// absent, or unreadable: no marks
		return file, store, nil
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, int64(self.settings.MarksMaxByteCount)+1))
	read := &computeDisclosureMarksFile{}
	if err != nil || self.settings.MarksMaxByteCount < len(data) || json.Unmarshal(data, read) != nil ||
		read.Format != computeDisclosureMarksFormat {
		return file, store, nil
	}
	read.Marks = slices.DeleteFunc(read.Marks, func(mark *computeDisclosureMark) bool { return mark == nil })
	return read, store, nil
}

// Writes file, oldest marks dropped past MarksMaxCount, the ids carried in none of keepIds first.
func (self *computeDisclosureMarks) writeWithLock(store SidecarStore, file *computeDisclosureMarksFile, keepIds []string) error {
	for self.settings.MarksMaxCount < len(file.Marks) {
		index := slices.IndexFunc(file.Marks, func(mark *computeDisclosureMark) bool { return !slices.Contains(keepIds, mark.Id) })
		if index < 0 {
			index = 0
		}
		file.Marks = slices.Delete(file.Marks, index, index+1)
	}
	data, err := json.Marshal(file)
	if err != nil {
		return err
	}
	writer, err := store.Create(computeDisclosureMarksName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// Whether each disclosure's lines are marked changed, by id, given the versions the person acknowledged; an id first
// listed here is recorded at its current version, so it is new, not changed.
func (self *computeDisclosureMarks) changed(disclosures []*ComputeDisclosure, acknowledged map[string]uint32) map[string]bool {
	idChanged := map[string]bool{}
	self.fileLock.Lock()
	defer self.fileLock.Unlock()
	file, store, err := self.readWithLock()
	if err != nil {
		for _, disclosure := range disclosures {
			acked := acknowledged[disclosure.Id.String()]
			idChanged[disclosure.Id.String()] = 0 < acked && acked < disclosure.Version()
		}
		return idChanged
	}
	added := false
	keepIds := []string{}
	for _, disclosure := range disclosures {
		id := disclosure.Id.String()
		keepIds = append(keepIds, id)
		index := slices.IndexFunc(file.Marks, func(mark *computeDisclosureMark) bool { return mark.Id == id })
		if index < 0 {
			file.Marks = append(file.Marks, &computeDisclosureMark{Id: id, First: disclosure.Version()})
			added = true
			acked := acknowledged[id]
			idChanged[id] = 0 < acked && acked < disclosure.Version()
			continue
		}
		mark := file.Marks[index]
		idChanged[id] = max(mark.First, mark.Opened, acknowledged[id]) < disclosure.Version()
	}
	if added {
		// a mark not written only leaves the id new again next time
		self.writeWithLock(store, file, keepIds)
	}
	return idChanged
}

// Records that the person opened id's text at version, which ends its lines' mark until a newer version.
func (self *computeDisclosureMarks) opened(id string, version uint32, keepIds []string) error {
	self.fileLock.Lock()
	defer self.fileLock.Unlock()
	file, store, err := self.readWithLock()
	if err != nil {
		return err
	}
	index := slices.IndexFunc(file.Marks, func(mark *computeDisclosureMark) bool { return mark.Id == id })
	mark := &computeDisclosureMark{Id: id, First: version}
	if 0 <= index {
		mark = file.Marks[index]
		file.Marks = slices.Delete(file.Marks, index, index+1)
	}
	mark.Opened = max(mark.Opened, version)
	// the most recently touched last
	file.Marks = append(file.Marks, mark)
	return self.writeWithLock(store, file, keepIds)
}
