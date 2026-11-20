//go:build sidecar_testhooks

// FS-74 on real engines (§11.14's commit path and in-ref row; D-EVS-46, FI-18; SEARCH-M10-35): writers' in-ref
// pushes on the evs world (evs_world.go) at format 2, each writer's IndexWriter (SEARCH-M10-13) planning its head
// beside its content push through the push builder, so one head CAS commits content and index, through evsservice's
// engine on T2's fakes and, through server's evshost, on T3's stores; the index is read back through EvsRepo's
// verifying reader, as every index builder reads it (evs_index_store_evs.go).
//
//	Fs74DisjointHeadsOnEvs  writerA's and writerB's text pushes to the main ref, each changing only its own head in
//	                        the current bucket, commit at successive ref versions, and the reader's view of the index
//	                        holds both documents live
//
// Its check after every step is FI-18's documents clause, which the last step makes by hand (fs74Written): each file
// a writer's push committed has its document live in the reader's view of the index, read as the steps read it. The
// successive versions are the row's own clause, which that step holds; nothing here merges or rolls, so FI-20, the
// row's other invariant, is the search world's (fs74_test.go).
//
// The index's seams here (search_evs_testhooks.go) are the root's under sidecar_testhooks alone, so the case is
// registered only on that build, which both its tiers' tests take. The rest of FS-74, and FS-75 and FS-79, run on the
// search world (fs74_test.go, fs75_test.go, fs79_test.go), whose store stands in for evs; their merges, roll-ups,
// builds and backfills over EvsRepo, and a device's search through an EvsRepo-backed sync source (SEARCH-M10-19's,
// not built), are not run here yet.

package fault

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar"
)

var Fs74 = Register("FS-74", "", []Tier{TierT2, TierT3}, Fs74DisjointHeadsOnEvs)

// The default world at format 2 throughout: every instance, every device, and the network in the format2 gate.
func fs74EvsWorldSettings() *EvsWorldSettings {
	settings := DefaultEvsWorldSettings()
	settings.Format2 = DefaultEvsWorldFormat2Settings()
	settings.InstanceFormats = map[string]uint32{}
	for _, instance := range settings.Instances {
		settings.InstanceFormats[instance] = sidecar.EvsRepoFormat2
	}
	for _, device := range settings.Devices {
		device.Format2 = true
	}
	return settings
}

// No settings version counts in these rows: none is written.
func fs74NoAdmin(signer sidecar.Id) bool {
	return false
}

// A step action: an in-ref index writer on each of devices' clients, as the daemon's composition installs one.
func fs74InstallIndexWriters(world *EvsWorld, devices ...string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		for _, name := range devices {
			device := world.Device(name)
			if device == nil || device.Client == nil {
				return fmt.Errorf("device %s is not started", name)
			}
			remove, err := sidecar.InstallSearchTestIndexWriter(device.Client, &sidecar.SearchTestIndexWriterArgs{IsAdmin: fs74NoAdmin})
			if err != nil {
				return err
			}
			context.AfterFunc(net.Context(), remove)
		}
		return nil
	}
}

// The main ref's files a case's writers committed, and their documents' keys as the reader derives them: what FI-18's
// documents clause holds the reader's view of the index to after every step. Safe for concurrent use.
type fs74Written struct {
	world *EvsWorld

	stateLock sync.Mutex
	// each path once its writer's push committed, with its doc_key once derived
	pathKeys map[string]*[16]byte
	// the reader's view of the index as last read, and the ETag of main's head object it was read at
	index     *sidecar.SearchTestEvsIndex
	indexEtag string
}

// The reader's view of the index, read through EvsRepo's verifying reader as the steps read it, and read again only
// once main's head object, which every push to the ref rewrites, has changed in the store since: a check after a step
// that pushed nothing reads the head alone.
func (self *fs74Written) readIndex(ctx context.Context, oracle *Oracle) (*sidecar.SearchTestEvsIndex, error) {
	head, err := oracle.View.Head(ctx, self.world.RepoId, self.world.RefId())
	if err != nil {
		return nil, err
	}
	etag := ""
	if head != nil {
		etag = head.Etag
	}
	self.stateLock.Lock()
	index, indexEtag := self.index, self.indexEtag
	self.stateLock.Unlock()
	if index != nil && etag != "" && etag == indexEtag {
		return index, nil
	}
	index, err = sidecar.ReadSearchTestEvsIndex(ctx, self.world.Device("reader").Repo, nil, fs74NoAdmin)
	if err != nil {
		return nil, fmt.Errorf("the reader's view of the index: %w", err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.index, self.indexEtag = index, etag
	return index, nil
}

func newFs74Written(world *EvsWorld) *fs74Written {
	return &fs74Written{world: world, pathKeys: map[string]*[16]byte{}}
}

// A step action: device writes content at path, as world.Write does, and the path is noted once its push committed.
func (self *fs74Written) write(device string, path string, content []byte) func(ctx context.Context, net *Net) error {
	write := self.world.Write(device, path, content)
	return func(ctx context.Context, net *Net) error {
		if err := write(ctx, net); err != nil {
			return err
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if _, ok := self.pathKeys[path]; !ok {
				self.pathKeys[path] = nil
			}
		}()
		return nil
	}
}

// FI-18's documents clause (§11.14's in-ref, merge and roll-up rows; I-EVS-11's merged view): after every step, each
// file a writer's push committed has its document live in the reader's view of the index, whatever was sealed, merged
// or rolled since (readIndex).
func (self *fs74Written) documentsLive() Invariant {
	return NewInvariant("FI-18/documents", func(ctx context.Context, oracle *Oracle) error {
		self.stateLock.Lock()
		pathKeys := maps.Clone(self.pathKeys)
		self.stateLock.Unlock()
		if len(pathKeys) == 0 {
			return nil
		}
		index, err := self.readIndex(ctx, oracle)
		if err != nil {
			return err
		}
		for _, path := range slices.Sorted(maps.Keys(pathKeys)) {
			key := pathKeys[path]
			if key == nil {
				derived, err := sidecar.SearchTestEvsDocKey(ctx, self.world.Device("reader").Repo, self.world.RefId(), path)
				if err != nil {
					return err
				}
				key = &derived
				func() {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					self.pathKeys[path] = key
				}()
			}
			if index.Live[*key] == 0 {
				return fmt.Errorf("%s, committed, is not live in the reader's view of the index at ref version %d", path, index.Version)
			}
		}
		return nil
	})
}

// See the file header.
func Fs74DisjointHeadsOnEvs(net *Net) *Schedule {
	world := NewEvsWorld(net, fs74EvsWorldSettings())
	written := newFs74Written(world)
	paths := map[string]string{"notes/harbor.md": "writerA", "notes/lighthouse.md": "writerB"}
	contents := map[string][]byte{
		"notes/harbor.md":     []byte("the harbor at noon\n"),
		"notes/lighthouse.md": []byte("a lighthouse keeper's log\n"),
	}
	var before uint64
	read := func(ctx context.Context) (*sidecar.SearchTestEvsIndex, error) {
		return sidecar.ReadSearchTestEvsIndex(ctx, world.Device("reader").Repo, nil, fs74NoAdmin)
	}
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: fs74InstallIndexWriters(world, "writerA", "writerB")},
		{Actor: "reader", Action: func(ctx context.Context, net *Net) error {
			index, err := read(ctx)
			if err != nil {
				return err
			}
			before = index.Version
			return nil
		}},
		{Actor: "writerA", Action: written.write("writerA", "notes/harbor.md", contents["notes/harbor.md"])},
		{Actor: "writerB", Action: written.write("writerB", "notes/lighthouse.md", contents["notes/lighthouse.md"])},
		{Actor: "reader", Action: func(ctx context.Context, net *Net) error {
			index, err := read(ctx)
			if err != nil {
				return err
			}
			if index.Version != before+2 {
				return fmt.Errorf("two in-ref pushes took the ref from %d to %d", before, index.Version)
			}
			reader := world.Device("reader").Repo
			for path, writer := range paths {
				key, err := sidecar.SearchTestEvsDocKey(ctx, reader, world.RefId(), path)
				if err != nil {
					return err
				}
				if index.Live[key] == 0 {
					return fmt.Errorf("%s's push left %s out of the index: %v", writer, path, index.Files)
				}
			}
			return nil
		}},
	}
	return &Schedule{Steps: steps, Check: []Invariant{written.documentsLive()}, Tiers: []Tier{TierT2, TierT3}}
}
