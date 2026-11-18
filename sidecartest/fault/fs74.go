// FS-74 on real engines (§11.14's commit path and in-ref row; D-EVS-46, FI-18; SEARCH-M10-35): writers' in-ref
// pushes on the evs world (evs_world.go) at format 2, each writer's IndexWriter (SEARCH-M10-13) planning its head
// beside its content push through the push builder, so one head CAS commits content and index, through evsservice's
// engine on T2's fakes and, through server's evshost, on T3's stores; the index is read back through EvsRepo's
// verifying reader, as every index builder reads it (evs_index_store_evs.go).
//
//	Fs74DisjointHeadsOnEvs  writerA's and writerB's text pushes to the main ref, each changing only its own head in
//	                        the current bucket, commit at successive ref versions, and the reader's view of the index
//	                        holds both documents live, each at the version its content push wrote
//
// The rest of FS-74, and FS-75 and FS-79, run on the search world (fs74_test.go, fs75_test.go, fs79_test.go), whose
// store stands in for evs; their merges, roll-ups, builds and backfills over EvsRepo, and a device's search through an
// EvsRepo-backed sync source (SEARCH-M10-19's, not built), are not run here yet.

package fault

import (
	"context"
	"fmt"

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

// See the file header.
func Fs74DisjointHeadsOnEvs(net *Net) *Schedule {
	world := NewEvsWorld(net, fs74EvsWorldSettings())
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
		{Actor: "writerA", Action: world.Write("writerA", "notes/harbor.md", contents["notes/harbor.md"])},
		{Actor: "writerB", Action: world.Write("writerB", "notes/lighthouse.md", contents["notes/lighthouse.md"])},
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
	return &Schedule{Steps: steps, Tiers: []Tier{TierT2, TierT3}}
}
