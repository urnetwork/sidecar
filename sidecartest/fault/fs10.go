// FS-10 (§22.8; §11.9's reader and trusts rows, §2.8's disclosure, I-4, I-16; EVS1-M2-41) on the evs world
// (evs_world.go), T2 alone, since the server forges state here, with its twin on T3 too (§22.8's cadence rule).
//
// The registered case, Fs10ReaderOnlyForgery, beside its twin: a member device that only reads the repo, its own
// configuration lying to it that it writes, and evs, which here grants any scope a token asks for, together commit a
// change to x.txt: a statement the forger signed, sealed under the generation it holds as a reader. The head-mode
// reader's next read of x.txt is refused, the walk finding a shared ref's writer its state does not list, and the
// reader raises tamper naming the forger; nothing it held moves. The twin, Fs10WriterChange, has a writer make the
// same change, which the reader reads and verifies.
//
// The clause beside it, Fs10RollbackRefused: the reader reads x.txt, folded into its entry; a writer changes it and the
// fold takes the change in; then evs serves x.txt's entry as it stood before, so the newest version it answers is the
// one the reader already read, while a statement after the reader's record changes x.txt: the reader refuses the
// entry, a later statement changing the path it was served as unchanged, and alarms tamper. The server forging that entry breaks FI-6's one home per path, which is the
// point, so the clause checks the client's side alone.
//
// FS-10's further clauses (a never-read path served at an older version or at a refused push's writer-signed entry,
// accepted as §2.8 publishes; a 100,000-change push's adjacent-leaf proofs with no change list fetched and an unsorted
// change list refused; a reader 10,000 versions behind re-pinning with a gap mark; P read at v20 at pin 25 with the pin
// moved to 30 and P changed at v28 by a rooted statement, and an evicted read record reading as never read) are
// EVS1-M2-41's report's; FI-3's oracle is not bound (TEST-M2-05), so the schedules check the readers' answers and
// alarms in its place.

package fault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs10 = Register("FS-10", "", []Tier{TierT2}, Twin(Fs10ReaderOnlyForgery, Fs10WriterChange))

// The default world and a forger: a device that reads the repo and whose own configuration says it writes it.
func fs10WorldSettings() *EvsWorldSettings {
	settings := DefaultEvsWorldSettings()
	settings.Devices = append(settings.Devices, &EvsWorldDeviceSettings{Name: "forger", Instances: []string{"evs2"}, ForgesWriter: true})
	return settings
}

// See the file header.
func Fs10ReaderOnlyForgery(net *Net) *Schedule {
	world := NewEvsWorld(net, fs10WorldSettings())
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "x.txt", EvsWorldContent("fs10 x 1", 200))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt")},
		{Actor: "forger", Action: world.Write("forger", "x.txt", EvsWorldContent("fs10 x forged", 200))},
		{Actor: "reader", Action: world.VerifyRefused("reader", "x.txt", sidecar.ErrEvsStatementRefused)},
		{Actor: "check", Action: world.ExpectAlarm("reader", sidecar.SidecarEvsAlarmTamper)},
		{Actor: "reader", Action: world.VerifyRefused("reader", "x.txt", sidecar.ErrEvsStatementRefused)},
	}
	return &Schedule{
		Id: "FS-10", Steps: steps, Check: world.ChecksAlarming(map[string]sidecar.SidecarEvsAlarm{"reader": sidecar.SidecarEvsAlarmTamper}),
		Tiers: []Tier{TierT2}, Refuses: "a change a reader-only member signed and evs committed, refused by the head-mode reader with tamper",
	}
}

// See the file header.
func Fs10WriterChange(net *Net) *Schedule {
	world := NewEvsWorld(net, fs10WorldSettings())
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "x.txt", EvsWorldContent("fs10 x 1", 200))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt")},
		{Actor: "writerB", Action: world.Write("writerB", "x.txt", EvsWorldContent("fs10 x 2", 200))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt")},
	}
	return &Schedule{Id: "FS-10", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}

// See the file header.
func Fs10RollbackRefused(net *Net) *Schedule {
	world := NewEvsWorld(net, nil)
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "x.txt", EvsWorldContent("fs10 x 1", 200))},
		// x.txt's version in its entry, which the next commit's folded_through covers
		{Actor: "folder", Action: world.Fold("evs1")},
		{Actor: "writerA", Action: world.Write("writerA", "d/keep.txt", EvsWorldContent("fs10 keep 1", 16))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt")},
		{Actor: "server", Action: world.SaveEntries()},
		{Actor: "writerA", Action: world.Write("writerA", "x.txt", EvsWorldContent("fs10 x 2", 200))},
		{Actor: "folder", Action: world.Fold("evs1")},
		{Actor: "writerA", Action: world.Write("writerA", "d/keep.txt", EvsWorldContent("fs10 keep 2", 16))},
		// evs serves x.txt's entry as it stood before its second version
		{Actor: "server", Action: world.RestoreEntries()},
		{Actor: "reader", Action: world.VerifyRefused("reader", "x.txt", sidecar.ErrEvsEntryRefused)},
		{Actor: "check", Action: world.ExpectAlarm("reader", sidecar.SidecarEvsAlarmTamper)},
	}
	return &Schedule{
		Id: "FS-10 rollback refused", Steps: steps, Check: []Invariant{world.Outcomes()}, Tiers: []Tier{TierT2},
		Refuses: "a path's entry served at a version older than a statement after the reader's record changes it",
		Forged:  true, Twin: Fs10RollbackTwin,
	}
}

// The rollback clause's twin: the same writes and folds, and evs serving x.txt's entry as it stands.
func Fs10RollbackTwin(net *Net) *Schedule {
	world := NewEvsWorld(net, nil)
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "x.txt", EvsWorldContent("fs10 x 1", 200))},
		{Actor: "folder", Action: world.Fold("evs1")},
		{Actor: "writerA", Action: world.Write("writerA", "d/keep.txt", EvsWorldContent("fs10 keep 1", 16))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt")},
		{Actor: "writerA", Action: world.Write("writerA", "x.txt", EvsWorldContent("fs10 x 2", 200))},
		{Actor: "folder", Action: world.Fold("evs1")},
		{Actor: "writerA", Action: world.Write("writerA", "d/keep.txt", EvsWorldContent("fs10 keep 2", 16))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt")},
	}
	return &Schedule{Id: "FS-10 rollback refused twin", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}

// A step action: device's read of path fails, with an error is errIs when that is not nil, and returns nothing.
func (self *EvsWorld) VerifyRefused(device string, path string, errIs error) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		out := &bytes.Buffer{}
		_, err := self.Device(device).Repo.ReadHead(ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true}, out)
		switch {
		case err == nil:
			return fmt.Errorf("%s read %q as %d bytes, where the read must be refused", device, path, out.Len())
		case errIs != nil && !errors.Is(err, errIs):
			return fmt.Errorf("%s's read of %q ended %v, not %v", device, path, err, errIs)
		}
		return nil
	}
}

// A step action: device has raised alarm.
func (self *EvsWorld) ExpectAlarm(device string, alarm sidecar.SidecarEvsAlarm) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, raised := range self.deviceAlarms[device] {
			if strings.HasPrefix(raised, string(alarm)+" ") {
				return nil
			}
		}
		return fmt.Errorf("%s raised no %s, only %v", device, alarm, self.deviceAlarms[device])
	}
}

// Checks's, with the alarms a forged schedule expects in place of none: each device named may raise its alarm, and
// no device raises another.
func (self *EvsWorld) ChecksAlarming(expected map[string]sidecar.SidecarEvsAlarm) []Invariant {
	return []Invariant{FI(1), FI(6), self.Outcomes(), NewInvariant("evs alarms", func(ctx context.Context, oracle *Oracle) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, name := range self.deviceNames {
			for _, raised := range self.deviceAlarms[name] {
				if alarm, ok := expected[name]; ok && strings.HasPrefix(raised, string(alarm)+" ") {
					continue
				}
				return fmt.Errorf("%s alarmed: %s", name, raised)
			}
		}
		return nil
	})}
}

// A step action: the server keeps every idx/ object of the repo as it stands, for RestoreEntries.
func (self *EvsWorld) SaveEntries() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		saved, err := self.entryObjects(ctx, net)
		if err != nil {
			return err
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.savedEntries = saved
		return nil
	}
}

// A step action: the server puts back each file's idx/ entry SaveEntries kept whose bytes have changed since, by
// If-Match on what stands, under an inspecting context: files' entries rolled back, directories' tables left alone.
func (self *EvsWorld) RestoreEntries() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.stateLock.Lock()
		saved := self.savedEntries
		self.stateLock.Unlock()
		if saved == nil {
			return errors.New("no entries saved")
		}
		inspect := sidecartest.InspectContext(ctx)
		cluster, err := net.Host().Blobs.FirstCluster()
		if err != nil {
			return err
		}
		restored := 0
		for key, body := range saved {
			object, err := cluster.Get(inspect, key)
			if err != nil {
				return err
			}
			standing, err := io.ReadAll(object.Body)
			object.Body.Close()
			if err != nil {
				return err
			}
			if bytes.Equal(standing, body) {
				continue
			}
			entry := &protocol.EvsIndexEntry{}
			if err := proto.Unmarshal(body, entry); err != nil {
				return fmt.Errorf("a saved entry %s: %w", key, err)
			}
			if entry.GetNames() != nil {
				continue
			}
			if _, err := cluster.PutIfMatch(inspect, key, object.Etag, body, nil); err != nil {
				return fmt.Errorf("rolling %s back: %w", key, err)
			}
			restored += 1
		}
		if restored == 0 {
			return errors.New("no entry changed since it was saved")
		}
		return nil
	}
}

// Every idx/ object of the repo on its cluster, by key.
func (self *EvsWorld) entryObjects(ctx context.Context, net *Net) (map[string][]byte, error) {
	inspect := sidecartest.InspectContext(ctx)
	cluster, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		return nil, err
	}
	prefix := "idx/" + sidecar.EvsKeyId(self.RepoId) + "/"
	objects := map[string][]byte{}
	startAfter := ""
	for {
		infos, more, err := cluster.List(inspect, prefix, startAfter, 1000)
		if err != nil {
			return nil, err
		}
		for _, info := range infos {
			object, err := cluster.Get(inspect, info.Key)
			if err != nil {
				return nil, err
			}
			body, err := io.ReadAll(object.Body)
			object.Body.Close()
			if err != nil {
				return nil, err
			}
			objects[info.Key] = body
		}
		if !more || len(infos) == 0 {
			return objects, nil
		}
		startAfter = infos[len(infos)-1].Key
	}
}
