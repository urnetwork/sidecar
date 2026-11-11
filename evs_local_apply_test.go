//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// Settle's table (DESIGN-DETAILS 8.2.7), a test a row, on device B's bare repository with its local ref moved by hand
// as a client or a restored state would, and a kill at each of a flush's three points (apply.state, apply.ref,
// apply.done) with the restart's settle finishing as an unkilled flush does.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// Writes commit, its tree and every object below it from the publisher's history into the device's bare repository,
// as a client's push or a restored state leaves them there.
func (self *evsTestDevice) hold(commit EvsGitOid) {
	self.t.Helper()
	store := self.publisher.mount.history.store
	var write func(oid EvsGitOid)
	write = func(oid EvsGitOid) {
		object := store.objects[oid]
		if object == nil {
			self.t.Fatalf("no object %x in the history", oid[:])
		}
		command := exec.Command(self.mount.git.gitPath, "-C", self.mount.BareDir, "hash-object", "-w", "--literally", "-t", object.kind, "--stdin")
		command.Env = self.mount.git.environment()
		command.Stdin = bytes.NewReader(object.content)
		if out, err := command.Output(); err != nil || strings.TrimSpace(string(out)) != oid.String() {
			self.t.Fatalf("hash-object: %v %s", err, out)
		}
		switch object.kind {
		case evsGitCommitKind:
			tree, parents, err := EvsGitCommitGraph(object.content)
			if err != nil {
				self.t.Fatal(err)
			}
			write(tree)
			for _, parent := range parents {
				if !self.present(parent) {
					write(parent)
				}
			}
		case evsGitTreeKind:
			entries, err := EvsGitTreeRead(object.content)
			if err != nil {
				self.t.Fatal(err)
			}
			for _, entry := range entries {
				write(entry.Oid)
			}
		}
	}
	write(commit)
}

// Whether the device's bare repository holds oid.
func (self *evsTestDevice) present(oid EvsGitOid) bool {
	_, err := self.mount.Git(context.Background(), "cat-file", "-e", oid.String())
	return err == nil
}

// Moves the device's local ref by hand, outside the daemon, none deleting it.
func (self *evsTestDevice) moveLocal(gitRef string, oid *EvsGitOid) {
	self.t.Helper()
	if oid == nil {
		evsTestGit(self.t, self.mount.BareDir, "update-ref", "-d", gitRef)
		return
	}
	evsTestGit(self.t, self.mount.BareDir, "update-ref", gitRef, hex.EncodeToString(oid[:]))
}

// Writes a journal of the ref of name holding updates, as the receive path or the queue leaves one.
func (self *evsTestDevice) journal(name string, updates ...*EvsJournalUpdate) {
	self.t.Helper()
	journal := &EvsJournalRef{RefName: []byte(name), Updates: updates, NextSeq: uint64(len(updates))}
	if err := self.engine.state.writeJournal(self.publisher.ref(name).refId, journal); err != nil {
		self.t.Fatal(err)
	}
}

// Settle's follow rows: the local ref at the applied tip follows evs, and so does one a client moved to an ancestor of
// evs's new tip; a SENT update evs's tip now covers is deleted, and no conflict branch is made (8.1's E).
func TestEvsLocalSettleFollows(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c1 := publisher.commit(map[string]string{"a.txt": "one\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	device := newEvsTestDevice(t, publisher, "device b")
	device.replay("main")
	c2 := publisher.commit(map[string]string{"a.txt": "two\n"}, c1)
	c3 := publisher.commit(map[string]string{"a.txt": "three\n"}, c2)
	if _, err := publisher.publish("main", &c2); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.publish("main", &c3); err != nil {
		t.Fatal(err)
	}
	// a client fetched c2 into the local ref, an ancestor of evs's new tip; the device's own push of c2 is SENT
	device.hold(c2)
	device.moveLocal("refs/heads/main", &c2)
	device.journal("main", &EvsJournalUpdate{Seq: 1, Old: c1.String(), New: c2.String(), State: EvsJournalSent, Kind: EvsJournalKindReceive})
	device.replay("main")
	if local := device.local("refs/heads/main"); local == nil || *local != c3 {
		t.Fatalf("main is %v (c2 %v c3 %v) record %+v alarms %v", local, c2, c3, device.ref("main"), device.alarms())
	}
	journal, err := device.engine.state.journal(publisher.ref("main").refId)
	if err != nil || len(journal.Updates) != 0 {
		t.Fatalf("the covered update stands: %+v %v", journal, err)
	}
	if conflicts := device.test.eventsOf(SidecarEventEvsConflict); len(conflicts) != 0 {
		t.Fatalf("a conflict for a commit evs holds: %v", conflicts)
	}
}

// Settle's keep and nothing rows: a local ref ahead of evs's new tip by its own queue is kept, applied_tip moving to
// evs's; then, evs not having moved, a settle does nothing while the queue holds the local ref.
func TestEvsLocalSettleKeepsAQueue(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c0 := publisher.commit(map[string]string{"a.txt": "zero\n"})
	if _, err := publisher.publish("main", &c0); err != nil {
		t.Fatal(err)
	}
	device := newEvsTestDevice(t, publisher, "device b")
	device.replay("main")
	c1 := publisher.commit(map[string]string{"a.txt": "one\n"}, c0)
	c2 := publisher.commit(map[string]string{"a.txt": "two\n"}, c1)
	device.hold(c2)
	device.moveLocal("refs/heads/main", &c2)
	device.journal("main", &EvsJournalUpdate{Seq: 1, Old: c0.String(), New: c2.String(), State: EvsJournalLocal, Kind: EvsJournalKindQueue})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	device.replay("main")
	if local := device.local("refs/heads/main"); local == nil || *local != c2 {
		t.Fatalf("the queued local ref moved to %v", local)
	}
	ref := device.ref("main")
	if !evsOidEqual(ref.AppliedTip, &c1) || !evsOidEqual(ref.Tip, &c1) {
		t.Fatalf("the record %+v", ref)
	}
	journal, _ := device.engine.state.journal(publisher.ref("main").refId)
	if len(journal.Updates) != 1 {
		t.Fatalf("the queue's update went: %+v", journal)
	}
	if err := device.engine.settle(context.Background(), publisher.ref("main").refId); err != nil {
		t.Fatal(err)
	}
	if local := device.local("refs/heads/main"); local == nil || *local != c2 {
		t.Fatalf("a settle with evs unmoved moved the queued ref to %v", local)
	}
}

// A kill at each of a flush's points leaves what a restart's settle finishes: the local ref at evs's tip and
// applied_tip equal to the tip, with nothing applied twice and no conflict branch.
func TestEvsLocalSettleKilledAtEachPoint(t *testing.T) {
	for _, point := range []string{"state", "ref", "done"} {
		publisher := newEvsTestPublisher(t)
		c1 := publisher.commit(map[string]string{"a.txt": "one\n"})
		if _, err := publisher.publish("main", &c1); err != nil {
			t.Fatal(err)
		}
		device := newEvsTestDevice(t, publisher, "device b")
		device.replay("main")
		c2 := publisher.commit(map[string]string{"a.txt": "two\n"}, c1)
		if _, err := publisher.publish("main", &c2); err != nil {
			t.Fatal(err)
		}
		killed := errors.New("killed")
		evsLocalApplyKillHook = func(at string) error {
			if at == point {
				return killed
			}
			return nil
		}
		err := device.engine.Replay(context.Background(), publisher.ref("main").refId)
		evsLocalApplyKillHook = nil
		if !errors.Is(err, killed) {
			t.Fatalf("%s: the replay %v", point, err)
		}
		// the restart: a new engine on the same mount and store
		restarted := newEvsGitSyncEngine(device.test.client, device.mount)
		if err := restarted.Start(context.Background()); err != nil {
			t.Fatalf("%s: the restart %v", point, err)
		}
		if err := restarted.Replay(context.Background(), publisher.ref("main").refId); err != nil {
			t.Fatalf("%s: the replay after %v", point, err)
		}
		if local := device.local("refs/heads/main"); local == nil || *local != c2 {
			t.Fatalf("%s: main is %v", point, local)
		}
		ref, _ := restarted.GitRef(context.Background(), publisher.ref("main").refId)
		if ref.Version != 2 || !evsOidEqual(ref.AppliedTip, &c2) || !evsOidEqual(ref.Tip, &c2) {
			t.Fatalf("%s: the record %+v", point, ref)
		}
		if conflicts := device.test.eventsOf(SidecarEventEvsConflict); len(conflicts) != 0 {
			t.Fatalf("%s: conflicts %v", point, conflicts)
		}
	}
}

// The local state's names hold what Name gives, and a stored record reads back equal.
func TestEvsLocalGitRefRecordRoundTrips(t *testing.T) {
	state := &evsLocalState{store: newEvsTestStore(t), repoId: evsTestId("repo")}
	owner, waiting := evsTestId("owner"), evsTestId("source")
	tip, last := EvsGitOid{1}, EvsGitOid{2}
	ref := &EvsGitRef{
		RefId: evsTestId("ref"), Name: []byte("ur/x/feature"), Kind: protocol.EvsRefKind_EVS_REF_OWNED, Mode: protocol.EvsRefMode_EVS_REF_GIT,
		OwnerSidecarId: &owner, Version: 9, Chain: [32]byte{3}, Tip: &tip, Peeled: &tip, TipVersion: 8, AppliedTip: &last,
		LastTip: &last, Base: &protocol.EvsOverlay{RefId: evsTestId("base").Bytes(), Version: 4}, StuckAt: 7,
		Stopped: [][2]uint64{{7, 0}}, Tainted: []EvsTaintedPath{{Epoch: 1, Key: "t"}}, WaitingSource: &waiting, WaitingVersion: 5,
		AppliedOrder: 11, PathEpoch: &protocol.EvsPathEpoch{Current: 2}, SettleStopped: true,
	}
	if err := state.writeGitRef(ref); err != nil {
		t.Fatal(err)
	}
	read, err := state.gitRef(ref.RefId)
	if err != nil {
		t.Fatal(err)
	}
	if read.record().PathEpoch == nil || !bytes.Equal(read.Name, ref.Name) || *read.OwnerSidecarId != owner || read.Version != 9 ||
		!evsOidEqual(read.Tip, &tip) || !evsOidEqual(read.AppliedTip, &last) || read.Base.GetVersion() != 4 ||
		read.StuckAt != 7 || len(read.Tainted) != 1 || *read.WaitingSource != waiting || read.PathEpoch.GetCurrent() != 2 ||
		!read.SettleStopped || read.AppliedOrder != 11 {
		t.Fatalf("read back %+v", read)
	}
}
