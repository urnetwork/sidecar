// A directory a client's own overlapping creations wrote (the e2e-client-origins bug's listings; evs_epoch_read.go's
// evsBelowReadRecord): its version falls when a delta its writer based on an older table commits last, and it reads
// as it stands, while a rollback of it to a delta that committed before the one recorded is still refused.

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// A writer of a world whose requests go through wrap's handler around the push stand-in, as newEvsTestWriter's go to
// the stand-in itself.
func newEvsTestWriterThrough(t *testing.T, wrap func(server http.Handler) http.Handler) *evsTestWriter {
	world := newEvsTestWorld(t)
	server := newEvsTestPushServer(t, world)
	gkm := newEvsTestWriteGkm()
	test := newEvsTestClient(t, wrap(server), newEvsTestStore(t))
	test.client.args.Gkm = gkm
	test.client.args.Config = func() GkmAuthView { return world.config }
	test.client.args.Sign = world.signer.sign
	identity := &SidecarIdentity{NetworkId: testNetworkId, SidecarId: world.signer.sidecarId, ClientId: evsTestId("world client")}
	test.client.args.Identity = func() *SidecarIdentity { return identity }
	return &evsTestWriter{world: world, server: server, gkm: gkm, test: test, repo: test.client.Repo(world.repoId)}
}

// The names a listing gives, in order.
func evsTestListedNames(listing *EvsListing) string {
	names := []string{}
	for _, entry := range listing.Entries {
		names = append(names, string(entry.Name))
	}
	return strings.Join(names, ",")
}

// One client's creations in a directory at once: one write's push reaches evs after two later writes', its delta on
// the table it read before theirs, which evs merges with no path-level CAS (§11.7's directory row), so the
// directory's newest version falls below the one the client listed between them. The client lists the directory as
// it stands, every name there, with no alarm: a directory is held to where its newest delta committed, which only
// rises. Before the fix the listing was refused as tampering, as the e2e's verification listings were after its
// shared-client bursts. A rollback to a delta that committed before the one the client recorded is still refused and
// alarmed.
func TestEvsOverlappingCreationsLeaveTheirDirectoryReadable(t *testing.T) {
	var hold *evsTestHold
	writer := newEvsTestWriterThrough(t, func(server http.Handler) http.Handler {
		hold = &evsTestHold{handler: server}
		return hold
	})
	ctx := context.Background()
	if _, err := writer.write(t, "d/a.txt", []byte("a")); err != nil {
		t.Fatal(err)
	}
	held := hold.arm(evsTestIsPush, true)
	t.Cleanup(held.let)
	writes := make(chan error, 1)
	go func() {
		_, err := writer.write(t, "d/x.txt", []byte("x"))
		writes <- err
	}()
	<-held.held
	for _, name := range []string{"y", "z"} {
		if _, err := writer.write(t, "d/"+name+".txt", []byte(name)); err != nil {
			t.Fatal(err)
		}
	}
	listing, err := writer.repo.List(ctx, &EvsReadArgs{Path: "d"})
	if err != nil || evsTestListedNames(listing) != "a.txt,y.txt,z.txt" {
		t.Fatalf("the listing between: %v %v", listing, err)
	}
	listed := writer.entry(t, "d").GetVersion()
	held.let()
	if err := <-writes; err != nil {
		t.Fatalf("the held write: %v", err)
	}
	if fell := writer.entry(t, "d").GetVersion(); listed <= fell {
		t.Fatalf("the directory's version did not fall: %d then %d", listed, fell)
	}
	listing, err = writer.repo.List(ctx, &EvsReadArgs{Path: "d"})
	if err != nil || evsTestListedNames(listing) != "a.txt,x.txt,y.txt,z.txt" {
		t.Fatalf("the listing after: %v %v", listing, err)
	}
	if alarms := writer.test.alarms(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
	// evs serving the directory's first version, which committed before the one recorded: a rollback
	writer.world.stateLock.Lock()
	writer.world.serveVersion["d"] = 1
	writer.world.stateLock.Unlock()
	if _, err := writer.repo.List(ctx, &EvsReadArgs{Path: "d"}); !errors.Is(err, ErrEvsEntryRefused) {
		t.Fatalf("the rolled-back directory: %v", err)
	}
	tampers := writer.test.eventsOf(SidecarEventEvsAlarm)
	if len(tampers) != 1 || tampers[0].EvsAlarm != SidecarEvsAlarmTamper {
		t.Errorf("alarms %v", tampers)
	}
}
