//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// The search world's slots, which FS-109's sampler of searches at once holds through each collection (sidecartest's
// search_heap.go): HoldSearchSlots counts the searches of a device's engine that hold a slot and holds the rest.

import (
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// With no search at work no slot is held; a search parked at a record it opens, inside its page, holds one; and once
// it ended every slot is free again, the holds given back.
func TestSearchWorldHoldSearchSlotsCountsASearchInItsPage(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	index, err := sidecar.NewSearchTestWorld(&sidecar.SearchTestWorldArgs{
		RepoId: searchId("slots repo"), RefId: searchId("slots ref"), Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := clock.Now()
	err = index.PushDocuments(ctx, searchId("slots writer"), now, []*sidecar.SearchTestDocument{
		{Path: "notes/harbor.md", Version: 1, Title: "Harbor", Text: "the harbor at noon", Time: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	host := searchHostNamed("desktop")
	inRecord := make(chan struct{})
	goOn := make(chan struct{})
	once := sync.Once{}
	device, err := index.NewDevice(ctx, &sidecar.SearchTestDeviceArgs{
		Settings: host.settings(), Conditions: func() sidecar.SearchConditions { return host.conditions },
		ReadByteCount: 32 * 1024 * 1024,
		OnRecord: func() {
			once.Do(func() {
				close(inRecord)
				<-goOn
			})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	if err := device.Sync(ctx); err != nil {
		t.Fatal(err)
	}

	holderCount, release := device.HoldSearchSlots()
	release()
	if holderCount != 0 {
		t.Fatalf("with no search at work %d searches hold a slot", holderCount)
	}

	searched := make(chan error, 1)
	go func() {
		_, err := device.Search(ctx, &sidecar.SearchRequest{Text: "harbor", Scope: sidecar.SearchCached, Remote: "off"}, 64, nil)
		searched <- err
	}()
	select {
	case <-inRecord:
	case err := <-searched:
		t.Fatalf("the search ended, answering %v, before it opened a record", err)
	case <-time.After(time.Minute):
		t.Fatal("the search opened no record in a minute")
	}
	holderCount, release = device.HoldSearchSlots()
	release()
	close(goOn)
	if err := <-searched; err != nil {
		t.Fatal(err)
	}
	if holderCount != 1 {
		t.Fatalf("with a search parked inside its page %d searches hold a slot", holderCount)
	}

	holderCount, release = device.HoldSearchSlots()
	release()
	if holderCount != 0 {
		t.Fatalf("with the search ended %d searches hold a slot", holderCount)
	}
}
