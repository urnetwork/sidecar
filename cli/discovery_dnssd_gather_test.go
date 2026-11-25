// The macOS gatherer's state on every platform (§17.7.1; owner decision 778): a browse's instance is resolved on its
// link and its target looked up once however many instances point at it; a report holds only instances of listed
// types whose target has an address, own where an address is this host's, each expiring ReportTtl on; a move of
// target, a lost address and a lost instance each change the report and end what nothing needs; a reply from another
// link or of an unlisted type is dropped; the bounds hold; and a LocalOnly link's instances are marked so.

package main

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

// A state whose resolves and lookups the test records, running and ended.
type testDnsSdGather struct {
	state    *urDnsSdGatherState
	resolves map[urDnsSdInstanceKey]bool
	lookups  map[urDnsSdHostKey]bool
}

func newTestDnsSdGather(settings *urDnsSdGatherSettings, types []string) *testDnsSdGather {
	self := &testDnsSdGather{resolves: map[urDnsSdInstanceKey]bool{}, lookups: map[urDnsSdHostKey]bool{}}
	self.state = newUrDnsSdGatherState(settings, types, func(key urDnsSdInstanceKey, instance *urDnsSdInstance) func() {
		self.resolves[key] = true
		return func() { delete(self.resolves, key) }
	}, func(key urDnsSdHostKey) func() {
		self.lookups[key] = true
		return func() { delete(self.lookups, key) }
	})
	return self
}

func TestDnsSdGatherStateFollowsBrowseResolveAndLookup(t *testing.T) {
	gather := newTestDnsSdGather(defaultUrDnsSdGatherSettings(), []string{"_smb._tcp", "_rfb._tcp"})
	state := gather.state
	now := time.Unix(1_800_000_000, 0)
	local := []netip.Addr{netip.MustParseAddr("192.168.1.10")}

	state.browsed(4, 4, true, "NAS Files", "_smb._tcp.", "local.")
	state.browsed(4, 4, true, "NAS Screen", "_RFB._tcp.", "local.")
	state.browsed(4, 4, true, "Printer", "_ipp._tcp.", "local.")
	state.browsed(4, 7, true, "Elsewhere", "_smb._tcp.", "local.")
	state.browsed(5, 5, true, "Desk", "_smb._tcp.", "local.")
	if len(gather.resolves) != 3 {
		t.Fatalf("resolving %v", gather.resolves)
	}
	nasFiles := urDnsSdInstanceKey{index: 4, name: "nas files", service: "_smb._tcp"}
	nasScreen := urDnsSdInstanceKey{index: 4, name: "nas screen", service: "_rfb._tcp"}
	desk := urDnsSdInstanceKey{index: 5, name: "desk", service: "_smb._tcp"}
	state.resolved(nasFiles, "NAS.local.", 445, []byte("\x04a=bc"))
	state.resolved(nasScreen, "nas.local", 5900, nil)
	state.resolved(desk, "Desk.local.", 445, nil)
	nas := urDnsSdHostKey{index: 4, host: "nas.local."}
	if len(gather.lookups) != 2 || !gather.lookups[nas] {
		t.Fatalf("looking up %v", gather.lookups)
	}
	// nothing reports before an address
	if gathered := state.gathered(now, local); len(gathered) != 0 {
		t.Fatalf("reported %d with no address", len(gathered))
	}
	state.addressed(nas, true, netip.MustParseAddr("192.168.1.20"))
	state.addressed(nas, true, netip.MustParseAddr("fe80::1"))
	state.addressed(urDnsSdHostKey{index: 5, host: "desk.local."}, true, netip.MustParseAddr("192.168.1.10"))
	if !state.changed {
		t.Fatal("an address changed nothing")
	}
	gathered := state.gathered(now, local)
	names := []string{}
	for _, item := range gathered {
		names = append(names, item.Service+" "+item.Name)
		if !item.Expires.Equal(now.Add(120*time.Second)) || item.LocalOnly || item.PointToPoint {
			t.Fatalf("%q expires %v local-only %v", item.Name, item.Expires, item.LocalOnly)
		}
		switch item.Name {
		case "NAS Files":
			if item.Port != 445 || string(item.Txt) != "\x04a=bc" || item.HostName != "nas.local." || item.Own ||
				!slices.Equal(item.Addresses, []netip.Addr{netip.MustParseAddr("192.168.1.20")}) {
				t.Fatalf("NAS Files reported %+v", item)
			}
		case "Desk":
			if !item.Own {
				t.Fatal("this host's own instance is not own")
			}
		}
	}
	if !slices.Equal(names, []string{"_rfb._tcp NAS Screen", "_smb._tcp Desk", "_smb._tcp NAS Files"}) {
		t.Fatalf("reported %v", names)
	}
	if state.changed {
		t.Fatal("a report left the state changed")
	}

	// one instance goes: its target's lookup stays for the other
	state.browsed(4, 4, false, "NAS Screen", "_rfb._tcp.", "local.")
	if gather.resolves[nasScreen] || !gather.lookups[nas] || !state.changed {
		t.Fatalf("after one loss resolving %v looking up %v", gather.resolves, gather.lookups)
	}
	// the other moves to a new target: the old lookup ends and a new one starts
	state.resolved(nasFiles, "nas-2.local.", 445, []byte("\x04a=bc"))
	if gather.lookups[nas] || !gather.lookups[urDnsSdHostKey{index: 4, host: "nas-2.local."}] {
		t.Fatalf("after the move looking up %v", gather.lookups)
	}
	if gathered := state.gathered(now, local); len(gathered) != 1 || gathered[0].Name != "Desk" {
		t.Fatalf("before the new target's address reported %d", len(gathered))
	}
	// the address goes: the instance leaves the report
	state.addressed(urDnsSdHostKey{index: 5, host: "desk.local."}, false, netip.MustParseAddr("192.168.1.10"))
	if gathered := state.gathered(now, local); len(gathered) != 0 {
		t.Fatalf("with no address reported %d", len(gathered))
	}
	// a link goes, with everything on it
	state.dropLink(4)
	if len(gather.lookups) != 1 || len(gather.resolves) != 1 {
		t.Fatalf("after the link went resolving %v looking up %v", gather.resolves, gather.lookups)
	}
	state.clear()
	if len(gather.lookups) != 0 || len(gather.resolves) != 0 {
		t.Fatalf("after clear resolving %v looking up %v", gather.resolves, gather.lookups)
	}
}

func TestDnsSdGatherStateBoundsAndMarksLocalOnly(t *testing.T) {
	settings := defaultUrDnsSdGatherSettings()
	settings.InstanceCount = 2
	gather := newTestDnsSdGather(settings, []string{"_smb._tcp"})
	state := gather.state
	for _, name := range []string{"a", "b", "c"} {
		state.browsed(urDnsSdLocalOnlyIndex, urDnsSdLocalOnlyIndex, true, name, "_smb._tcp.", "local.")
	}
	if len(gather.resolves) != 2 {
		t.Fatalf("past the bound resolving %d", len(gather.resolves))
	}
	state.resolved(urDnsSdInstanceKey{index: urDnsSdLocalOnlyIndex, name: "a", service: "_smb._tcp"}, "one.local.", 445, nil)
	state.resolved(urDnsSdInstanceKey{index: urDnsSdLocalOnlyIndex, name: "b", service: "_smb._tcp"}, "two.local.", 445, nil)
	// a third target would pass the bound; a second instance at a held target does not
	state.browsed(urDnsSdLocalOnlyIndex, urDnsSdLocalOnlyIndex, false, "b", "_smb._tcp.", "local.")
	state.browsed(urDnsSdLocalOnlyIndex, urDnsSdLocalOnlyIndex, true, "c", "_smb._tcp.", "local.")
	state.resolved(urDnsSdInstanceKey{index: urDnsSdLocalOnlyIndex, name: "c", service: "_smb._tcp"}, "one.local.", 445, nil)
	state.addressed(urDnsSdHostKey{index: urDnsSdLocalOnlyIndex, host: "one.local."}, true, netip.MustParseAddr("100.80.0.9"))
	gathered := state.gathered(time.Unix(0, 0), nil)
	if len(gathered) != 2 || !gathered[0].LocalOnly || !gathered[1].LocalOnly {
		t.Fatalf("reported %+v", gathered)
	}
}
