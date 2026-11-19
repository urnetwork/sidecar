package main

// `ur status`'s index line (D-QUOTA-10; QUOTA-M10-01): under each network, the search index's share of its storage as
// the Sidecar last read it, apart from content, with what the read could not cover; nothing before a read.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

func TestUrStatusShowsTheIndexShareUnderItsNetwork(t *testing.T) {
	readAt := time.Date(2026, time.November, 19, 6, 30, 0, 0, time.UTC)
	shared := sidecar.NewId()
	unread := sidecar.NewId()
	none := sidecar.NewId()
	reply := &urStatusReply{Instance: "test", KeyStore: "memory", Networks: []urNetworkStatus{
		{NetworkId: shared, State: "online", IndexShare: &sidecar.SidecarIndexShare{RepoCount: 3, FileCount: 12, ByteCount: 40960, ReadAt: readAt}},
		{NetworkId: unread, State: "online", IndexShare: &sidecar.SidecarIndexShare{RepoCount: 2, UnreadRepoCount: 1, FileCount: 1, ByteCount: 512, ReadAt: readAt}},
		{NetworkId: none, State: "online"},
	}}
	// the reply crosses the daemon's socket as JSON, the share with it
	encoded, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &urStatusReply{}
	if err := json.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	cli, out, _ := newTestUrCli("")
	printUrStatus(cli, decoded)
	shown := out.String()
	for _, want := range []string{
		"  index:    40960 bytes in 12 files across 3 repos, read 2026-11-19T06:30:00Z\n",
		"  index:    512 bytes in 1 files across 2 repos, 1 of them unread, read 2026-11-19T06:30:00Z\n",
	} {
		if !strings.Contains(shown, want) {
			t.Fatalf("ur status printed:\n%s\nwithout %q", shown, want)
		}
	}
	if count := strings.Count(shown, "  index:"); count != 2 {
		t.Fatalf("%d index lines for two networks with a share:\n%s", count, shown)
	}
}
