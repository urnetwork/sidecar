//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

package sidecartest

import (
	"bytes"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A removed bucket shard is absent from the live tree. The signed history still names its bytes in its first
// life after the shard is removed and after a new shard takes the name. A truncated walk keeps completion open.
func TestEvsIndexRetainedWalksARemovedShardEndToEnd(t *testing.T) {
	world := newVersionlessWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	w := world.format2Device("w")
	ctx := world.ctx
	const path = ".ur-index/i1/b/0/s/0"
	write := func(device *epochDevice, content []byte) *sidecar.EvsWritePathsResult {
		t.Helper()
		file := &sidecar.EvsPathWrite{Path: path, Options: &sidecar.EvsWriteOptions{Reserved: sidecar.EvsReservedIndex}}
		if content == nil {
			file.Remove = true
		} else {
			file.Content = bytes.NewReader(content)
		}
		result, err := device.repo.WritePaths(ctx, &sidecar.EvsWritePathsArgs{Writes: []*sidecar.EvsPathWrite{file}})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	contents := []byte("the first bucket shard")
	created := write(w, contents)
	write(w, nil)
	check := func(device *epochDevice, wantComplete bool) {
		t.Helper()
		listed, complete, err := sidecar.SearchTestEvsRetainedVersions(ctx, device.repo, nil)
		if err != nil || complete != wantComplete {
			t.Fatalf("retained history complete %t, want %t: %v", complete, wantComplete, err)
		}
		if !wantComplete {
			return
		}
		for _, file := range listed {
			if file.Path == path && file.CommitVersion == created.Version {
				if file.Readable && (file.ReadErr != nil || !bytes.Equal(file.Plaintext, contents)) {
					t.Fatalf("the first life: %q, %v", file.Plaintext, file.ReadErr)
				}
				return
			}
		}
		t.Fatalf("the retained versions omit %s at commit %d", path, created.Version)
	}
	check(w, true)
	write(w, []byte("a new bucket shard"))
	check(w, true)
	limited := world.device("v", func(settings *sidecar.EvsSettings) { settings.HistoryVersionCount = 1 })
	limited.client.EnableFormat2Reader()
	check(limited, false)
}

func TestEvsIndexRetainedUsesTheVerifiedInboxRoleOfAGeneralRepo(t *testing.T) {
	for _, inbox := range []protocol.RepoInbox{protocol.RepoInbox_REPO_INBOX_NONE, protocol.RepoInbox_REPO_INBOX_GROUP, protocol.RepoInbox_REPO_INBOX_ADMIN} {
		world := newVersionlessWorldWithInbox(t, protocol.RepoKind_REPO_KIND_GENERAL, inbox)
		device := world.format2Device("w")
		file := &sidecar.EvsPathWrite{
			Path: ".ur-index/i1/b/0/s/0", Content: bytes.NewReader([]byte("index shard")),
			Options: &sidecar.EvsWriteOptions{Reserved: sidecar.EvsReservedIndex},
		}
		if _, err := device.repo.WritePaths(world.ctx, &sidecar.EvsWritePathsArgs{Writes: []*sidecar.EvsPathWrite{file}}); err != nil {
			t.Fatal(err)
		}
		_, complete, err := sidecar.SearchTestEvsRetainedVersions(world.ctx, device.repo, nil)
		if err != nil || complete != (inbox != protocol.RepoInbox_REPO_INBOX_NONE) {
			t.Fatalf("%s: retained proof complete %t, %v", inbox, complete, err)
		}
	}
}
