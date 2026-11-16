package main

// ur lfs-agent's daemon side (EVS2-M10-25): a store's failures cross the socket as a kind and a message and come back as
// the root's errors, a pruned object keeping when its prune committed; --repo takes id:<repo_id> alone or after
// git-remote-ur's network; and the methods refuse, saying so, while the daemon builds no evs client.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

func TestUrLfsReplyCarriesTheStoresFailures(t *testing.T) {
	oid, err := sidecar.EvsLfsOidDecodeHex(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	removedAt := time.Date(2026, time.November, 1, 2, 3, 4, 0, time.UTC)
	cases := []struct {
		err  error
		want error
	}{
		{err: nil, want: nil},
		{err: &sidecar.EvsLfsMissingError{Oid: oid, RemovedAt: removedAt}, want: sidecar.ErrEvsLfsObjectMissing},
		{err: &sidecar.EvsLfsTooLargeError{Oid: oid, Size: 3 * 1024 * 1024 * 1024}, want: sidecar.ErrEvsFileTooLarge},
		{err: sidecar.ErrEvsLfsObjectInvalid, want: sidecar.ErrEvsLfsObjectInvalid},
	}
	for i, c := range cases {
		reply := urLfsReplyOf(c.err)
		encoded, err := json.Marshal(reply)
		if err != nil {
			t.Fatal(err)
		}
		decoded := &urLfsReply{}
		if err := json.Unmarshal(encoded, decoded); err != nil {
			t.Fatal(err)
		}
		got := decoded.err(oid)
		if (c.want == nil) != (got == nil) || (c.want != nil && !errors.Is(got, c.want)) {
			t.Errorf("case %d: %v came back as %v", i, c.err, got)
		}
	}
	var missing *sidecar.EvsLfsMissingError
	if err := urLfsReplyOf(&sidecar.EvsLfsMissingError{Oid: oid, RemovedAt: removedAt}).err(oid); !errors.As(err, &missing) || !missing.RemovedAt.Equal(removedAt) {
		t.Fatalf("a pruned object's time: %v", err)
	}
}

func TestUrLfsRepoIdTakesBothForms(t *testing.T) {
	repoId := sidecar.NewId()
	for _, repo := range []string{"id:" + repoId.String(), "synthetic-net/id:" + repoId.String()} {
		got, err := urLfsRepoId(repo)
		if err != nil || got != repoId {
			t.Errorf("%s: %v %v", repo, got, err)
		}
	}
	if _, err := urLfsRepoId("plain-name"); err == nil {
		t.Error("a repo by name before names exist")
	}
}

// With no evs client the methods refuse, saying so.
func TestUrLfsMethodsRefuseWithoutAnEvsClient(t *testing.T) {
	saved := urDaemonEvsClient
	urDaemonEvsClient = nil
	defer func() { urDaemonEvsClient = saved }()
	methods := urLfsMethods(&urDaemonNetwork{})
	if len(methods) != 2 {
		t.Fatalf("%d methods", len(methods))
	}
	params, _ := json.Marshal(&urLfsParams{Repo: "id:" + sidecar.NewId().String(), Oid: strings.Repeat("ab", 32), Size: 1, Path: "/x"})
	for _, method := range methods {
		if _, err := method.Handler(context.Background(), &sidecar.DaemonCall{Params: params}); !errors.Is(err, errUrNoEvsClient) {
			t.Errorf("%s without an evs client: %v", method.Name, err)
		}
	}
}
