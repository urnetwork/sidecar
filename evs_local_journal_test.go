//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The journal's record and the hook seam's refusals (DESIGN-DETAILS 8.2.8): an update's states and an attempt's SENT,
// settle's queued reading, a journal with no work removed; a quarantine the relay names outside the mount's bare
// repository refused before any git runs on it; and a relay with no session exiting 1, so a hook never fails open.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// An update's states through an attempt, queued's reading of the newest LOCAL or SENT update, and a journal with no
// work removed from the store.
func TestEvsJournalRecordStates(t *testing.T) {
	state := &evsLocalState{store: newEvsTestStore(t), repoId: evsTestId("repo")}
	refId := evsTestId("ref")
	at := time.Date(2026, time.November, 11, 0, 0, 0, 0, time.UTC)
	c1, c2 := EvsGitOid{1}, EvsGitOid{2}
	journal := &EvsJournalRef{RefName: []byte("ur/x/work")}
	first := journal.add(nil, &c1, EvsJournalLocal, EvsJournalKindQueue, at)
	second := journal.add(&c1, &c2, EvsJournalLocal, EvsJournalKindQueue, at)
	if first.Seq != 1 || second.Seq != 2 || !journal.queued(&c2) || journal.queued(&c1) {
		t.Fatalf("queued %+v", journal)
	}
	journal.addAttempt(&EvsJournalAttempt{PushId: evsTestId("push"), BaseVersion: 3, New: c2.String()})
	for _, update := range journal.Updates {
		if update.State != EvsJournalSent {
			t.Fatalf("an update the attempt covers is %d", update.State)
		}
	}
	if err := state.writeJournal(refId, journal); err != nil {
		t.Fatal(err)
	}
	read, err := state.journal(refId)
	if err != nil || len(read.Updates) != 2 || len(read.Attempts) != 1 || read.Attempts[0].BaseVersion != 3 || !bytes.Equal(read.RefName, journal.RefName) {
		t.Fatalf("read back %+v %v", read, err)
	}
	read.deleteUpdate(1)
	read.deleteUpdate(2)
	if len(read.Attempts) != 0 {
		t.Fatal("an attempt outlived every update it covers")
	}
	if err := state.writeJournal(refId, read); err != nil {
		t.Fatal(err)
	}
	if refIds, err := state.journalRefIds(); err != nil || len(refIds) != 0 {
		t.Fatalf("a journal with no work stands: %v %v", refIds, err)
	}
}

// pre-receive's relayed object directories must lie inside the mount's bare repository; one outside is refused before
// any git runs on it, an alternate outside as well.
func TestEvsLocalQuarantineMustLieInTheMount(t *testing.T) {
	bare := t.TempDir()
	mount := &EvsLocalRepo{BareDir: bare}
	inside := filepath.Join(bare, "objects", "tmp_objdir-incoming-x")
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	header := &EvsGitHookHeader{ObjectDirectory: inside, AlternateObjectDirectories: filepath.Join(bare, "objects")}
	if env, err := mount.quarantineEnvironment(header); err != nil || len(env) != 2 {
		t.Fatalf("the repository's own quarantine: %v %v", env, err)
	}
	for _, header := range []*EvsGitHookHeader{
		{ObjectDirectory: t.TempDir()},
		{ObjectDirectory: filepath.Join(bare, "..")},
		{ObjectDirectory: bare, AlternateObjectDirectories: t.TempDir()},
		{ObjectDirectory: "objects"},
		{ObjectDirectory: filepath.Join(bare, "absent")},
	} {
		if _, err := mount.quarantineEnvironment(header); !errors.Is(err, ErrEvsGitHookInvalid) {
			t.Errorf("%+v: %v", header, err)
		}
	}
}

// A relay with no session, or no daemon, exits 1 with a line saying why: a hook never fails open.
func TestEvsGitHookRelayFailsClosed(t *testing.T) {
	stderr := &bytes.Buffer{}
	code := EvsGitHookRelay(context.Background(), &EvsGitHookRelayArgs{
		Hook: EvsGitHookPreReceive, Getenv: func(string) string { return "" },
		Dial:  func(ctx context.Context) (io.ReadWriteCloser, error) { return nil, errors.New("no daemon") },
		Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: stderr,
	})
	if code != 1 || !strings.Contains(stderr.String(), "no receive session") {
		t.Fatalf("no session: %d %q", code, stderr.String())
	}
	stderr.Reset()
	code = EvsGitHookRelay(context.Background(), &EvsGitHookRelayArgs{
		Hook: EvsGitHookPreReceive, Getenv: func(name string) string { return "session" },
		Dial:  func(ctx context.Context) (io.ReadWriteCloser, error) { return nil, errors.New("no daemon") },
		Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: stderr,
	})
	if code != 1 || !strings.Contains(stderr.String(), "did not answer") {
		t.Fatalf("no daemon: %d %q", code, stderr.String())
	}
}
