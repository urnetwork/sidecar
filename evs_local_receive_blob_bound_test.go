//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// The local tier's blob bound is EvsSettings.ReceiveBlobMaxByteCount (QD-702), §11.19's 2 GiB by default, read where
// pre-receive judges a pushed commit's blobs and where an evs_write at a git-mode tip takes its content.

package sidecar

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A blob one byte past ReceiveBlobMaxByteCount is refused by pre-receive, naming its size and the bound, and nothing
// reaches evs; a blob at the bound lands. An evs_write at the tip past it is refused before anything is read.
func TestEvsLocalReceiveRefusesABlobPastItsBound(t *testing.T) {
	if DefaultEvsSettings().ReceiveBlobMaxByteCount != EvsFileMaxByteCount {
		t.Fatalf("the default bound is not §11.19's file bound")
	}
	publisher := newEvsTestPublisher(t)
	receiver := newEvsTestReceiver(t, publisher)
	publisher.writer.test.client.settings.ReceiveBlobMaxByteCount = 16
	dir := receiver.clone()
	receiver.commit(dir, map[string]string{"a.txt": strings.Repeat("x", 17)})
	out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/main")
	if ok || !strings.Contains(out, "brings a blob of 17 bytes, past the 16 a file may hold") {
		t.Fatalf("a blob past the bound: %v %s", ok, out)
	}
	if version := receiver.headVersion("main"); version != 0 {
		t.Fatalf("evs took a refused push: %d", version)
	}
	other := receiver.clone()
	receiver.commit(other, map[string]string{"a.txt": strings.Repeat("y", 16)})
	if out, ok := receiver.push(other, "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("a blob at the bound: %s", out)
	}
	if version := receiver.headVersion("main"); version != 1 {
		t.Fatalf("the push at the bound: %d", version)
	}

	writer := newEvsTestTipWriter(t)
	writer.publisher.writer.test.client.settings.ReceiveBlobMaxByteCount = 16
	_, err := writer.repo.WriteAtTip(context.Background(), &EvsWriteAtTipArgs{
		Path: "big.txt", Content: []byte(strings.Repeat("z", 17)), Message: "past the bound", AgentLabel: "agent one",
	})
	if !errors.Is(err, ErrEvsWriteInvalid) {
		t.Fatalf("an evs_write past the bound: %v", err)
	}
}
