//go:build !ios_extension

// EvsSettings.MaxFormat (EVS2-M10-30; FS-72's format-1 client): a client held to format 1 writes and reads as a
// format-1 one whatever the gate says, so this code stands for a format-1 client on T2. It writes no versionless
// version, refusing an explicit "off" before anything is sent and writing versioning 0 otherwise, and it refuses a
// versionless version it reads as needing format 2, while the same client at format 2 reads it.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

func TestEvsMaxFormatOneWritesAndReadsAsFormatOne(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.server.format2 = true
	client := writer.test.client
	client.SetFormat2Source(func() bool { return true })
	client.EnableFormat2Reader()
	if !client.Format2Admitted() {
		t.Fatal("a format-2 client in the gate is not admitted")
	}
	client.settings.MaxFormat = 1
	if on, known := client.Format2Gate(); !known || !on {
		t.Fatal("the format-1 binary lost the network's format-2 rollout")
	}
	if client.Format2Admitted() {
		t.Fatal("a client held to format 1 is admitted")
	}
	writer.server.know("a.txt")
	_, err := writer.repo.Write(context.Background(), &EvsWriteArgs{Path: "a.txt", Content: bytes.NewReader([]byte("off")), Size: 3, Versioning: EvsVersioningOff})
	if !errors.Is(err, ErrEvsFormatUnsupported) || len(writer.server.postedStatements) != 0 {
		t.Fatalf("versioning off at format 1: %v", err)
	}
	if _, err := writer.write(t, "a.txt", []byte("kept")); err != nil {
		t.Fatal(err)
	}
	if entry := writer.entry(t, "a.txt"); entry.GetVersioning() != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) {
		t.Fatalf("a format-1 client wrote versioning %d", entry.GetVersioning())
	}
	// a versionless version another writer committed: refused as needing format 2 at format 1, read at format 2
	evsTestWriteVersionless(writer.world, "v.bin", []byte("versionless content"), false)
	reader := writer.world.reader(t, evsTestId("format-1 reader"))
	reader.client.EnableFormat2Reader()
	reader.client.settings.MaxFormat = 1
	if _, err := reader.client.Repo(writer.world.repoId).ReadHead(context.Background(), &EvsReadArgs{Path: "v.bin"}, &bytes.Buffer{}); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Fatalf("a versionless version at format 1: %v", err)
	}
	reader.client.settings.MaxFormat = 2
	out := &bytes.Buffer{}
	if _, err := reader.client.Repo(writer.world.repoId).ReadHead(context.Background(), &EvsReadArgs{Path: "v.bin"}, out); err != nil || out.String() != "versionless content" {
		t.Fatalf("the same version at format 2: %q %v", out.String(), err)
	}
}
