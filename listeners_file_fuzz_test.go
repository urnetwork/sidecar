//go:build !ios_extension && !sidecar_http && !js

// FuzzListenersFile (LSTN-M13-01): ParseListenersFile over any bytes is total and bounded, and what it takes marshals,
// reads back equal and marshals again to the same bytes, every description in it one cleaning leaves as it is and no
// address of its host in it. Seeded from testdata/listeners/file/, §26.6's example among them. Off the js leg, whose
// Worker has no file system for the seeds.

package sidecar

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"
)

func FuzzListenersFile(f *testing.F) {
	directory := filepath.Join("testdata", "listeners", "file")
	seeds, err := os.ReadDir(directory)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range seeds {
		data, err := os.ReadFile(filepath.Join(directory, seed.Name()))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	writer, err := ParseId(testListenersFileSidecar)
	if err != nil {
		f.Fatal(err)
	}
	settings := DefaultListenersSettings()
	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := ParseListenersFile(data, writer, settings)
		if err != nil {
			if file != nil {
				t.Fatalf("a refusal answered a file")
			}
			return
		}
		if settings.FileMaxByteCount < len(data) || settings.EntryMaxCount < len(file.GetEntries()) {
			t.Fatalf("a file past its caps read: %d bytes, %d entries", len(data), len(file.GetEntries()))
		}
		for _, entry := range file.GetEntries() {
			if bind := entry.GetBind(); bind != "" && bind != listenersBindAnyIpv4 && bind != listenersBindAnyIpv6 {
				t.Fatalf("an address read: %q", bind)
			}
			if desc := entry.GetDesc(); ListenersCleanDescription(desc, settings.DescriptionMaxCharCount) != desc {
				t.Fatalf("a description cleaning changes read: %q", desc)
			}
		}
		marshalled, err := MarshalListenersFile(file, settings)
		if err != nil {
			t.Fatalf("a file read does not write: %v", err)
		}
		again, err := ParseListenersFile(marshalled, writer, settings)
		if err != nil || !proto.Equal(again, file) {
			t.Fatalf("%s reads back as %v, %v", marshalled, again, err)
		}
		stable, err := MarshalListenersFile(again, settings)
		if err != nil || !bytes.Equal(stable, marshalled) {
			t.Fatalf("a re-marshal moved: %s and %s, %v", marshalled, stable, err)
		}
	})
}
