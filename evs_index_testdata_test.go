// What the index tests share to reach testdata/: vectors and seeds ride in the binary, since the sidecar_http leg's
// Worker has no file system, and byte-equal on every leg means that one too. Setting testWriteVectorsEnvironment
// rewrites them instead, as after a format change before the freeze, and a run without it holds them to what the code
// now builds.

package sidecar

import (
	"bytes"
	"embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testWriteVectorsEnvironment = "SIDECAR_WRITE_VECTORS"

//go:embed testdata/index testdata/fuzz/FuzzIndexNormalize
var testIndexFiles embed.FS

// Writes a vector file, for the rewrite mode alone.
func testWriteJson(t *testing.T, path string, value any) {
	encoded, err := json.MarshalIndent(value, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Holds one seed file to what it should say. Seeds are files so a -fuzz run keeps them and a crasher joins them, and
// generated so a format change cannot leave one stale, refused for the wrong reason.
func testCheckCorpusFile(t testing.TB, target string, name string, lines ...string) {
	path := "testdata/fuzz/" + target + "/" + name
	corpus := []byte("go test fuzz v1\n" + strings.Join(lines, "\n") + "\n")
	if os.Getenv(testWriteVectorsEnvironment) != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, corpus, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	held, err := testIndexFiles.ReadFile(path)
	if err != nil {
		t.Errorf("%s: %v; %s=1 writes it", path, err, testWriteVectorsEnvironment)
		return
	}
	if !bytes.Equal(held, corpus) {
		t.Errorf("%s is stale; %s=1 rewrites it", path, testWriteVectorsEnvironment)
	}
}
