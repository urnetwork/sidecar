//go:build !js

package sidecar

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// A backend over a new directory, which it names too.
func newTestOsBackend(t *testing.T) (SidecarStoreBackend, string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "state")
	backend, err := NewSidecarOsBackend(directory)
	if err != nil {
		t.Fatal(err)
	}
	return backend, directory
}

func TestOsBackendRoundTrip(t *testing.T) {
	backend, directory := newTestOsBackend(t)
	putBackendFile(t, backend, "net/a/b/file", []byte("synthetic"))
	if content := readBackend(t, backend, "net/a/b/file"); string(content) != "synthetic" {
		t.Errorf("content %q", content)
	}
	if _, err := os.Stat(filepath.Join(directory, "net", "a", "b", "file")); err != nil {
		t.Error(err)
	}
	putBackendFile(t, backend, "net/a/b/file", []byte("replaced"))
	if content := readBackend(t, backend, "net/a/b/file"); string(content) != "replaced" {
		t.Errorf("content %q", content)
	}
	if err := backend.Remove("net/a/b/file"); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Open("net/a/b/file"); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("err %v", err)
	}
	if err := backend.Remove("net/a/b/file"); err != nil {
		t.Errorf("removing nothing: %v", err)
	}
}

// Only a file that is not there is absent. A directory where a file should be is a fault.
func TestOsBackendTellsAbsentFromAFault(t *testing.T) {
	backend, directory := newTestOsBackend(t)
	if _, err := backend.Open("nothing"); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("err %v", err)
	}
	if err := os.Mkdir(filepath.Join(directory, "unlock.wrap"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := readBackendFile(backend, "unlock.wrap", 1024)
	if !errors.Is(err, ErrSidecarStoreFailed) || errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("err %v", err)
	}
}

// An error carries the cause and no path (I-13).
func TestOsBackendErrorsCarryNoPath(t *testing.T) {
	backend, directory := newTestOsBackend(t)
	if err := os.Mkdir(filepath.Join(directory, "secretname"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := readBackendFile(backend, "secretname", 1024)
	if err == nil {
		t.Fatal("read a directory")
	}
	if strings.Contains(err.Error(), "secretname") {
		t.Errorf("err %v", err)
	}
}

func TestOsBackendKeepsItsFilesToTheUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows has no mode bits to read")
	}
	backend, directory := newTestOsBackend(t)
	putBackendFile(t, backend, "net/a/file", []byte("synthetic"))
	for path, want := range map[string]os.FileMode{
		directory:                                    0o700,
		filepath.Join(directory, "net"):              0o700,
		filepath.Join(directory, "net", "a"):         0o700,
		filepath.Join(directory, "net", "a", "file"): 0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != want {
			t.Errorf("%s: mode %o", path, mode)
		}
	}
}

// A temp file shows at no path and in no listing, and a sweep takes what a kill left.
func TestOsBackendKeepsTempFilesOutOfSight(t *testing.T) {
	backend, directory := newTestOsBackend(t)
	putBackendFile(t, backend, "file", []byte("synthetic"))
	left, err := backend.CreateTemp()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := left.Write([]byte("left by a kill")); err != nil {
		t.Fatal(err)
	}
	entries, err := backend.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "file" {
		t.Errorf("entries %+v", entries)
	}
	if err := backend.RemoveTemp(); err != nil {
		t.Fatal(err)
	}
	remaining, err := os.ReadDir(filepath.Join(directory, osBackendTempDirectoryName))
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Errorf("%d temp files remain", len(remaining))
	}
}

func TestOsBackendDiscardDropsTheFile(t *testing.T) {
	backend, directory := newTestOsBackend(t)
	file, err := backend.CreateTemp()
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Discard(); err != nil {
		t.Fatal(err)
	}
	if err := file.Discard(); err != nil {
		t.Errorf("a second discard: %v", err)
	}
	remaining, err := os.ReadDir(filepath.Join(directory, osBackendTempDirectoryName))
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Errorf("%d temp files remain", len(remaining))
	}
}

// A renamed file stays: the writer's deferred Discard must not reach it.
func TestOsBackendDiscardAfterRenameKeepsTheFile(t *testing.T) {
	backend, _ := newTestOsBackend(t)
	file, err := backend.CreateTemp()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	if err := commitBackendFile(backend, file, "file"); err != nil {
		t.Fatal(err)
	}
	if err := file.Discard(); err != nil {
		t.Fatal(err)
	}
	if content := readBackend(t, backend, "file"); string(content) != "synthetic" {
		t.Errorf("content %q", content)
	}
}

func TestOsBackendListsByPrefix(t *testing.T) {
	backend, _ := newTestOsBackend(t)
	for _, path := range []string{"net/a/evs/one", "net/a/evs/two", "net/a/evs2/three", "net/b/evs/four", "sidecar.json"} {
		putBackendFile(t, backend, path, []byte("x"))
	}
	for _, c := range []struct {
		prefix string
		want   []string
	}{
		{prefix: "net/a/evs/", want: []string{"net/a/evs/one", "net/a/evs/two"}},
		{prefix: "net/a/evs", want: []string{"net/a/evs/one", "net/a/evs/two", "net/a/evs2/three"}},
		{prefix: "net/a/evs/o", want: []string{"net/a/evs/one"}},
		{prefix: "net/c/", want: []string{}},
		{prefix: "nothing", want: []string{}},
		{prefix: "", want: []string{"net/a/evs/one", "net/a/evs/two", "net/a/evs2/three", "net/b/evs/four", "sidecar.json"}},
	} {
		entries, err := backend.List(c.prefix)
		if err != nil {
			t.Fatal(err)
		}
		names := []string{}
		for _, entry := range entries {
			names = append(names, entry.Name)
			if entry.ByteCount != 1 {
				t.Errorf("%s: %d bytes", entry.Name, entry.ByteCount)
			}
		}
		if !slices.Equal(names, c.want) {
			t.Errorf("%q: names %v", c.prefix, names)
		}
	}
}

// The layers above build clean paths, and this holds if one ever does not.
func TestOsBackendRefusesAPathOutOfItsDirectory(t *testing.T) {
	backend, _ := newTestOsBackend(t)
	for _, path := range []string{"../file", "a/../../file", "/etc/hosts", ""} {
		if _, err := backend.Open(path); !errors.Is(err, ErrSidecarStoreName) {
			t.Errorf("Open(%q): %v", path, err)
		}
		if err := backend.Remove(path); !errors.Is(err, ErrSidecarStoreName) {
			t.Errorf("Remove(%q): %v", path, err)
		}
	}
	file, err := backend.CreateTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Discard()
	if err := file.Rename("../file"); !errors.Is(err, ErrSidecarStoreName) {
		t.Errorf("Rename: %v", err)
	}
}

// Every level of a new state tree is made, down from the first that exists.
func TestOsBackendMakesItsTree(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "a", "b", "state")
	backend, err := NewSidecarOsBackend(directory)
	if err != nil {
		t.Fatal(err)
	}
	putBackendFile(t, backend, "net/a/b/c/file", []byte("synthetic"))
	if content := readBackend(t, backend, "net/a/b/c/file"); string(content) != "synthetic" {
		t.Errorf("content %q", content)
	}
}

// A file where a directory has to go is a fault, reported as one.
func TestOsBackendReportsAFileInTheWay(t *testing.T) {
	backend, _ := newTestOsBackend(t)
	putBackendFile(t, backend, "net", []byte("in the way"))
	err := writeBackendFile(backend, "net/a/file", []byte("synthetic"))
	if !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("err %v", err)
	}
}

func TestOsBackendWantsAnAbsoluteDirectory(t *testing.T) {
	if _, err := NewSidecarOsBackend("relative"); err == nil {
		t.Error("a relative state directory was taken")
	}
}

// The whole path on real files: a first run, an enrollment, a restart, a rotation and a restart.
func TestAnInstanceOnRealFiles(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	keyStore := newFakeKeyStore()
	backend, err := NewSidecarOsBackend(directory)
	if err != nil {
		t.Fatal(err)
	}
	instance := newInstanceOn(t, backend, keyStore)
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	enrollTestNetwork(t, instance, testNetworkId)
	content := sealTestPlaintext(2*sealChunkByteCount + 3)
	writeStoreFile(t, storeOf(t, instance, testNetworkId, "evs"), "repo/file", content)
	instance.Close()

	reopenedBackend, err := NewSidecarOsBackend(directory)
	if err != nil {
		t.Fatal(err)
	}
	reopened := newInstanceOn(t, reopenedBackend, keyStore)
	if err := reopened.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	store := storeOf(t, reopened, testNetworkId, "evs")
	requireStoreFile(t, store, "repo/file", content)
	if err := reopened.RotateKeychain(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	requireRotationFinished(t, reopened, reopenedBackend, testNetworkId)
	requireStoreFile(t, store, "repo/file", content)
	reader, err := store.Open("repo/file")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatal(err)
	}
}

// A kill's temp file does not outlive the next opening.
func TestOpeningAnInstanceSweepsTempFiles(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	backend, err := NewSidecarOsBackend(directory)
	if err != nil {
		t.Fatal(err)
	}
	left, err := backend.CreateTemp()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := left.Write([]byte("left by a kill")); err != nil {
		t.Fatal(err)
	}
	newInstanceOn(t, backend, newFakeKeyStore())
	remaining, err := os.ReadDir(filepath.Join(directory, osBackendTempDirectoryName))
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Errorf("%d temp files remain", len(remaining))
	}
}

// Stable where one exists, and a sandbox with none reads as none.
func TestMachineIdIsStable(t *testing.T) {
	first := SidecarMachineId()
	second := SidecarMachineId()
	if string(first) != string(second) {
		t.Error("two reads differ")
	}
}
