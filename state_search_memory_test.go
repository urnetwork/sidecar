// The memory-only SidecarStore (state_search_memory.go): a file is there once its writer commits and never before,
// a store name is checked as a sealed store checks it, the listing is sorted by name within a prefix, narrowing is
// refused, and clear drops everything.

package sidecar

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// Writes content under name and commits it.
func testSearchMemoryPut(t *testing.T, store *searchMemoryStore, name string, content []byte) {
	t.Helper()
	writer, err := store.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestSearchMemoryStoreKeepsWhatIsCommitted(t *testing.T) {
	store := newSearchMemoryStore()
	if _, err := store.Open("a/one"); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Fatalf("a file never written: %v", err)
	}
	// a writer closed before Commit leaves nothing, and takes no more
	writer, err := store.Create("a/one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("dropped")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open("a/one"); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("a file closed before Commit: %v", err)
	}
	if err := writer.Commit(); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("Commit after Close: %v", err)
	}
	if _, err := writer.Write([]byte("late")); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("Write after Close: %v", err)
	}

	testSearchMemoryPut(t, store, "a/one", []byte("first"))
	testSearchMemoryPut(t, store, "a/one", []byte("second"))
	reader, err := store.Open("a/one")
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(content, []byte("second")) {
		t.Errorf("the file reads %q, %v", content, err)
	}
	if err := reader.Close(); err != nil {
		t.Error(err)
	}
	if err := store.Remove("a/one"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open("a/one"); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("a removed file: %v", err)
	}
}

func TestSearchMemoryStoreListsAPrefixSorted(t *testing.T) {
	store := newSearchMemoryStore()
	for _, name := range []string{"b/two", "a/zed", "a/one", "c"} {
		testSearchMemoryPut(t, store, name, []byte(name))
	}
	entries, err := store.List("a/")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name != "a/one" || entries[1].Name != "a/zed" || entries[0].ByteCount != int64(len("a/one")) {
		t.Errorf("the listing under a/: %+v", entries)
	}
	store.clear()
	if entries, err := store.List(""); err != nil || len(entries) != 0 {
		t.Errorf("after clear: %+v, %v", entries, err)
	}
}

func TestSearchMemoryStoreRefusesBadNamesAndNarrowing(t *testing.T) {
	store := newSearchMemoryStore()
	for _, name := range []string{"", "a//b", ".hidden", "a/b:c"} {
		if _, err := store.Create(name); !errors.Is(err, ErrSidecarStoreName) {
			t.Errorf("Create(%q): %v", name, err)
		}
		if _, err := store.Open(name); !errors.Is(err, ErrSidecarStoreName) {
			t.Errorf("Open(%q): %v", name, err)
		}
	}
	if narrowed, err := store.Directory("a", SidecarSearchFileClass); narrowed != nil || !errors.Is(err, ErrSidecarStoreName) {
		t.Errorf("Directory: %v", err)
	}
}
