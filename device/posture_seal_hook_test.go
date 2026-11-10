//go:build sidecar_testhooks

// The sealed store reports its root key and every record key it derives to the privacy harness (§22.7), under the
// tag: the root key as it takes it, and one record key at each write and each open, the same for a record and its
// read.

package device

import (
	"bytes"
	"io"
	"sync"
	"testing"
)

func TestSealedPostureStoreHooksItsKeys(t *testing.T) {
	stateLock := sync.Mutex{}
	kindSecrets := map[string][][]byte{}
	SetTestHooks(&TestHooks{Secret: func(kind string, secret []byte) {
		stateLock.Lock()
		defer stateLock.Unlock()
		kindSecrets[kind] = append(kindSecrets[kind], secret)
	}})
	defer SetTestHooks(nil)
	rootKey := testSealedRootKey(0x3a)
	store, err := NewSealedPostureStore(newMemoryPostureStore(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	writeSealedRecord(t, store, "posture", []byte("manifest"), 8)
	reader, err := store.Open("posture")
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(reader)
	reader.Close()
	stateLock.Lock()
	defer stateLock.Unlock()
	if roots := kindSecrets["forward_store_root_key"]; len(roots) != 1 || !bytes.Equal(roots[0], rootKey) {
		t.Errorf("root keys reported %d", len(roots))
	}
	records := kindSecrets["forward_store_record_key"]
	if len(records) != 2 || !bytes.Equal(records[0], records[1]) || len(records[0]) != sealedPostureRecordKeyByteCount ||
		bytes.Equal(records[0], rootKey) {
		t.Errorf("record keys reported %d", len(records))
	}
}
