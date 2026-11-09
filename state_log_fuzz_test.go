//go:build !js

// FuzzStoreLogRead: the log's decoder under arbitrary bytes. Go's fuzzing reads its seed corpus from testdata, which the
// js leg cannot open, so this stays off it.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
)

// Any bytes at a log's path read without a panic, and a read that answers nil handed over records that fit what was
// there: the decoder is total, and takes no more memory than the file holds plus one record's bound.
func FuzzStoreLogRead(f *testing.F) {
	backend := NewSidecarMemoryBackend()
	settings := cheapKeychainSettings()
	settings.KeychainSettings.AutoLockTimeout = 0
	clock := newTestClock()
	instance, err := newSidecarInstance(context.Background(),
		&SidecarInstanceArgs{Backend: backend, KeyStore: newFakeKeyStore(), Settings: settings},
		clock.now, clock.after, rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	defer instance.Close()
	if err := instance.Unlock(nil); err != nil {
		f.Fatal(err)
	}
	if _, err := instance.createKeychain(testNetworkId); err != nil {
		f.Fatal(err)
	}
	store, err := instance.Store(&testNetworkId).Directory("approval", "approval")
	if err != nil {
		f.Fatal(err)
	}
	log, err := OpenSidecarStoreLog(store, "a")
	if err != nil {
		f.Fatal(err)
	}
	for _, record := range []string{"one", "", "three"} {
		if err := log.Append([]byte(record)); err != nil {
			f.Fatal(err)
		}
	}
	valid, err := readBackendFile(backend, testLogPath("a"), 1024*1024)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(valid[:len(valid)-3])
	f.Add(append(bytes.Clone(valid), 0, 0, 0))
	f.Add([]byte(storeLogMagic))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, content []byte) {
		putBackendFile(t, backend, testLogPath("a"), content)
		byteCount := 0
		err := log.Read(func(index uint64, record []byte) error {
			byteCount += len(record) + storeLogSealedMinByteCount + storeLogFrameByteCount
			return nil
		})
		if err == nil && len(content) < byteCount {
			t.Errorf("records of %d bytes from a file of %d", byteCount, len(content))
		}
		if err != nil && !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("a read answered %v", err)
		}
	})
}
