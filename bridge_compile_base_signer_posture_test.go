// QD-1200 across the compile and the device role: the state the compile gives on a later writer's save, handed to a
// pending posture with its run from the save, re-anchors the posture on the save, for each case the question names: an
// admin's device admitted after the last fold whose save no rule lets reach the host, a personal network's second
// device revoked after its save, and a member's device the tail made an admin's; and a restart restores it. The same
// state without the key the save verified under, as the compile gave it before QD-1200, is refused and leaves the
// posture pending. An external test, so the root links no device/ (§4.4).

package sidecar_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"maps"
	"slices"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A posture's records in memory, so the test runs where there is no file system, a Worker's leg among them. Safe for
// concurrent use.
type testBaseSignerPostureStore struct {
	stateLock   sync.Mutex
	nameRecords map[string][]byte
}

func (self *testBaseSignerPostureStore) Open(name string) (io.ReadCloser, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	record, found := self.nameRecords[name]
	if !found {
		return nil, device.ErrPostureStoreAbsent
	}
	return io.NopCloser(bytes.NewReader(record)), nil
}

func (self *testBaseSignerPostureStore) Write(name string, write func(writer io.Writer) error) error {
	buffer := &bytes.Buffer{}
	if err := write(buffer); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nameRecords[name] = buffer.Bytes()
	return nil
}

func (self *testBaseSignerPostureStore) Remove(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.nameRecords, name)
	return nil
}

func (self *testBaseSignerPostureStore) List() ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Sorted(maps.Keys(self.nameRecords)), nil
}

var _ device.PostureStore = (*testBaseSignerPostureStore)(nil)

func TestACompiledStateOnALaterWritersSaveReanchorsThePosture(t *testing.T) {
	settings := device.DefaultPostureSettings()
	for _, c := range sidecar.CompileBaseSignerPostureCases(t) {
		store := &testBaseSignerPostureStore{nameRecords: map[string][]byte{}}
		posture, decision := device.NewPosture(store, settings)
		if decision.State != device.PostureLegacy {
			t.Fatalf("%s: a new posture is %v", c.Name, decision.State)
		}
		if _, err := posture.SetPending(c.Pending); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		log := &device.PostureLog{
			Entries: c.Entries,
			OpenRows: func(rowsSha256 []byte) (io.ReadCloser, error) {
				rows, found := c.Rows[[sha256.Size]byte(rowsSha256)]
				if !found {
					return nil, errors.New("no such rows")
				}
				return io.NopCloser(bytes.NewReader(rows)), nil
			},
		}

		unkeyed := proto.Clone(c.State).(*bridge.BridgeState)
		unkeyed.BaseSignerIdentityPublicKey = nil
		decision, err := posture.SetState(unkeyed, log)
		if !errors.Is(err, device.ErrPostureRefused) || decision.State != device.PosturePending {
			t.Errorf("%s: the state without its base's key: %v, %v, %v", c.Name, err, decision.State, decision.Alarms)
		}

		decision, err = posture.SetState(c.State, log)
		if err != nil || decision.State != device.PostureEnforcingDocument || !proto.Equal(decision.Pin, c.State.GetAuth()) ||
			!proto.Equal(decision.BridgeState.GetAuth(), c.State.GetAuth()) || decision.Pin.GetVersion() < c.BaseN {
			t.Errorf("%s: the compiled state: %v, %v, %v, %v", c.Name, err, decision.State, decision.Pin, decision.Alarms)
			continue
		}
		if _, restored := device.NewPosture(store, settings); len(restored.Alarms) != 0 || restored.State != device.PostureEnforcingDocument ||
			!proto.Equal(restored.Pin, c.State.GetAuth()) {
			t.Errorf("%s: restored %v at %v, %v", c.Name, restored.State, restored.Pin, restored.Alarms)
		}
	}
}
