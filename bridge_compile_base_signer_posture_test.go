// QD-1200 across the compile and the device role: the state the compile gives on a later writer's save, handed to a
// pending posture with its run from the save, re-anchors the posture on the save, for each case the question names: an
// admin's device admitted after the last fold whose save no rule lets reach the host, a personal network's second
// device revoked after its save, and a member's device the tail made an admin's. The same state without the key the
// save verified under, as the compile gave it before QD-1200, is refused and leaves the posture pending. An external
// test, so the root links no device/ (§4.4).

package sidecar_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

func TestACompiledStateOnALaterWritersSaveReanchorsThePosture(t *testing.T) {
	for _, c := range sidecar.CompileBaseSignerPostureCases(t) {
		store, err := device.NewFilePostureStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		posture, decision := device.NewPosture(store, device.DefaultPostureSettings())
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
		decision, err = posture.SetState(unkeyed, log)
		if !errors.Is(err, device.ErrPostureRefused) || decision.State != device.PosturePending {
			t.Errorf("%s: the state without its base's key: %v, %v, %v", c.Name, err, decision.State, decision.Alarms)
		}

		decision, err = posture.SetState(c.State, log)
		if err != nil || decision.State != device.PostureEnforcingDocument || !proto.Equal(decision.Pin, c.State.GetAuth()) ||
			!proto.Equal(decision.BridgeState.GetAuth(), c.State.GetAuth()) {
			t.Errorf("%s: the compiled state: %v, %v, %v, %v", c.Name, err, decision.State, decision.Pin, decision.Alarms)
			continue
		}
		if decision.Pin.GetVersion() < c.BaseN {
			t.Errorf("%s: the posture's pin %d is below the save at %d", c.Name, decision.Pin.GetVersion(), c.BaseN)
		}
	}
}
