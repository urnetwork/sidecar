//go:build !js

// §22.6's state-machine target for HeadCheck, whose seeds in testdata/fuzz/FuzzHeadCheckState run as
// ordinary tests under go test. Not on the js leg, whose worker cannot open the seed directory.

package sidecar

import (
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What one byte of FuzzHeadCheckState's script does.
const (
	testHeadOpMessage = iota
	testHeadOpServe
	testHeadOpProve
	testHeadOpRound
	testHeadOpRevoke
	testHeadOpWait
	testHeadOpCount
)

// The bounds §6.4 sets on what a device holds, each of which every step must keep.
func testHeadCheckBounds(t *testing.T, device *testHeadCheckDevice, state headCheckState) {
	t.Helper()
	if HeadCheckMaxUnverifiedCount < len(state.unverified) || HeadCheckMaxUnverifiedCount < len(state.fetches) {
		t.Fatalf("holds %d pins and %d fetches", len(state.unverified), len(state.fetches))
	}
	peerCounts := map[Id]int{}
	for i, held := range state.unverified {
		if len(held.path) == 0 || HeadCheckMaxPathCount < len(held.path) {
			t.Fatalf("a path of %d", len(held.path))
		}
		for _, sidecarId := range held.path {
			if sidecarId == device.sidecarId {
				t.Fatal("a path through this device")
			}
		}
		if 0 < i && headCheckPinCompare(state.unverified[i-1].pin, held.pin) >= 0 {
			t.Fatal("not highest first, or held twice")
		}
		peerCounts[held.peerId()] += 1
		if HeadCheckMaxUnverifiedPeerCount < peerCounts[held.peerId()] {
			t.Fatalf("%d taken from one peer", peerCounts[held.peerId()])
		}
	}
	for i, fetch := range state.fetches {
		if 0 < i && headCheckPinCompare(state.fetches[i-1].pin, fetch.pin) >= 0 {
			t.Fatal("fetches out of order, or one twice")
		}
	}
	if state.withheld != nil && HeadCheckMaxProofByteCount < len(state.withheld.proof) {
		t.Fatal("a proof past its cap")
	}
}

// §22.6's state-machine target: whatever peers send and however api and proofs answer, a device's head
// check state stays within §6.4's bounds, never counts a witness while it holds an UNVERIFIED pin, and
// once api serves everything and every peer that sent anything is revoked, it holds nothing and the
// next peer at its pin witnesses: it converges.
func FuzzHeadCheckState(f *testing.F) {
	f.Add([]byte{testHeadOpMessage, 0, 30, 0, 0, testHeadOpWait, 12, testHeadOpServe, 20, testHeadOpProve, 1})
	f.Add([]byte{testHeadOpMessage, 1, 12, 9, 4, 2, 0x81, testHeadOpRound, testHeadOpRevoke, 1})
	f.Fuzz(func(t *testing.T, script []byte) {
		device := newTestHeadCheckDevice(testHeadSelf)
		peerIds := []Id{}
		for i := range 6 {
			peerIds = append(peerIds, Id{0x10, byte(i)})
		}
		device.admit(peerIds...)
		// relayers and claimants a path may name: the peers, strangers, and now and then this device
		pathIds := append([]Id{testHeadSelf, {0x20, 1}, {0x20, 2}, {0x20, 3}}, peerIds...)
		state := headCheckState{}
		now := testHeadStart
		next := func() byte {
			if len(script) == 0 {
				return 0
			}
			b := script[0]
			script = script[1:]
			return b
		}
		pin := func() *bridge.AuthPin {
			b := next()
			version := uint64(next() % 50)
			if b&1 == 0 {
				return testMainChain.pin(version)
			}
			return testForkChain(uint64(b>>1) % 20).pin(version)
		}

		for 0 < len(script) {
			switch next() % testHeadOpCount {
			case testHeadOpMessage:
				peerId := peerIds[next()%byte(len(peerIds))]
				message := device.message(pin())
				flags := next()
				if flags&1 != 0 {
					message.Proven = pin()
				}
				for range int(flags>>1) % 5 {
					copyPin := pin()
					path := [][]byte{}
					for range 1 + int(next())%9 {
						path = append(path, pathIds[next()%byte(len(pathIds))].Bytes())
					}
					message.Unverified = append(message.Unverified, &protocol.UnverifiedPin{Pin: copyPin, Path: path})
				}
				nextState, _, err := headCheckReconcile(state, device.mine(now), peerId, message)
				if err != nil {
					if !errors.Is(err, errHeadCheckPeer) {
						t.Fatalf("refused: %v", err)
					}
					continue
				}
				state = nextState
			case testHeadOpServe:
				if through := uint64(next() % 50); device.pin.GetVersion() < through {
					device.follow(testMainChain, 1, through)
				}
				state, _ = headCheckFetched(state, device.mine(now))
			case testHeadOpProve:
				if len(state.fetches) == 0 {
					continue
				}
				fetch := state.fetches[int(next())%len(state.fetches)]
				state, _ = headCheckProved(state, device.mine(now), fetch.pin, fetch.claimantId, [][]byte{[]byte("entries")}, next()&1 != 0)
			case testHeadOpRound:
				state, _ = headCheckRound(state, device.mine(now))
				for _, held := range state.unverified {
					for _, sidecarId := range held.path {
						if peer := device.peers[sidecarId]; peer.Revoked || peer.Parked {
							t.Fatal("a round kept a copy through a revoked or parked sidecar")
						}
					}
				}
			case testHeadOpRevoke:
				sidecarId := pathIds[1+int(next())%(len(pathIds)-1)]
				peer := device.peers[sidecarId]
				peer.Admitted = true
				if next()&1 == 0 {
					peer.Revoked = true
				} else {
					peer.Parked = true
				}
				device.peers[sidecarId] = peer
			case testHeadOpWait:
				now = now.Add(time.Duration(next()%16) * time.Minute)
			}
			testHeadCheckBounds(t, device, state)
			if len(state.unverified) != 0 {
				for _, peerId := range peerIds {
					if headCheckWitnessFor(state, device.mine(now), peerId, device.message(device.pin), false) != nil {
						t.Fatal("a witness while holding an UNVERIFIED pin")
					}
				}
			}
		}

		// converge: api serves past every pin a script can name, and every sidecar that could have sent
		// or relayed anything is revoked
		device.follow(testMainChain, 1, 50)
		state, _ = headCheckFetched(state, device.mine(now))
		for _, sidecarId := range pathIds[1:] {
			device.peers[sidecarId] = HeadCheckPeer{Admitted: true, Revoked: true}
		}
		state, _ = headCheckRound(state, device.mine(now.Add(time.Hour)))
		if len(state.unverified) != 0 || state.withheld != nil || state.forked != nil || len(state.fetches) != 0 {
			t.Fatalf("did not converge: %d held, withheld %v, forked %v, %d fetches", len(state.unverified), state.withheld != nil, state.forked != nil, len(state.fetches))
		}
		fresh := Id{0x30}
		device.admit(fresh)
		message := device.message(device.pin)
		state, step := testReconcile(t, device, state, fresh, message, now.Add(time.Hour))
		if headCheckWitnessFor(state, device.mine(now.Add(time.Hour)), fresh, message, step.forked) == nil {
			t.Fatal("a converged device did not count a peer at its pin")
		}
	})
}
