//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The daemon's disclosure methods (disclosure_daemon.go; CTRUST-M11-01, CTRUST-M12-01, CTRUST-M12-02) on backends a test sets: the
// list's policy_unavailable as its reply's code, never an empty list; the acts as Confirm methods, refused unconfirmed
// and to a caller under a harness process or one the daemon cannot name, before their backends run; a version not the
// current one, or a policy with nothing to act on, as the reply's refusal; params read strictly; and every reply past
// the secret walk.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
)

// The methods over recording backends, by name, and a caller of each.
type testDisclosureDaemonWorld struct {
	methods map[string]*DaemonMethod

	stateLock    sync.Mutex
	list         *ComputeDisclosureList
	listErr      error
	actErr       error
	underHarness bool
	acks         []*ComputeDisclosureAckArgs
	opens        []string
	networkAcks  []*ComputeNetworkDisclosureAckArgs
	removals     []*ComputeNetworkDisclosureRemoveArgs
}

func newTestDisclosureDaemonWorld() *testDisclosureDaemonWorld {
	world := &testDisclosureDaemonWorld{methods: map[string]*DaemonMethod{}}
	for _, method := range DaemonComputeDisclosureMethods(&DaemonComputeDisclosureBackends{
		List: func(ctx context.Context, sidecar *Sidecar, locale string) (*ComputeDisclosureList, error) {
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			return world.list, world.listErr
		},
		Ack: func(ctx context.Context, sidecar *Sidecar, args *ComputeDisclosureAckArgs) error {
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			if world.actErr != nil {
				return world.actErr
			}
			world.acks = append(world.acks, args)
			return nil
		},
		Open: func(ctx context.Context, sidecar *Sidecar, id string, version uint32) error {
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			if world.actErr != nil {
				return world.actErr
			}
			world.opens = append(world.opens, id)
			return nil
		},
		AckNetwork: func(ctx context.Context, sidecar *Sidecar, args *ComputeNetworkDisclosureAckArgs) error {
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			if world.actErr != nil {
				return world.actErr
			}
			world.networkAcks = append(world.networkAcks, args)
			return nil
		},
		RemoveNetwork: func(ctx context.Context, sidecar *Sidecar, args *ComputeNetworkDisclosureRemoveArgs) error {
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			if world.actErr != nil {
				return world.actErr
			}
			world.removals = append(world.removals, args)
			return nil
		},
		UnderHarness: func(ctx context.Context, call *DaemonCall) bool {
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			return world.underHarness
		},
	}) {
		world.methods[method.Name] = method
	}
	return world
}

// One call of name with params, confirmed or not, on a network's Sidecar, the reply passing the secret walk.
func (self *testDisclosureDaemonWorld) call(t *testing.T, name string, params string, confirmed bool) (any, error) {
	t.Helper()
	method := self.methods[name]
	if method == nil {
		t.Fatalf("no method %s", name)
	}
	reply, err := method.Handler(t.Context(), &DaemonCall{Params: json.RawMessage(params), Confirmed: confirmed, Sidecar: &Sidecar{}})
	if err == nil {
		if walkErr := checkDaemonReply(reply); walkErr != nil {
			t.Fatalf("%s's reply fails the secret walk: %v", name, walkErr)
		}
	}
	return reply, err
}

// The list's no-policy reply is its code; the acts are Confirm methods, refused unconfirmed and under a harness before
// their backends run, their refusals the reply's code; and unknown params refused.
func TestDaemonComputeDisclosureMethods(t *testing.T) {
	world := newTestDisclosureDaemonWorld()
	for name, confirm := range map[string]bool{
		DaemonMethodComputeDisclosureList: false,
		DaemonMethodComputeDisclosureAck:  true,
		DaemonMethodComputeDisclosureOpen: true,
	} {
		if method := world.methods[name]; method == nil || method.Confirm != confirm || !method.Network {
			t.Errorf("%s: %+v", name, method)
		}
	}

	world.listErr = ErrComputeDisclosurePolicyUnavailable
	reply, err := world.call(t, DaemonMethodComputeDisclosureList, `{"locale":"de-AT"}`, false)
	list, ok := reply.(*ComputeDisclosureList)
	if err != nil || !ok || list.Unavailable != ComputeDisclosureCodePolicyUnavailable || list.Disclosures == nil || len(list.Disclosures) != 0 {
		t.Fatalf("no policy: %+v, %v", reply, err)
	}
	world.listErr = nil
	world.list = &ComputeDisclosureList{PolicyVersion: 3, Disclosures: []*ComputeDisclosureView{{Id: "inference:engy", Version: 1, Exposed: []string{}, Private: []string{}}}}
	if reply, err := world.call(t, DaemonMethodComputeDisclosureList, `{}`, false); err != nil || reply != world.list {
		t.Fatalf("the list: %+v, %v", reply, err)
	}
	if _, err := world.call(t, DaemonMethodComputeDisclosureList, `{"locale":"en","extra":1}`, false); err == nil {
		t.Fatal("a list with an unknown param")
	}

	act := `{"id":"inference:engy","version":1}`
	for _, name := range []string{DaemonMethodComputeDisclosureAck, DaemonMethodComputeDisclosureOpen} {
		if _, err := world.call(t, name, act, false); !errors.Is(err, ErrDisclosureAckRefused) {
			t.Errorf("%s unconfirmed: %v", name, err)
		}
		world.underHarness = true
		if _, err := world.call(t, name, act, true); !errors.Is(err, ErrDisclosureAckRefused) {
			t.Errorf("%s under a harness: %v", name, err)
		}
		world.underHarness = false
		if _, err := world.call(t, name, `{"id":"inference:engy","version":1,"confirmed":true}`, true); err == nil {
			t.Errorf("%s with an unknown param", name)
		}
	}
	if len(world.acks) != 0 || len(world.opens) != 0 {
		t.Fatalf("a refused act reached its backend: %v %v", world.acks, world.opens)
	}

	// the person's act lands, as SidecarActConfirmed, and says what it recorded
	reply, err = world.call(t, DaemonMethodComputeDisclosureAck, act, true)
	if err != nil || len(world.acks) != 1 || world.acks[0].Origin != SidecarActConfirmed || world.acks[0].Id != "inference:engy" ||
		world.acks[0].Version != 1 || world.acks[0].HarnessAncestor {
		t.Fatalf("the act: %+v, %v, %+v", reply, err, world.acks)
	}
	if actReply, ok := reply.(*DaemonComputeDisclosureActReply); !ok || actReply.Refusal != "" || actReply.Version != 1 {
		t.Fatalf("the reply %+v", reply)
	}
	if _, err := world.call(t, DaemonMethodComputeDisclosureOpen, act, true); err != nil || !slices.Equal(world.opens, []string{"inference:engy"}) {
		t.Fatalf("the opening: %v, %v", err, world.opens)
	}

	// each refusal the backends answer as the reply's code; any other error stands
	for actErr, code := range map[error]string{
		ErrDisclosureChanged:                  ComputeDisclosureCodeChanged,
		ErrComputeDisclosurePolicyUnavailable: ComputeDisclosureCodePolicyUnavailable,
		ErrComputeDisclosureNotCarried:        ComputeDisclosureCodeRequired,
		ErrComputeDisclosureRefused:           ComputeDisclosureCodeRequired,
	} {
		world.actErr = actErr
		for _, name := range []string{DaemonMethodComputeDisclosureAck, DaemonMethodComputeDisclosureOpen} {
			reply, err := world.call(t, name, act, true)
			actReply, ok := reply.(*DaemonComputeDisclosureActReply)
			if err != nil || !ok || actReply.Refusal != code || actReply.Id != "inference:engy" {
				t.Errorf("%s at %v: %+v, %v", name, actErr, reply, err)
			}
		}
	}
	world.actErr = ErrHarnessConfigUnavailable
	if _, err := world.call(t, DaemonMethodComputeDisclosureAck, act, true); !errors.Is(err, ErrHarnessConfigUnavailable) {
		t.Errorf("another error: %v", err)
	}
	// a caller the daemon cannot name is treated as under a harness
	unnamed := DaemonComputeDisclosureMethods(nil)
	for _, method := range unnamed {
		if method.Name != DaemonMethodComputeDisclosureAck {
			continue
		}
		if _, err := method.Handler(t.Context(), &DaemonCall{Params: json.RawMessage(act), Confirmed: true, Sidecar: &Sidecar{}}); !errors.Is(err, ErrDisclosureAckRefused) {
			t.Errorf("a caller with no pid: %v", err)
		}
	}
}

// The network's acknowledgment and its removal are Confirm methods on the call's network, refused unconfirmed and under
// a harness before their backends run, their params read strictly; the act reaches its backend as the person's
// confirmed act with the version, locale and revision shown; a text not the current version's, or a policy with nothing
// to act on, is the reply's code; and a refusal naming who can, as a Member's device gets, stands as the call's error.
func TestDaemonComputeNetworkDisclosureMethods(t *testing.T) {
	world := newTestDisclosureDaemonWorld()
	for _, name := range []string{DaemonMethodComputeDisclosureAckNetwork, DaemonMethodComputeDisclosureRemoveNetwork} {
		if method := world.methods[name]; method == nil || !method.Confirm || !method.Network {
			t.Errorf("%s: %+v", name, method)
		}
	}
	act := `{"id":"inference:engy","version":2,"locale":"de","revision":3}`
	remove := `{"id":"inference:engy"}`
	for name, params := range map[string]string{DaemonMethodComputeDisclosureAckNetwork: act, DaemonMethodComputeDisclosureRemoveNetwork: remove} {
		if _, err := world.call(t, name, params, false); !errors.Is(err, ErrDisclosureAckRefused) {
			t.Errorf("%s unconfirmed: %v", name, err)
		}
		world.underHarness = true
		if _, err := world.call(t, name, params, true); !errors.Is(err, ErrDisclosureAckRefused) {
			t.Errorf("%s under a harness: %v", name, err)
		}
		world.underHarness = false
		if _, err := world.call(t, name, `{"id":"inference:engy","origin":1}`, true); err == nil {
			t.Errorf("%s with an unknown param", name)
		}
	}
	if len(world.networkAcks) != 0 || len(world.removals) != 0 {
		t.Fatalf("a refused act reached its backend: %v %v", world.networkAcks, world.removals)
	}

	reply, err := world.call(t, DaemonMethodComputeDisclosureAckNetwork, act, true)
	if err != nil || len(world.networkAcks) != 1 {
		t.Fatalf("the act: %+v, %v", reply, err)
	}
	if args := world.networkAcks[0]; args.Id != "inference:engy" || args.Version != 2 || args.Locale != "de" || args.Revision != 3 ||
		args.Origin != SidecarActConfirmed || args.HarnessAncestor {
		t.Fatalf("the act's args %+v", args)
	}
	if actReply, ok := reply.(*DaemonComputeDisclosureActReply); !ok || actReply.Refusal != "" || actReply.Version != 2 {
		t.Fatalf("the reply %+v", reply)
	}
	if _, err := world.call(t, DaemonMethodComputeDisclosureRemoveNetwork, remove, true); err != nil || len(world.removals) != 1 ||
		world.removals[0].Id != "inference:engy" || world.removals[0].Origin != SidecarActConfirmed {
		t.Fatalf("the removal: %v, %+v", err, world.removals)
	}

	for actErr, code := range map[error]string{
		ErrDisclosureChanged:                  ComputeDisclosureCodeChanged,
		ErrComputeDisclosurePolicyUnavailable: ComputeDisclosureCodePolicyUnavailable,
		ErrComputeDisclosureNotCarried:        ComputeDisclosureCodeRequired,
	} {
		world.actErr = actErr
		reply, err := world.call(t, DaemonMethodComputeDisclosureAckNetwork, act, true)
		actReply, ok := reply.(*DaemonComputeDisclosureActReply)
		if err != nil || !ok || actReply.Refusal != code {
			t.Errorf("at %v: %+v, %v", actErr, reply, err)
		}
	}
	world.actErr = fmt.Errorf("%w: this device's member is no Owner or Admin", ErrNetworkDisclosureRefused)
	for name, params := range map[string]string{DaemonMethodComputeDisclosureAckNetwork: act, DaemonMethodComputeDisclosureRemoveNetwork: remove} {
		if _, err := world.call(t, name, params, true); !errors.Is(err, ErrNetworkDisclosureRefused) {
			t.Errorf("%s by a Member's device: %v", name, err)
		}
	}
}
