//go:build !js && !ios && !android && !sdk_mobile_bind

// §22.7's devices row's two remote-mode desktops through a real ur daemon (MCP-M8-01; §16.6's host table, D-SDK-9), on
// the legs that build the daemon, beside approval_devices_test.go's world: the second desktop's app lists and decides
// over its own daemon's app methods on a socket of its own.

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// desktop's ur daemon serving a remote-mode app's request methods on a socket of its own, and the control session the
// app holds on it, both ended when the test ends.
func startApprovalDevicesDaemon(t *testing.T, net *Net, desktop *TestSidecar) *sidecar.DaemonClient {
	t.Helper()
	// a short path, since a Unix socket's name is bounded
	directory, err := os.MkdirTemp("/tmp", "ur-approval-app-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	socketPath := filepath.Join(directory, "s")
	ctx, cancel := context.WithCancel(context.Background())
	daemon, err := sidecar.NewDaemon(ctx, &sidecar.DaemonSettings{
		Instance:       "test",
		StateDirectory: directory,
		SocketPath:     socketPath,
		Local:          sidecar.DefaultSidecarSettings().LocalSettings,
		Version:        sidecar.Version,
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		daemon.Close()
		<-done
	})
	for _, method := range sidecar.DaemonApprovalsAppMethods() {
		if err := daemon.RegisterMethod(method); err != nil {
			close(done)
			t.Fatal(err)
		}
	}
	if err := daemon.AddSidecar(net.DefaultNetworkId(), desktop.Sidecar()); err != nil {
		close(done)
		t.Fatal(err)
	}
	go func() {
		defer close(done)
		daemon.Run()
	}()
	app, err := sidecar.DialDaemon(t.Context(), socketPath, &sidecar.DaemonHello{Mode: sidecar.DaemonModeControl, Version: sidecar.Version, Pid: int64(os.Getpid())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	return app
}

// The item of approvalId in reply, nil for none.
func approvalDevicesAppItem(reply *sidecar.DaemonApprovalsAppReply, approvalId sidecar.Id) *sidecar.DaemonApprovalsAppItem {
	for _, item := range reply.Items {
		if item.ApprovalId != nil && *item.ApprovalId == approvalId {
			return item
		}
	}
	return nil
}

// Two remote-mode desktops, with and without a presence key: the second desktop's app, over its daemon's app methods,
// lists the first desktop's request on channel device and its own daemon's request with no decision; an unconfirmed
// decision runs nothing and the daemon's own is refused whatever is sent (D-SDK-9); the confirmed decision on the
// first desktop's request is signed by the second desktop's identity key, and the first daemon spends it. The first
// desktop's own request then takes the member's presence key, by its daemon's prompt: it spends where the member holds
// the key, and is refused where it does not.
func TestRemoteDesktopsDecideOverTheAppMethods(t *testing.T) {
	for _, presenceKey := range []bool{false, true} {
		func() {
			devices := newApprovalDevicesWorld(t, &approvalDevicesPairing{name: "two remote-mode desktops", presenceKey: presenceKey})
			defer devices.net.Close()
			world := devices.world
			desktop, _, log := devices.addMemberSidecar("second desktop")
			desktopId := desktop.Sidecar().Identity().SidecarId
			app := startApprovalDevicesDaemon(t, devices.net, desktop)
			sink := world.Sink(sidecar.SidecarActionMail)

			stored, _, approvalId := devices.call("first@recipient.example")
			if approvalId == (sidecar.Id{}) {
				t.Fatalf("key %t: the first desktop's call spent beside a second desktop", presenceKey)
			}
			ownAction, err := world.MailAction("own@recipient.example")
			if err != nil {
				t.Fatal(err)
			}
			own := devices.fileOwnRequest(log, desktopId, ownAction)

			reply := &sidecar.DaemonApprovalsAppReply{}
			if err := app.Call(t.Context(), sidecar.DaemonMethodApprovalsAppRequests, &sidecar.DaemonApprovalsAppParams{}, false, reply); err != nil {
				t.Fatal(err)
			}
			first := approvalDevicesAppItem(reply, approvalId)
			if first == nil || first.Channel != "device" || !slices.Equal(first.Decisions, []string{sidecar.SidecarDecisionApprove, sidecar.SidecarDecisionDeny}) ||
				first.SidecarId == nil || *first.SidecarId != world.Laptop.SidecarId || first.Kind != "mail_send" {
				t.Fatalf("key %t: the first desktop's request on the app: %+v", presenceKey, first)
			}
			ownItem := approvalDevicesAppItem(reply, own.ApprovalId())
			if ownItem == nil || ownItem.Channel != "" || len(ownItem.Decisions) != 0 || ownItem.SidecarId == nil || *ownItem.SidecarId != desktopId {
				t.Fatalf("key %t: its daemon's own request on the app: %+v", presenceKey, ownItem)
			}

			approveFirst := &sidecar.DaemonApprovalsAppDecideParams{ApprovalId: approvalId, Decision: sidecar.SidecarDecisionApprove}
			rpcErr := &sidecar.DaemonRpcError{}
			if err := app.Call(t.Context(), sidecar.DaemonMethodApprovalsAppRequest, approveFirst, false, nil); !errors.As(err, &rpcErr) || rpcErr.Code != sidecar.DaemonRpcConfirmationRequired {
				t.Fatalf("key %t: an unconfirmed decision: %v", presenceKey, err)
			}
			for _, decision := range []string{sidecar.SidecarDecisionApprove, sidecar.SidecarDecisionDeny} {
				params := &sidecar.DaemonApprovalsAppDecideParams{ApprovalId: own.ApprovalId(), Decision: decision}
				if err := app.Call(t.Context(), sidecar.DaemonMethodApprovalsAppRequest, params, true, nil); err == nil || !strings.Contains(err.Error(), sidecar.ErrSidecarApprovalNotEligible.Error()) {
					t.Fatalf("key %t: the app's %s of its daemon's own request: %v", presenceKey, decision, err)
				}
			}
			if filed := log.decisions(t); len(filed) != 0 {
				t.Fatalf("key %t: %d decisions filed before the confirmed one", presenceKey, len(filed))
			}

			if err := app.Call(t.Context(), sidecar.DaemonMethodApprovalsAppRequest, approveFirst, true, nil); err != nil {
				t.Fatal(err)
			}
			action := world.Action(stored)
			if err := world.Authorize(t.Context(), action); err != nil || action.Outcome == nil || action.Outcome.State != sidecar.ApprovalOutcomeDone {
				t.Fatalf("key %t: the first daemon's spend of the app's decision: %v %+v", presenceKey, err, action.Outcome)
			}
			decisions, err := world.Decisions(approvalId)
			if err != nil || len(decisions) != 1 || decisions[0].Decision.GetChannel() != uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE) ||
				!bytes.Equal(decisions[0].Signed.GetSignerId(), desktopId.Bytes()) {
				t.Fatalf("key %t: the decision kept: %+v, %v", presenceKey, decisions, err)
			}

			// the first desktop's own request by the member's presence key, as its daemon's prompt signs it
			stored, _, approvalId = devices.call("presence@recipient.example")
			key := devices.key
			if key == nil {
				key = NewFixturePresenceKey("a key no state holds", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
			}
			signed, err := world.SignPresenceDecision(approvalId, devices.deadline(), key)
			if err != nil {
				t.Fatal(err)
			}
			action, err = devices.spend(stored, signed)
			wantEffects := 1
			if presenceKey {
				wantEffects = 2
				if err != nil || action.Outcome == nil || action.Outcome.State != sidecar.ApprovalOutcomeDone {
					t.Fatalf("the presence decision: %v %+v", err, action.Outcome)
				}
			} else if !approvalDevicesSignerRefused(err) {
				t.Fatalf("a presence decision under a key P does not hold: %v", err)
			}
			if sink.EffectCount() != wantEffects {
				t.Errorf("key %t: %d effects", presenceKey, sink.EffectCount())
			}
			if err := world.CheckEffects(true); err != nil {
				t.Error(err)
			}
		}()
	}
}
