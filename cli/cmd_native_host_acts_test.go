package main

// ur native-host and §5.8's two calls (CORE-M8-03, D-SDK-30): a remote-mode app's two-call methods are Confirm methods
// no extension reaches. The native host answers a revocation's REVOKE_NOT_CAPABLE itself and refuses the rest at its
// allow-list, and even a list naming them relays them unconfirmed, which the daemon refuses before any handler runs.

import (
	"context"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// TestNativeHostRefuses: every two-call method, its first call and its later ones, is refused at the relay on the real
// allow-list (REVOKE_NOT_CAPABLE for a revocation's), and on a list that names them a revocation's is still answered
// at the relay while the rest reach the daemon unconfirmed and are refused there; a request asking for the
// confirmation is malformed for the native host. No handler of the daemon's runs.
func TestNativeHostRefuses(t *testing.T) {
	calls := &testNativeHostCalls{}
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		for _, method := range append(sidecar.DaemonDevicesMethods(daemon), sidecar.DaemonApprovalsMethods(daemon)...) {
			name, handler := method.Name, method.Handler
			recorded := *method
			recorded.Handler = func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				calls.record(name, call)
				return handler(ctx, call)
			}
			if err := daemon.RegisterMethod(&recorded); err != nil {
				t.Fatal(err)
			}
		}
	})
	twoCall := []string{
		sidecar.DaemonMethodDevicesRevokeBegin, sidecar.DaemonMethodDevicesRevokeFinish,
		sidecar.DaemonMethodDevicesCosignBegin, sidecar.DaemonMethodDevicesCosignFinish,
		sidecar.DaemonMethodApprovalsDecideBegin, sidecar.DaemonMethodApprovalsDecideFinish,
		sidecar.DaemonMethodKeysPresenceBegin, sidecar.DaemonMethodKeysPresenceProve, sidecar.DaemonMethodKeysPresenceFinish,
	}
	origin := []string{"chrome-extension://" + testNativeHostChromeId + "/"}
	for _, name := range twoCall {
		revocation := strings.Contains(name, "revoke")
		request := `{"jsonrpc":"2.0","id":1,"method":"` + name + `","params":{"act_id":"00000000-0000-0000-0000-000000000000"}}`
		asking := `{"jsonrpc":"2.0","id":2,"method":"` + name + `","ur_confirmed":true}`

		// the real allow-list
		stdout, _, code := runTestNativeHost(t, daemon.socketPath, nil, origin, request, asking)
		if code != urExitOk {
			t.Fatalf("%s: exit %d", name, code)
		}
		replies := testNativeHostReplies(t, stdout)
		if len(replies) != 2 {
			t.Fatalf("%s: %d replies", name, len(replies))
		}
		code0, message0 := testNativeHostError(replies[0])
		if revocation && message0 != nativeHostRevokeNotCapable {
			t.Errorf("%s on the real list: %d %q, not REVOKE_NOT_CAPABLE", name, code0, message0)
		}
		if !revocation && code0 != -32601 {
			t.Errorf("%s on the real list: %d %q, not refused at the relay", name, code0, message0)
		}
		if code1, _ := testNativeHostError(replies[1]); code1 != -32600 {
			t.Errorf("%s asking for the confirmation: %v", name, replies[1])
		}

		// a list that names it
		stdout, _, code = runTestNativeHost(t, daemon.socketPath, twoCall, origin, request)
		if code != urExitOk {
			t.Fatalf("%s: exit %d", name, code)
		}
		replies = testNativeHostReplies(t, stdout)
		if len(replies) != 1 {
			t.Fatalf("%s: %d replies", name, len(replies))
		}
		named, namedMessage := testNativeHostError(replies[0])
		if revocation && namedMessage != nativeHostRevokeNotCapable {
			t.Errorf("%s on a list naming it: %d %q, not REVOKE_NOT_CAPABLE", name, named, namedMessage)
		}
		if !revocation && named != sidecar.DaemonRpcConfirmationRequired {
			t.Errorf("%s on a list naming it: %d %q, not the daemon's refusal", name, named, namedMessage)
		}
	}
	if methods, _ := calls.snapshot(); len(methods) != 0 {
		t.Errorf("the daemon ran %v", methods)
	}
}
