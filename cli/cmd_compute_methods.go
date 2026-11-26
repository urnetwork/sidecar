// ur daemon's compute methods (DESIGN-COMPUTE §9.11, §15.1, §15.3; BAL-M12-18): the root's DaemonComputeMethods
// (BAL-M12-17), which ur compute and a remote-mode app's Compute() call, registered with every other control method,
// with compute.redeem refused to a caller that has a harness process among its ancestors, as terms accept is (§9.11):
// a code is a person's to redeem, at their own terminal or in an app, never an agent's, and the daemon reads the
// caller's ancestry from the peer's pid, which the caller cannot set. A caller the daemon cannot name is refused too,
// the closed reading. ur native-host relays none of these (QD-1253): its allow-list holds no compute method.

package main

import (
	"context"
	"errors"

	"github.com/urnetwork/sidecar"
)

// What compute.redeem answers a caller under a harness.
var errUrComputeRedeemUnderHarness = errors.New("a promotion code is redeemed by a person, never under a harness process (§9.11)")

// Whether the call's process has a harness process of its network's runs among its ancestors; true where the daemon
// cannot name the caller or its network. A test replaces it.
var urComputeUnderHarness = func(ctx context.Context, call *sidecar.DaemonCall) bool {
	pid := urCallPid(call)
	if pid <= 0 || call.Sidecar == nil {
		return true
	}
	return call.Sidecar.HarnessAncestor(ctx, pid)
}

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urComputeMethods)
}

// The compute methods over target, the root's, guarded, where it hosts Sidecars; none for a target that hosts none.
func urComputeMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	if _, ok := target.(*urDaemonNetwork); !ok {
		return nil
	}
	return urComputeGuardMethods(sidecar.DaemonComputeMethods(nil))
}

// methods with compute.redeem refused under a harness before its handler runs; the rest as they are.
func urComputeGuardMethods(methods []*sidecar.DaemonMethod) []*sidecar.DaemonMethod {
	guarded := []*sidecar.DaemonMethod{}
	for _, method := range methods {
		if method.Name != sidecar.DaemonMethodComputeRedeem {
			guarded = append(guarded, method)
			continue
		}
		copied := *method
		handler := method.Handler
		copied.Handler = func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			if urComputeUnderHarness(ctx, call) {
				return nil, errUrComputeRedeemUnderHarness
			}
			return handler(ctx, call)
		}
		guarded = append(guarded, &copied)
	}
	return guarded
}
