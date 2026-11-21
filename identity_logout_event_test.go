//go:build !sidecar_http && !js && !ios_extension

package sidecar

import "testing"

func TestCompletedLogoutRetainsItsDaemonEventOrigin(t *testing.T) {
	world := newTestEnrollWorld(t)
	if err := world.enroll(t.Context()); err != nil {
		t.Fatal(err)
	}
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOffline, 1))
	world.installAuthority(t, nil)
	identity := world.sidecar.Identity()
	events := newDaemonEvents(DefaultSidecarSettings().LocalSettings, nil)
	detach := events.Attach(world.sidecar)
	defer detach()
	cursor := events.cursorOf(0)
	if err := world.sidecar.Logout(t.Context()); err != nil {
		t.Fatal(err)
	}
	reply, err := events.next(t.Context(), nil, cursor, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range reply.Events {
		if event.LoggedOut && event.NetworkId != nil && *event.NetworkId == identity.NetworkId &&
			event.OriginSidecarId != nil && *event.OriginSidecarId == identity.SidecarId &&
			event.State == string(SidecarStateUnenrolled) && event.Generation == identity.Generation {
			return
		}
	}
	t.Fatal("the daemon did not emit a completed logout for the removed identity")
}
