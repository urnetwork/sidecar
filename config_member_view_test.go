package sidecar

import "testing"

func TestMemberViewReadsThePublishedBase(t *testing.T) {
	world := newTestConfigClientWorld(t)
	world.net.consentedMember("browser member")
	world.net.fold(world.net.owner, world.net.n, 2)
	world.publish()
	client := world.client(nil)
	want := world.caughtUp(client)
	state, head, policy, err := client.ReadMemberView(t.Context())
	if err != nil || state == nil || head == nil || policy == nil {
		t.Fatalf("published member view: %v", err)
	}
	if state.Pin().GetVersion() != want.Pin().GetVersion() || head.FoldedThrough() != state.Base().GetFoldedThrough() {
		t.Fatal("the view mixes a log and a different base")
	}
}
