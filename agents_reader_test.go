//go:build !ios_extension && !sidecar_http

// A reader holds each card path to its writer (§20.4, D-SKILL-10): another sidecar's version, a tagged sidecar's of a
// card not its own and a removal are passed over and alarmed once, the card before them standing; a card retires at
// its agent's revocation and after RetireAfterIdle with no status, and its name is refused for reuse until
// NameReuseAfter, then taken.

package sidecar

import (
	"errors"
	"testing"
	"time"
)

func TestCardForgedWriterIgnored(t *testing.T) {
	world := newTestAgentCardsWorld(t)
	laptop, phone := world.client(world.laptop), world.client(world.phone)
	registration, err := laptop.Register(world.ctx, &AgentRegisterArgs{Name: "fix", Harness: "ur-harness 1.0", Model: "local-gemma"})
	if err != nil {
		t.Fatal(err)
	}
	forged := *registration.Card
	forged.Model = "a model the agent never ran"
	// another sidecar of the member, and a tagged sidecar the member sponsors, rewrite the laptop's agent's card
	world.forge(world.phone, &forged)
	world.forge(world.cloud, &forged)
	view, err := phone.Card(world.ctx, "fix")
	if err != nil {
		t.Fatal(err)
	}
	if view.Card.Model != "local-gemma" || view.WriterSidecarId != world.laptop || len(view.PassedOver) != 2 {
		t.Fatalf("the card read past its forgeries: %+v, passed over %v", view.Card, view.PassedOver)
	}
	if world.alarmCount() != 2 {
		t.Fatalf("%d alarms for two forged versions", world.alarmCount())
	}
	// read again, each push alarms once a reader
	if _, err := phone.Card(world.ctx, "fix"); err != nil {
		t.Fatal(err)
	}
	if world.alarmCount() != 2 {
		t.Fatalf("%d alarms after a second read", world.alarmCount())
	}
	// a first version claiming another sidecar's agent is no card at all, and a card's own later version still reads
	claimed := &AgentCard{Name: "claimed", AgentId: testConfigId("someone"), SidecarId: world.laptop, Started: world.clock.Now()}
	world.forge(world.phone, claimed)
	if _, err := laptop.Card(world.ctx, "claimed"); !errors.Is(err, ErrAgentCardAbsent) {
		t.Fatalf("a card its sidecar never wrote: %v", err)
	}
	// a removal is passed over: a card is retired, never removed
	repo := world.agentsRepo()
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		repo.put(world.laptop, AgentCardPath("fix"), nil)
	}()
	if view, err := phone.Card(world.ctx, "fix"); err != nil || view.Card.Model != "local-gemma" {
		t.Fatalf("the card past a removal: %+v, %v", view, err)
	}
}

func TestCardRetireOnRevokeAndIdle(t *testing.T) {
	world := newTestAgentCardsWorld(t)
	laptop, phone := world.client(world.laptop), world.client(world.phone)
	revoked, err := laptop.Register(world.ctx, &AgentRegisterArgs{Name: "fix", Harness: "ur-harness 1.0"})
	if err != nil {
		t.Fatal(err)
	}
	idle, err := laptop.Register(world.ctx, &AgentRegisterArgs{Name: "idle", Harness: "ur-harness 1.0"})
	if err != nil {
		t.Fatal(err)
	}
	// AgentRevoke tombstones fix's subkey: the laptop retires its card, and no other sidecar may
	if _, err := phone.Retire(world.ctx, "fix"); !errors.Is(err, ErrAgentsNotWriter) {
		t.Fatalf("another device retiring a card that is not idle: %v", err)
	}
	world.revoked[revoked.AgentId] = true
	names, err := laptop.RetireRevoked(world.ctx)
	if err != nil || len(names) != 1 || names[0] != "fix" {
		t.Fatalf("retired at revocation: %v, %v", names, err)
	}
	if views, err := phone.Cards(world.ctx, false); err != nil || len(views) != 1 || views[0].Card.Name != "idle" {
		t.Fatalf("the cards standing: %d, %v", len(views), err)
	}
	if views, err := phone.Cards(world.ctx, true); err != nil || len(views) != 2 {
		t.Fatalf("the cards with the retired: %d, %v", len(views), err)
	}
	// the name is refused for reuse until NameReuseAfter: another agent takes fix-2
	world.clock.Set(world.clock.Now().Add(world.settings.NameReuseAfter - time.Minute))
	early, err := phone.Register(world.ctx, &AgentRegisterArgs{Name: "fix", Harness: "codex 0.80"})
	if err != nil || early.Name != "fix-2" {
		t.Fatalf("a registration of fix before its reuse: %+v, %v", early, err)
	}
	// idle: no status for RetireAfterIdle, so any untagged consented device of the member retires it
	world.clock.Set(world.clock.Now().Add(2 * time.Minute))
	retired, err := phone.RetireIdle(world.ctx)
	if err != nil {
		t.Fatal(err)
	}
	// fix was retired already and fix-2 registered two minutes ago, so only idle is past the bound
	if len(retired) != 1 || retired[0] != "idle" {
		t.Fatalf("retired as idle: %v", retired)
	}
	view, err := laptop.Card(world.ctx, "idle")
	if err != nil || !view.Card.IsRetired() || view.WriterSidecarId != world.phone || view.Card.AgentId != idle.AgentId {
		t.Fatalf("the idle card: %+v, %v", view, err)
	}
	if view, err := laptop.Card(world.ctx, "fix-2"); err != nil || view.Card.IsRetired() {
		t.Fatalf("an agent registered a minute ago retired as idle: %+v, %v", view, err)
	}
	// past NameReuseAfter, another agent takes fix, and every reader takes its card
	taken, err := phone.Register(world.ctx, &AgentRegisterArgs{Name: "fix", Harness: "codex 0.80"})
	if err != nil || taken.Name != "fix" || taken.AgentId == revoked.AgentId {
		t.Fatalf("a registration of fix past its reuse: %+v, %v", taken, err)
	}
	if view, err := laptop.Card(world.ctx, "fix"); err != nil || view.Card.SidecarId != world.phone || view.Card.IsRetired() {
		t.Fatalf("the reused card as the laptop reads it: %+v, %v", view, err)
	}
	if world.alarmCount() != 0 {
		t.Fatalf("%d alarms with no forgery", world.alarmCount())
	}
}
