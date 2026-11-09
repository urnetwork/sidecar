package fault

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/sidecartest"
)

// A row that asks a Net on a platform for a link's conditions or a contract's class, which T3's exchange cannot apply,
// fails at the step that asked, naming what it asked for: it ran without it. The same row passes on the fakes, and a
// row that asks for neither passes on the platform.
func TestARowAskingAPlatformForWhatItCannotApplyFails(t *testing.T) {
	a, b := connect.NewId(), connect.NewId()
	schedule := func(ask func(net *Net)) *Schedule {
		return &Schedule{
			Id:    "platform-unapplied",
			Tiers: []Tier{TierT2, TierT3},
			Steps: []*Step{
				{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
					return nil
				}},
				{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
					ask(net)
					return nil
				}},
			},
		}
	}
	run := func(onPlatform bool, ask func(net *Net)) *Result {
		settings := sidecartest.DefaultNetSettings()
		if onPlatform {
			// never built: asking for a link or a class opens no client
			settings.Platform = func(ctx context.Context, net *Net) (sidecartest.NetPlatform, error) {
				return nil, errors.New("this test opens no client")
			}
		}
		net := sidecartest.NewNet(t.Context(), settings)
		defer net.Close()
		return Run(t.Context(), schedule(ask), net)
	}
	partition := func(net *Net) {
		net.SetLink(a, b, &sidecartest.LinkConditions{Partition: true})
	}
	controlClass := func(net *Net) {
		net.SetContractClass(a, b, protocol.ContractClass_ContractClassControl)
	}
	for _, ask := range []func(net *Net){partition, controlClass} {
		result := run(true, ask)
		if result.Err == nil || result.FailedStep != 1 || !strings.Contains(result.Err.Error(), "cannot apply") {
			t.Errorf("%s", result)
		}
		wantPass(t, run(false, ask))
	}
	wantPass(t, run(true, func(net *Net) {
		net.SetLink(a, b, nil)
	}))
}

// The shape of a row with connect clients, which server's T3 runs on its exchange from the same builder: two clients
// trade a message each way inside one actor's step, sending and waiting with the baton given up, and each holds a
// sealed session with the other.
func TestAClientRowTradesMessagesInOneStep(t *testing.T) {
	RunTest(t, &Schedule{
		Id:    "clients",
		Tiers: []Tier{TierT2, TierT3},
		Steps: []*Step{
			{Actor: "daemonA", Action: func(ctx context.Context, net *Net) error {
				a, err := net.OpenClient("a", nil)
				if err != nil {
					return err
				}
				b, err := net.OpenClient("b", nil)
				if err != nil {
					return err
				}
				asks := make(chan *sidecartest.NetMessage, 4)
				defer b.ReceiveMessages(asks)()
				answers := make(chan *sidecartest.NetMessage, 4)
				defer a.ReceiveMessages(answers)()
				if err := a.SendMessage(b.ClientId, "ask"); err != nil {
					return err
				}
				ask, err := net.AwaitMessage(ctx, asks)
				if err != nil {
					return err
				}
				if ask.Source != a.ClientId || ask.Content != "ask" {
					return errors.New("the ask came wrong")
				}
				if err := b.SendMessage(a.ClientId, "answer"); err != nil {
					return err
				}
				if _, err := net.AwaitMessage(ctx, answers); err != nil {
					return err
				}
				if !a.Sealed(b.ClientId) || !b.Sealed(a.ClientId) {
					return errors.New("a pair traded messages with no sealed session")
				}
				return nil
			}},
		},
	}, nil)
}

// A wait for a message gives up the actor's baton: one actor waits for what only another actor's later step sends,
// and the run neither stalls nor leaves the schedule's order.
func TestAwaitMessageGivesUpTheBaton(t *testing.T) {
	messages := make(chan *sidecartest.NetMessage, 1)
	RunTest(t, &Schedule{
		Id:    "await-message",
		Tiers: []Tier{TierT2},
		Steps: []*Step{
			{Actor: "waiter", Background: true, Action: func(ctx context.Context, net *Net) error {
				message, err := net.AwaitMessage(ctx, messages)
				if err != nil {
					return err
				}
				if message.Content != "from the sender" {
					return errors.New("the waiter read another message")
				}
				return nil
			}},
			{Actor: "sender", Action: func(ctx context.Context, net *Net) error {
				messages <- &sidecartest.NetMessage{Content: "from the sender"}
				return nil
			}},
			{Actor: "waiter", Join: true},
		},
	}, nil)
}

// A wait for a message that never comes ends with the context's error.
func TestAwaitMessageEndsWithItsContext(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if message, err := net.AwaitMessage(ctx, make(chan *sidecartest.NetMessage)); message != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("%v, %v", message, err)
	}
}
