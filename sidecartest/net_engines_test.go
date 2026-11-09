package sidecartest

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
)

// What a T3 Net's stores cannot carry out is refused where the schedule arms it, as a fake refuses its own.
func TestFaultQueueCheckRefusesAPlanAtAdd(t *testing.T) {
	queue := NewFaultQueue()
	errParked := errors.New("a real store parks nothing")
	queue.SetCheck(func(plan *FaultPlan) error {
		if plan.Result == Delay {
			return errParked
		}
		return nil
	})
	if _, err := queue.Add(&FaultPlan{Op: FaultOpPut, Result: Delay}); !errors.Is(err, errParked) {
		t.Errorf("a delay was armed: %v", err)
	}
	if _, err := queue.Add(&FaultPlan{Op: FaultOpPut, Result: ApplyThenDrop}); err != nil {
		t.Errorf("a lost response was refused: %v", err)
	}
	if unfired := queue.Unfired(); len(unfired) != 1 || unfired[0].Result != ApplyThenDrop {
		t.Errorf("armed %v", unfired)
	}
	// validate's own rules still come first
	queue.SetCheck(nil)
	if _, err := queue.Add(&FaultPlan{Op: FaultOpGet, Result: Precondition}); err == nil {
		t.Error("a GET took a condition")
	}
}

// Take is the fakes' own take: it fires the plan, counts the operation, and takes nothing under
// InspectContext.
func TestFaultQueueTakeIsTheFakesTake(t *testing.T) {
	queue := NewFaultQueue()
	fired, err := queue.Add(&FaultPlan{Op: FaultOpPgCommit, Nth: 2, Result: ApplyThenDrop})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if plan := queue.Take(InspectContext(ctx), FaultOpPgCommit, "", "", true); plan != nil {
		t.Errorf("an oracle's read took %v", plan)
	}
	if plan := queue.Take(ctx, FaultOpPgCommit, "", "", true); plan != nil {
		t.Errorf("the first commit took %v", plan)
	}
	plan := queue.Take(ctx, FaultOpPgCommit, "", "", true)
	if plan == nil || plan.Result != ApplyThenDrop {
		t.Fatalf("the second commit took %v", plan)
	}
	select {
	case <-fired:
	default:
		t.Error("the plan did not fire")
	}
	if results := queue.WriteResults(FaultOpPgCommit); !slices.Equal(results, []FaultResult{0, ApplyThenDrop}) {
		t.Errorf("counted %v", results)
	}
}

// A host whose closing the test can see.
type netEnginesRecord struct {
	closed       bool
	engineClosed bool
	order        []string
}

type netEnginesEngine struct {
	record *netEnginesRecord
}

func (self *netEnginesEngine) Ready() bool {
	return true
}

func (self *netEnginesEngine) Drain() {}

func (self *netEnginesEngine) Close() {
	self.record.engineClosed = true
	self.record.order = append(self.record.order, "engine")
}

// NetSettings.Engines hosts the engines, Blobs still behind the recorder FI-30 reads, and the host closes
// after its engines.
func TestNetEnginesHostTheEngines(t *testing.T) {
	record := &netEnginesRecord{}
	var built *Net
	other := NewFakeHost(t.Context(), nil, nil, nil, nil)
	settings := DefaultNetSettings()
	settings.Engines = func(ctx context.Context, net *Net) (*sidecar.ServiceHost, func(), error) {
		built = net
		host := net.Fakes().ServiceHost()
		host.Redis = other.Redis
		host.Blobs = other.Blobs
		return host, func() {
			record.closed = true
			record.order = append(record.order, "host")
		}, nil
	}
	net := NewNet(t.Context(), settings)
	if built != net {
		t.Fatal("Engines was not given the Net")
	}
	if net.Host().Redis != sidecar.Redis(other.Redis) {
		t.Error("the engines' Redis is not the host's")
	}
	if _, ok := net.Host().Blobs.(*BlobRecorder); !ok {
		t.Errorf("the engines' Blobs are not recorded: %T", net.Host().Blobs)
	}
	if _, err := net.AddEngine("engine", func(ctx context.Context, host *sidecar.ServiceHost) (sidecar.Engine, error) {
		return &netEnginesEngine{record: record}, nil
	}); err != nil {
		t.Fatal(err)
	}
	net.Close()
	if !record.closed || !record.engineClosed {
		t.Errorf("closed host %t, engine %t", record.closed, record.engineClosed)
	}
	if !slices.Equal(record.order, []string{"engine", "host"}) {
		t.Errorf("closed in the order %v", record.order)
	}
	other.Redis.Close()
}

// A host Engines cannot build leaves no Net to run on.
func TestNetEnginesErrorPanics(t *testing.T) {
	settings := DefaultNetSettings()
	errStack := errors.New("the stack is down")
	settings.Engines = func(ctx context.Context, net *Net) (*sidecar.ServiceHost, func(), error) {
		return nil, nil, errStack
	}
	defer func() {
		recovered := recover()
		err, ok := recovered.(error)
		if !ok || !errors.Is(err, errStack) {
			t.Errorf("recovered %v", recovered)
		}
	}()
	NewNet(t.Context(), settings)
	t.Error("NewNet returned")
}
