package computeservice

// The reference provider's shell (PROV-M12-01; DESIGN-COMPUTE §11.3, D-ENC-2): inference not offered, every VM call
// and its shapes forwarded to ENC's side, nothing offered without one. Its refusal in production is
// provider_registry_test.go's.

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A VM side that records what it was asked. Safe for concurrent use.
type recordingComputeEnclaveSide struct {
	stateLock sync.Mutex
	calls     []string
	catalog   *ComputeProviderCatalog
}

func (self *recordingComputeEnclaveSide) called(call string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, call)
}

func (self *recordingComputeEnclaveSide) Catalog(ctx context.Context) (*ComputeProviderCatalog, error) {
	self.called("catalog")
	return self.catalog, nil
}

func (self *recordingComputeEnclaveSide) CreateVm(ctx context.Context, spec *ComputeVmSpec) (*ComputeVm, error) {
	self.called("create " + spec.ShapeId)
	return &ComputeVm{VmId: "vm-1", State: ComputeVmCreating, SetupHost: "setup.reference.example", SetupPort: 2222}, nil
}

func (self *recordingComputeEnclaveSide) VmEvidence(ctx context.Context, vmId string, nonce []byte) (*ComputeEvidence, error) {
	self.called("evidence " + vmId + " " + string(nonce))
	return &ComputeEvidence{Scheme: sidecar.ComputePolicySchemeEnclave, Document: []byte("quote")}, nil
}

func (self *recordingComputeEnclaveSide) VmStatus(ctx context.Context, vmId string) (*ComputeVm, error) {
	self.called("status " + vmId)
	return &ComputeVm{VmId: vmId, State: ComputeVmRunning}, nil
}

func (self *recordingComputeEnclaveSide) DeleteVm(ctx context.Context, vmId string) error {
	self.called("delete " + vmId)
	return nil
}

// Every inference, direct and money call answers ErrComputeNotOffered, whatever side it has, and it takes no payment.
func TestReferenceProviderOffersNoInference(t *testing.T) {
	ctx := context.Background()
	provider := NewReferenceProvider(&recordingComputeEnclaveSide{})
	if provider.Id() != ComputeProviderIdReference {
		t.Fatalf("its id is %q", provider.Id())
	}
	calls := map[string]func() error{
		"InstanceKeys": func() error { _, err := provider.InstanceKeys(ctx, "model"); return err },
		"Evidence":     func() error { _, err := provider.Evidence(ctx, "model", "instance", []byte("nonce")); return err },
		"Invoke":       func() error { _, err := provider.Invoke(ctx, &ComputeInvoke{}); return err },
		"Usage":        func() error { _, err := provider.Usage(ctx, "request"); return err },
		"DirectTarget": func() error { _, err := provider.DirectTarget("model"); return err },
		"DirectUsage":  func() error { _, err := provider.DirectUsage(ctx, []byte("nonce"), []byte("hash")); return err },
		"VerifyReceipt": func() error {
			_, err := provider.VerifyReceipt([]byte("receipt"), []byte("hash"))
			return err
		},
		"Balance": func() error { _, err := provider.Balance(ctx); return err },
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, ErrComputeNotOffered) {
			t.Errorf("%s answered %v", name, err)
		}
	}
	if payment := provider.Payment(); payment.Method != ComputeProviderPaymentNone {
		t.Fatalf("it takes a payment: %+v", payment)
	}
}

// Each VM call and the catalog reach ENC's side with what was asked and answer what it answered, the catalog as the
// reference provider's own; a side answering models is refused, since the reference provider serves no inference.
func TestReferenceProviderForwardsVmCallsToItsEnclaveSide(t *testing.T) {
	ctx := context.Background()
	side := &recordingComputeEnclaveSide{catalog: &ComputeProviderCatalog{
		GammaNanoUsd: 1_000_000_000,
		Shapes:       []*ComputeProviderShape{{ShapeId: "cpu-2", Label: sidecar.ComputeLabelAp, HourNanoGamma: 52_000_000}},
	}}
	provider := NewReferenceProvider(side)
	catalog, err := provider.Catalog(ctx)
	if err != nil || catalog.Provider != ComputeProviderIdReference || len(catalog.Shapes) != 1 || catalog.Shapes[0].ShapeId != "cpu-2" {
		t.Fatalf("the catalog reads %+v, %v", catalog, err)
	}
	vm, err := provider.CreateVm(ctx, &ComputeVmSpec{ShapeId: "cpu-2", Incarnation: 1})
	if err != nil || vm.VmId != "vm-1" || vm.SetupHost != "setup.reference.example" || vm.SetupPort != 2222 {
		t.Fatalf("create answered %+v, %v", vm, err)
	}
	evidence, err := provider.VmEvidence(ctx, "vm-1", []byte("n1"))
	if err != nil || string(evidence.Document) != "quote" {
		t.Fatalf("evidence answered %+v, %v", evidence, err)
	}
	if vm, err := provider.VmStatus(ctx, "vm-1"); err != nil || vm.State != ComputeVmRunning {
		t.Fatalf("status answered %+v, %v", vm, err)
	}
	if err := provider.DeleteVm(ctx, "vm-1"); err != nil {
		t.Fatal(err)
	}
	if want := []string{"catalog", "create cpu-2", "evidence vm-1 n1", "status vm-1", "delete vm-1"}; !slices.Equal(side.calls, want) {
		t.Fatalf("the side was asked %v", side.calls)
	}

	side.catalog = &ComputeProviderCatalog{Models: []*ComputeProviderModel{{ModelId: "a-model"}}}
	if catalog, err := provider.Catalog(ctx); err == nil || catalog != nil {
		t.Fatalf("a side answering models read %+v", catalog)
	}
}

// With no side registered, it offers no VM call and no shape, and the registry's constructor builds it so.
func TestReferenceProviderWithoutSideOffersNoVm(t *testing.T) {
	ctx := context.Background()
	settings := DefaultComputeProviderSettings()
	settings.Environment = "local"
	provider, err := constructReferenceProviderWith(&ComputeProviderArgs{Id: ComputeProviderIdReference, Settings: settings}, nil)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := provider.Catalog(ctx)
	if err != nil || len(catalog.Shapes) != 0 || len(catalog.Models) != 0 {
		t.Fatalf("its catalog reads %+v, %v", catalog, err)
	}
	if _, err := provider.CreateVm(ctx, &ComputeVmSpec{ShapeId: "cpu-2"}); !errors.Is(err, ErrComputeNotOffered) {
		t.Fatalf("create: %v", err)
	}
	if _, err := provider.VmEvidence(ctx, "vm-1", nil); !errors.Is(err, ErrComputeNotOffered) {
		t.Fatalf("evidence: %v", err)
	}
	if _, err := provider.VmStatus(ctx, "vm-1"); !errors.Is(err, ErrComputeNotOffered) {
		t.Fatalf("status: %v", err)
	}
	if err := provider.DeleteVm(ctx, "vm-1"); !errors.Is(err, ErrComputeNotOffered) {
		t.Fatalf("delete: %v", err)
	}

	// a registered side is built from the same args, and its failure is the constructor's
	built := false
	if _, err := constructReferenceProviderWith(&ComputeProviderArgs{Id: ComputeProviderIdReference, Settings: settings}, func(args *ComputeProviderArgs) (ComputeEnclaveSide, error) {
		built = args.Id == ComputeProviderIdReference
		return nil, errors.New("no cloud project in this env")
	}); err == nil || !built {
		t.Fatalf("a failing side built: %v", err)
	}
	// ENC's registration point takes one side, never two or none
	saved := computeEnclaveSideRegistration
	t.Cleanup(func() { computeEnclaveSideRegistration = saved })
	computeEnclaveSideRegistration = nil
	side := func(args *ComputeProviderArgs) (ComputeEnclaveSide, error) {
		return &recordingComputeEnclaveSide{}, nil
	}
	registerComputeEnclaveSide(side)
	for label, register := range map[string]func(){
		"twice": func() { registerComputeEnclaveSide(side) },
		"none":  func() { registerComputeEnclaveSide(nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s registered", label)
				}
			}()
			register()
		}()
	}
}
