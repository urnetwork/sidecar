package controller

// Whether credits are on sale (BAL-M12-07; DESIGN-COMPUTE §9.5, Q-BAL-13): closed while no service that can spend
// credit is registered, closed while none registered says the network may use it or each that would fails, and open
// once one says yes; a second registration of a name, an empty name and a nil service panic.

import (
	"context"
	"errors"
	"testing"

	operator "github.com/urnetwork/operator-core"
)

// A service whose answer a test sets, for the networks it names.
type testSpendableService struct {
	networkIds map[operator.Id]bool
	err        error
}

func (self *testSpendableService) Spendable(env operator.Env, ctx context.Context, networkId operator.Id) (bool, error) {
	return self.networkIds[networkId], self.err
}

// Empties the registry for the test, putting back what stood after it.
func testComputeSalesRegistry(t *testing.T) {
	computeSpendableServicesLock.Lock()
	saved := computeSpendableServices
	computeSpendableServices = map[string]ComputeSpendableService{}
	computeSpendableServicesLock.Unlock()
	t.Cleanup(func() {
		computeSpendableServicesLock.Lock()
		defer computeSpendableServicesLock.Unlock()
		computeSpendableServices = saved
	})
}

func TestComputeSalesClosedUntilAServiceRegisters(t *testing.T) {
	testComputeSalesRegistry(t)
	env := newTestLedgerEnv()
	ctx := context.Background()
	open, closed := operator.Id{1}, operator.Id{2}
	if ComputeSalesOpen(env, ctx, open) {
		t.Fatal("sales open with no service registered")
	}
	// a service that fails, and one that says no, keep sales closed
	RegisterComputeSpendableService("enclaves", &testSpendableService{networkIds: map[operator.Id]bool{open: true}, err: errors.New("unread")})
	RegisterComputeSpendableService("web_search", &testSpendableService{networkIds: map[operator.Id]bool{}})
	if ComputeSalesOpen(env, ctx, open) {
		t.Fatal("sales open on a failing service's word")
	}
	// one that says yes for a network opens sales for it alone
	RegisterComputeSpendableService("inference", &testSpendableService{networkIds: map[operator.Id]bool{open: true}})
	if !ComputeSalesOpen(env, ctx, open) || ComputeSalesOpen(env, ctx, closed) {
		t.Fatal("sales do not follow the service that can spend")
	}
	for label, register := range map[string]func(){
		"twice":   func() { RegisterComputeSpendableService("inference", &testSpendableService{}) },
		"no name": func() { RegisterComputeSpendableService("", &testSpendableService{}) },
		"nil":     func() { RegisterComputeSpendableService("fetch", nil) },
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
