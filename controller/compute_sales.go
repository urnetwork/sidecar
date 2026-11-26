// Whether credits are on sale (DESIGN-COMPUTE §9.5, Q-BAL-13; BAL-M12-07): the stores' products, `ur compute buy` and
// the apps' purchase sheets open only once a service the network may use can spend credit, a remote model, web search
// or an enclave shape, since credit nothing can spend brings refunds and support work and a store expects what an app
// sells to be usable in it (CO-41). The ledger and its products ship closed and open the day a gate passes.
//
// Each such service registers what it answers for a network from its own file at init: INFER whether the network may
// use a remote model (C§6.3), SRCH whether it may search (C§21.9), ENC whether it may run an enclave shape (C§11.5).
// With none registered, sales are closed for every network; one service whose answer fails counts as closed for it,
// and sales open on any other that says yes.

package controller

import (
	"context"
	"fmt"
	"slices"
	"sync"

	operator "github.com/urnetwork/operator-core"
)

// A service that can spend a network's credit: a remote model, web search or an enclave shape.
type ComputeSpendableService interface {
	// Whether networkId may use the service now, so that credit bought for it can be spent.
	Spendable(env operator.Env, ctx context.Context, networkId operator.Id) (bool, error)
}

var (
	computeSpendableServicesLock sync.Mutex
	computeSpendableServices     = map[string]ComputeSpendableService{}
)

// Registers a service by its name (inference, web_search, enclaves), from its area's own file at init. A nil service,
// an empty name and a name registered twice panic: a build that registers wrongly does not start.
func RegisterComputeSpendableService(name string, service ComputeSpendableService) {
	if name == "" || service == nil {
		panic("compute sales: a spendable service is named and given")
	}
	computeSpendableServicesLock.Lock()
	defer computeSpendableServicesLock.Unlock()
	if _, ok := computeSpendableServices[name]; ok {
		panic(fmt.Sprintf("compute sales: the service %s registered twice", name))
	}
	computeSpendableServices[name] = service
}

// The registered services, by name in name order.
func computeSpendableServicesRegistered() []ComputeSpendableService {
	computeSpendableServicesLock.Lock()
	defer computeSpendableServicesLock.Unlock()
	names := []string{}
	for name := range computeSpendableServices {
		names = append(names, name)
	}
	slices.Sort(names)
	services := []ComputeSpendableService{}
	for _, name := range names {
		services = append(services, computeSpendableServices[name])
	}
	return services
}

// Whether credits are on sale for networkId (Q-BAL-13): open once any registered service says the network may use it,
// closed while none is registered or none says yes. A service whose answer fails counts as no.
func ComputeSalesOpen(env operator.Env, ctx context.Context, networkId operator.Id) bool {
	for _, service := range computeSpendableServicesRegistered() {
		spendable, err := service.Spendable(env, ctx, networkId)
		if err == nil && spendable {
			return true
		}
	}
	return false
}
