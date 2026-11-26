//go:build !ios_extension && !sidecar_http && !js

package model

// The ledger's settings and the root's store products name the same consumables and subscriptions (BAL-M12-09 beside
// BAL-M12-01; DESIGN-COMPUTE §9.5): server credits by the root's ComputeStoreProducts, so the two lists stay one.

import (
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
)

func TestComputeStoreProductsMatchTheLedger(t *testing.T) {
	ledger := DefaultComputeLedgerSettings()
	products := sidecar.DefaultComputeStoreProductSettings()
	if !slices.Equal(ledger.StoreConsumableCredits, products.ConsumableCredits) {
		t.Errorf("the consumables are %v here and %v in the products", ledger.StoreConsumableCredits, products.ConsumableCredits)
	}
	if !slices.Equal(ledger.StoreSubscriptionCredits, products.SubscriptionCredits) {
		t.Errorf("the subscriptions are %v here and %v in the products", ledger.StoreSubscriptionCredits, products.SubscriptionCredits)
	}
}
