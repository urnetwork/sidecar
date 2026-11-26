//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The stores' compute products (BAL-M12-09; DESIGN-COMPUTE §9.5, D-BAL-8): each product id and what it grants as
// vectors; the family telling compute's ids from Pro's; an id the settings do not list being no product; and the
// device's client offering the same products in both stores.

import (
	"testing"
)

func TestComputeStoreProductsVectors(t *testing.T) {
	type vector struct {
		productId string
		monthly   bool
		credits   int64
	}
	vectors := []vector{
		{productId: "compute.credits_10", credits: 10},
		{productId: "compute.credits_25", credits: 25},
		{productId: "compute.credits_50", credits: 50},
		{productId: "compute.credits_100", credits: 100},
		{productId: "compute.monthly_10", monthly: true, credits: 10},
		{productId: "compute.monthly_25", monthly: true, credits: 25},
		{productId: "compute.monthly_50", monthly: true, credits: 50},
		{productId: "compute.monthly_100", monthly: true, credits: 100},
	}
	products := ComputeStoreProducts(nil)
	if len(products) != len(vectors) {
		t.Fatalf("%d products, %d vectors", len(products), len(vectors))
	}
	for i, v := range vectors {
		product := products[i]
		if product.ProductId != v.productId || product.Monthly != v.monthly || product.Credits != v.credits {
			t.Errorf("product %d: %+v, want %+v", i, product, v)
		}
		if ComputeStoreProductId(v.monthly, v.credits) != v.productId || !ComputeStoreProductFamilyOf(v.productId) {
			t.Errorf("%s: its id or family", v.productId)
		}
		found, ok := ComputeStoreProductOf(nil, v.productId)
		if !ok || *found != *product {
			t.Errorf("%s: looked up as %+v", v.productId, found)
		}
	}
	// Pro's products, and ids the settings do not list, are none of compute's
	for _, productId := range []string{"supporter", "supporter_yearly", "supporter_monthly_26", "supporter_yearly_26", "compute.credits_5", "compute.monthly_250", "compute.", "credits_10", "Compute.credits_10"} {
		if _, ok := ComputeStoreProductOf(nil, productId); ok {
			t.Errorf("%s is a compute product", productId)
		}
	}
	for _, productId := range []string{"supporter", "supporter_yearly_26", "data_1tib"} {
		if ComputeStoreProductFamilyOf(productId) {
			t.Errorf("Pro's %s is of compute's family", productId)
		}
	}
	// a product the settings retire is no product
	retired := DefaultComputeStoreProductSettings()
	retired.ConsumableCredits = []int64{25}
	if _, ok := ComputeStoreProductOf(retired, "compute.credits_10"); ok {
		t.Error("a retired product is still sold")
	}
	// the device's client offers the same products in both stores
	client := newTestComputeClient(t, newTestComputeHost(t, testComputeApi(nil)), nil)
	for _, market := range []ComputeMarket{ComputeMarketAppStore, ComputeMarketGooglePlay} {
		packs, err := client.Packs(market)
		if err != nil {
			t.Fatal(err)
		}
		if len(packs) != len(vectors) {
			t.Fatalf("%s: %d packs", market, len(packs))
		}
		for i, pack := range packs {
			if pack.Market != market || pack.ProductId != vectors[i].productId || pack.Monthly != vectors[i].monthly || pack.Credits != vectors[i].credits {
				t.Errorf("%s pack %d: %+v", market, i, pack)
			}
		}
	}
}
