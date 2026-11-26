//go:build !ios_extension && !sidecar_http && !js

// The stores' compute products (DESIGN-COMPUTE §9.5, D-BAL-8; BAL-M12-09): the compute.* product family the App Store
// and Google Play sell, which server's store paths credit and the apps' sdk offers, both reading it here so the two
// never disagree on what a product grants.
//
//	compute.credits_<n>   a consumable of n credits: 10, 25, 50 and 100
//	compute.monthly_<n>   an auto-renewing subscription granting n credits a month: 10, 25, 50 and 100, in one
//	                      subscription group, so moving between them is a plan change (§9.5)
//
// A product id is an identifier: the family's prefix, the kind and the credits it was made with. What a product grants
// is the settings' (QD-702): a product the settings do not list is no compute product, so retiring one is a settings
// change, never a code one. Both stores sell the same ids, priced in each at the tier that nets at least the web price
// after the commission URnetwork pays there (Q-BAL-3); the price is the store's, so nothing here holds one. A credit is
// one US dollar of compute balance, whichever market sold it.
//
// The family keeps compute and Pro apart: a compute.* product never grants Pro, and Pro's products, none of which
// starts with the family's prefix, never credit compute.

package sidecar

import (
	"slices"
	"strconv"
	"strings"
)

// The prefix every compute product id starts with, and nothing of Pro's does: an identifier.
const ComputeStoreProductFamily = "compute."

// The kinds' words in a product id: identifiers.
const (
	computeStoreProductConsumable   = "credits_"
	computeStoreProductSubscription = "monthly_"
)

// What the stores' compute products grant, in credits, a credit one US dollar (§9.5).
type ComputeStoreProductSettings struct {
	// The consumables: 10, 25, 50 and 100 credits.
	ConsumableCredits []int64
	// The monthly subscriptions, in one subscription group: 10, 25, 50 and 100 credits a month.
	SubscriptionCredits []int64
}

// The defaults, the only place one is set.
func DefaultComputeStoreProductSettings() *ComputeStoreProductSettings {
	return &ComputeStoreProductSettings{
		ConsumableCredits:   []int64{10, 25, 50, 100},
		SubscriptionCredits: []int64{10, 25, 50, 100},
	}
}

// One compute product a store sells.
type ComputeStoreProduct struct {
	// The store's product id, compute.credits_<n> or compute.monthly_<n>.
	ProductId string
	// An auto-renewing subscription granting Credits each month; else a consumable bought once.
	Monthly bool
	Credits int64
}

// The product id of a consumable, or of a monthly subscription, of credits.
func ComputeStoreProductId(monthly bool, credits int64) string {
	kind := computeStoreProductConsumable
	if monthly {
		kind = computeStoreProductSubscription
	}
	return ComputeStoreProductFamily + kind + strconv.FormatInt(credits, 10)
}

// Whether productId is of the compute family, sold or not: what routes a store's report or notification to compute's
// paths rather than Pro's.
func ComputeStoreProductFamilyOf(productId string) bool {
	return strings.HasPrefix(productId, ComputeStoreProductFamily)
}

// Every product the settings list, the consumables first, each kind in its settings' order.
func ComputeStoreProducts(settings *ComputeStoreProductSettings) []*ComputeStoreProduct {
	if settings == nil {
		settings = DefaultComputeStoreProductSettings()
	}
	products := []*ComputeStoreProduct{}
	for _, credits := range settings.ConsumableCredits {
		products = append(products, &ComputeStoreProduct{ProductId: ComputeStoreProductId(false, credits), Credits: credits})
	}
	for _, credits := range settings.SubscriptionCredits {
		products = append(products, &ComputeStoreProduct{ProductId: ComputeStoreProductId(true, credits), Monthly: true, Credits: credits})
	}
	return products
}

// The product productId names, false for one the settings do not sell: a compute.* id the settings do not list, or
// any other id.
func ComputeStoreProductOf(settings *ComputeStoreProductSettings, productId string) (*ComputeStoreProduct, bool) {
	index := slices.IndexFunc(ComputeStoreProducts(settings), func(product *ComputeStoreProduct) bool {
		return product.ProductId == productId
	})
	if index < 0 {
		return nil, false
	}
	return ComputeStoreProducts(settings)[index], true
}

// The stores' products as the device's ComputeClient offers them: the same ids in the App Store and in Google Play.
func init() {
	registerComputeStoreProducts(func(market ComputeMarket) []*ComputePack {
		packs := []*ComputePack{}
		for _, product := range ComputeStoreProducts(nil) {
			packs = append(packs, &ComputePack{Market: market, Monthly: product.Monthly, Credits: product.Credits, ProductId: product.ProductId})
		}
		return packs
	})
}
