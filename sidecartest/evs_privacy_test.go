//go:build sidecar_testhooks

// The metadata guard over evs's stores (§22.7's guard, I-18, §2.8; EVS1-M2-42): what S2's run (evs_s2_test.go) leaves
// on every cluster and in Redis is classified by family, and every family must be one a live row of metadata_list.yml
// names, so evs stores only §2.8's evs fields, place/ and every family of the guard's list among them, and a new
// family with no row fails here.

package sidecartest_test

import (
	"context"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// §22.5's "servers get only §2.8's evs and gkm fields" (§23.4's exit row) for what S2 leaves: every object family on
// every cluster and every Redis family is one a live row of metadata_list.yml names, place/ among them.
func TestS2StoresOnlyListedFamilies(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	evsS2Run(t, net)
	guard, err := sidecartest.LoadSchemaGuard()
	if err != nil {
		t.Fatal(err)
	}
	redisKeys := []string{}
	for key := range net.Fakes().Redis.Dump() {
		redisKeys = append(redisKeys, key)
	}
	findings, err := guard.CheckStores(sidecartest.InspectContext(context.Background()), &sidecartest.SchemaGuardStores{
		Blobs: net.Host().Blobs, RedisKeys: redisKeys,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		t.Errorf("%s", finding)
	}
	if len(redisKeys) == 0 {
		t.Error("S2 left no Redis key to classify")
	}
}
