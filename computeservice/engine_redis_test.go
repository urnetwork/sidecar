package computeservice

// §14.4's Redis families (CSRV-M12-01): each builder's key under its one hash tag, the package's calls held to the
// CROSSSLOT lint, every family in a row of §2.8's list where I-18's guard reads it, and {cmpa} on its own instance alone.

import (
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/crossslot"
)

// One key of every family, by the row of §2.8's list that names it (metadata_list.yml, QD-1367).
func testComputeFamilyKeys() map[string][]string {
	networkId := testComputeId("network-a")
	hotkey := sha256.Sum256([]byte("a provider's hotkey"))
	return map[string][]string{
		"compute-1":  {ComputeNetworkRedisKey(networkId), ComputeDirectInFlightRedisKey(hotkey[:]), ComputeDirectPendingRedisKey(hotkey[:])},
		"compute-2":  {ComputePromoFailureRedisKey(networkId)},
		"compute-4":  {ComputeEnclaveRedisKey(testComputeId("enclave-1"))},
		"compute-6":  {ComputeBudgetRedisKey(networkId, testComputeId("agent-1"))},
		"compute-9":  {ComputeCollateralRedisKey(sha256.Sum256([]byte("a vendor's item")))},
		"compute-10": {ComputeSearchRateRedisKey(networkId), ComputeSearchLimiterRedisKey(), ComputeSearchAdmissionsRedisKey()},
		"compute-11": {ComputeSearchOutcomesRedisKey()},
	}
}

// A key's family as I-18's guard reads one: the tag's first word through its underscore, then what follows the tag
// through its first colon (sidecartest's schema_guard_keys.go).
func testComputeRedisFamily(key string) sidecartest.MetadataFamily {
	tagEnd := strings.IndexByte(key, '}')
	tag := key[1:tagEnd]
	if underscore := strings.IndexByte(tag, '_'); 0 <= underscore {
		tag = tag[:underscore+1]
	}
	suffix := key[tagEnd+1:]
	if colon := strings.IndexByte(suffix, ':'); 0 <= colon {
		suffix = suffix[:colon+1]
	}
	return sidecartest.MetadataFamily{Kind: sidecartest.MetadataFamilyRedis, Name: "{" + tag + "}" + suffix}
}

// Every call the package makes passes the CROSSSLOT lint, and each family's keys carry one tag: a network's holds and
// budget counters share theirs, so one script reaches both, and two networks never share one.
func TestComputeKeysKeepOneTagAScript(t *testing.T) {
	findings, err := crossslot.Check(".", ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		t.Errorf("CROSSSLOT: %s", finding)
	}
	for _, keys := range testComputeFamilyKeys() {
		for _, key := range keys {
			if !sidecar.RedisKeysShareTag([]string{key, key}) {
				t.Errorf("%s carries no tag", key)
			}
		}
	}
	networkId := testComputeId("network-a")
	holds := ComputeNetworkRedisKey(networkId)
	budget := ComputeBudgetRedisKey(networkId, testComputeId("agent-1"))
	if !sidecar.RedisKeysShareTag([]string{holds, budget}) {
		t.Fatalf("%s and %s share no tag, so one script cannot hold and check the budgets", holds, budget)
	}
	if sidecar.RedisKeysShareTag([]string{holds, ComputeNetworkRedisKey(testComputeId("network-b"))}) {
		t.Fatal("two networks' holds share a tag")
	}
	if sidecar.RedisKeysShareTag([]string{holds, ComputeSearchRateRedisKey(networkId)}) {
		t.Fatal("a network's search rate shares its holds' slot, which §14.4 keeps apart")
	}
}

// Every family's key, as it would sit in a store, belongs to a live row of §2.8's list (I-18; the schema guard's
// run-time half), and the row is the one metadata_list.yml names it under.
func TestComputeKeyFamiliesHaveRows(t *testing.T) {
	guard, err := sidecartest.LoadSchemaGuard()
	if err != nil {
		t.Fatal(err)
	}
	list, err := sidecartest.LoadMetadataList()
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for rowId, rowKeys := range testComputeFamilyKeys() {
		keys = append(keys, rowKeys...)
		row := list.Row(rowId)
		if row == nil || !row.Live() {
			t.Fatalf("%s is no live row", rowId)
		}
		for _, key := range rowKeys {
			family := testComputeRedisFamily(key)
			if !slices.Contains(row.Families(), family) {
				t.Errorf("%s's family %s is not in %s's store", key, family.Name, rowId)
			}
		}
	}
	findings, err := guard.CheckStores(t.Context(), &sidecartest.SchemaGuardStores{RedisKeys: keys})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		t.Error(finding)
	}
	// and a family no row names fails the same check
	findings, err = guard.CheckStores(t.Context(), &sidecartest.SchemaGuardStores{RedisKeys: []string{"{cmpz_00}"}})
	if err != nil || len(findings) != 1 {
		t.Fatalf("a stray family: %v %v", findings, err)
	}
}

// {cmpa} lives on the admissions instance alone and every other family on the host's Redis: each instance refuses
// the other's keys, a call naming keys of two tags is refused before Redis is asked, and a block with no admissions
// instance answers {cmpa} with an error.
func TestComputeAdmissionsLiveOnTheirOwnInstance(t *testing.T) {
	fixture := newComputeFixture(t, nil)
	engine := fixture.engine
	admissions := ComputeSearchAdmissionsRedisKey()
	holds := ComputeNetworkRedisKey(fixture.networkId)
	if redis, err := engine.RedisFor(admissions); err != nil || redis != sidecar.Redis(fixture.admissionsRedis) {
		t.Fatalf("{cmpa} went to %v: %v", redis, err)
	}
	if redis, err := engine.RedisFor(holds); err != nil || redis != sidecar.Redis(fixture.redis) {
		t.Fatalf("{cmp_} went to %v: %v", redis, err)
	}
	if _, err := engine.MainRedis(holds, admissions); !errors.Is(err, ErrComputeRedisInstance) {
		t.Fatalf("{cmpa} on the main instance: %v", err)
	}
	if _, err := engine.AdmissionsRedis(admissions, holds); !errors.Is(err, ErrComputeRedisInstance) {
		t.Fatalf("{cmp_} on the admissions instance: %v", err)
	}
	if _, err := engine.MainRedis(holds, ComputeSearchRateRedisKey(fixture.networkId)); err == nil {
		t.Fatal("a call across two tags was taken")
	}
	if _, err := engine.MainRedis(holds, ComputeBudgetRedisKey(fixture.networkId, testComputeId("agent-1"))); err != nil {
		t.Fatalf("a network's holds and budgets: %v", err)
	}
	bare, err := NewComputeEngine(fixture.ctx, fixture.host, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bare.Close)
	if _, err := bare.RedisFor(admissions); err == nil {
		t.Fatal("a block with no admissions instance answered {cmpa}")
	}
}
