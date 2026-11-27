package sidecartest

// DESIGN-COMPUTE's metadata rows (CARCH-M11-03) where I-18's guard reads them: every table and Redis family §14.4 names,
// and those compute-plan-money-schema-gaps and compute-plan-redis-family-rows add (QD-1252, QD-1367), is a family of a
// compute row or of api-7, so no compute task needs a row of its own; and a compute key no row names fails the guard
// wherever compute's server keys live, the broker's package, owner decision 594's packages and the search signer.

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// Each compute store, as the guard reads it from a row: §14.4's MG-C1, MG-C2, MG-S1 and MG-C3 tables and its Redis
// families, with the answers' additions, by the row that names each.
var testComputeRowFamilies = map[string][]MetadataFamily{
	"compute-1": {
		{Kind: MetadataFamilyRedis, Name: "{cmp_}"}, {Kind: MetadataFamilyRedis, Name: "{cmpd_}"}, {Kind: MetadataFamilyRedis, Name: "{cmpp_}"},
		{Kind: MetadataFamilyTable, Name: "compute_op"}, {Kind: MetadataFamilyTable, Name: "compute_charge"},
		{Kind: MetadataFamilyTable, Name: "compute_charge_day"},
	},
	"compute-2": {
		{Kind: MetadataFamilyRedis, Name: "{cmpk_}"}, {Kind: MetadataFamilyTable, Name: "compute_lot"},
		{Kind: MetadataFamilyTable, Name: "compute_promo_code"}, {Kind: MetadataFamilyTable, Name: "compute_promo_redemption"},
		{Kind: MetadataFamilyTable, Name: "compute_payer"}, {Kind: MetadataFamilyTable, Name: "compute_payer_day"},
		{Kind: MetadataFamilyTable, Name: "compute_terms"},
	},
	"compute-3": {
		{Kind: MetadataFamilyTable, Name: "compute_charge_lot"}, {Kind: MetadataFamilyTable, Name: "compute_charge_total"},
		{Kind: MetadataFamilyTable, Name: "compute_charge_pruned"}, {Kind: MetadataFamilyTable, Name: "compute_account"},
		// an operator's hold and its projection (CARCH-M12-01, QD-1438)
		{Kind: MetadataFamilyTable, Name: "compute_abuse_hold"}, {Kind: MetadataFamilyRedis, Name: "{cmp_}:"},
	},
	"compute-4": {
		{Kind: MetadataFamilyRedis, Name: "{cmpe_}"}, {Kind: MetadataFamilyTable, Name: "compute_enclave"},
		{Kind: MetadataFamilyTable, Name: "compute_enclave_event"},
	},
	"compute-6": {
		{Kind: MetadataFamilyRedis, Name: "{cmp_}"}, {Kind: MetadataFamilyTable, Name: "compute_auto_renew"},
		{Kind: MetadataFamilyTable, Name: "compute_budget_raise"},
	},
	"compute-7": {
		{Kind: MetadataFamilyRedis, Name: "{cmpv_}"}, {Kind: MetadataFamilyTable, Name: "compute_provider"},
		{Kind: MetadataFamilyTable, Name: "compute_provider_price"}, {Kind: MetadataFamilyTable, Name: "compute_provider_ledger"},
		{Kind: MetadataFamilyTable, Name: "compute_gamma_deposit"}, {Kind: MetadataFamilyTable, Name: "compute_gamma_op"},
	},
	"compute-8": {{Kind: MetadataFamilyTable, Name: "compute_dispute"}},
	"compute-9": {{Kind: MetadataFamilyRedis, Name: "{cmpc_}"}},
	"compute-10": {
		{Kind: MetadataFamilyRedis, Name: "{cmpr_}"}, {Kind: MetadataFamilyRedis, Name: "{cmps}"}, {Kind: MetadataFamilyRedis, Name: "{cmpa}"},
		{Kind: MetadataFamilyTable, Name: "compute_search_flag"}, {Kind: MetadataFamilyTable, Name: "search_signer_nonce"},
		{Kind: MetadataFamilyTable, Name: "search_signer_day"}, {Kind: MetadataFamilyTable, Name: "search_signer_cursor"},
		{Kind: MetadataFamilyTable, Name: "search_signer_facilitator"}, {Kind: MetadataFamilyTable, Name: "search_signer_screen"},
	},
	"compute-11": {{Kind: MetadataFamilyRedis, Name: "{cmpo}"}, {Kind: MetadataFamilyTable, Name: "compute_search_outcome_hour"}},
	"api-7":      {{Kind: MetadataFamilyRedis, Name: "{scf_}"}},
}

// Every compute store is a family of the row that names it, and each compute row is live with every field.
func TestComputeRowsNameTheirStores(t *testing.T) {
	list, err := LoadMetadataList()
	if err != nil {
		t.Fatal(err)
	}
	for rowId, families := range testComputeRowFamilies {
		row := list.Row(rowId)
		if row == nil || !row.Live() {
			t.Errorf("%s is no live row", rowId)
			continue
		}
		for _, family := range families {
			if !slices.Contains(row.Families(), family) {
				t.Errorf("%s's store does not name %s %s: %v", rowId, family.Kind, family.Name, row.Families())
			}
		}
	}
	if row := list.Row("compute-5"); row == nil || !row.Live() {
		t.Error("compute-5, what the broker relays in transit, is no live row")
	}
}

// The guard over a tree whose map takes the real map's key sources: a compute key a row names passes, and one no row
// names fails in the broker's package, in a server-hosted package's compute file and in the search signer, the last two
// only because the map's key sources reach them.
func TestSchemaGuardHoldsComputeKeysToTheirRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", schemaGuardFieldsPath))
	if err != nil {
		t.Fatal(err)
	}
	realMap := struct {
		KeySources []string `yaml:"key_sources"`
	}{}
	if err := yaml.Unmarshal(data, &realMap); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"controller/compute_*.go", "searchsigner/*.go"} {
		if !slices.Contains(realMap.KeySources, want) {
			t.Fatalf("the map's key sources lack %s: %v", want, realMap.KeySources)
		}
	}
	tree := newTestGuardTree(t)
	tree.list += `compute-1:
  service: compute
  store: compute_op; Redis {cmp_<network_id>}
  sees: holds
  why: settlement
  ttl: an hour
  owner: DESIGN-COMPUTE §14.6
`
	tree.fieldMap += "  compute-1: {planned: M12}\nkey_sources:\n"
	for _, keySource := range realMap.KeySources {
		tree.fieldMap += "  - " + keySource + "\n"
	}
	tree.write("computeservice/broker_keys.go", `package computeservice

func holdKey(networkId string) string { return "{cmp_" + networkId + "}" }
func strayKey(networkId string) string { return "{cmpz_" + networkId + "}" }
`)
	tree.write("controller/compute_ledger.go", `package controller

func ledgerKey(networkId string) string { return "{cmpy_" + networkId + "}" }
`)
	tree.write("controller/other.go", `package controller

func otherKey(networkId string) string { return "{oth_" + networkId + "}" }
`)
	tree.write("searchsigner/signer.go", `package searchsigner

func nonceKey(nonce string) string { return "{ssx_" + nonce + "}" }
`)
	// by family: controller/other.go is no compute file, so the map's sources do not reach its key
	wantGuardFindings(t, tree.findings(),
		`redis family {cmpy_}, from "{cmpy_<>}" at controller/compute_ledger.go:3, is in no row`,
		`redis family {cmpz_}, from "{cmpz_<>}" at computeservice/broker_keys.go:4, is in no row`,
		`redis family {ssx_}, from "{ssx_<>}" at searchsigner/signer.go:3, is in no row`,
	)
}
