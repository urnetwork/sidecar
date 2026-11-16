// I-18 for §13.15's bodies (tls_api.go): each field a server keeps names the §2.8 row that shows it, in that row's own
// words, and each it keeps nowhere says why, so a field added to a body cannot reach a store unnoticed.

package sidecartest

import (
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// Where one body field lives: a row and words of its sees, a question it waits on, or why nothing keeps it.
type testTlsApiField struct {
	row     string
	sees    string
	pending string
	nowhere string
}

// Every JSON field of every body, by type and name.
var testTlsApiFields = map[reflect.Type]map[string]testTlsApiField{
	reflect.TypeFor[sidecar.TlsCertRecord](): {
		"cert_id":               {row: "cert-1", sees: "cert_id"},
		"network_id":            {row: "cert-1", sees: "network_id"},
		"client_id":             {row: "cert-1", sees: "client_id"},
		"sidecar_id":            {row: "cert-1", sees: "sidecar_id"},
		"identifier_set_sha256": {row: "cert-1", sees: "identifier-set hash"},
		"spki_sha256":           {row: "cert-1", sees: "SPKI hash"},
		"attestation":           {row: "cert-1", sees: "the identity-key attestation"},
		"csr":                   {row: "cert-1", sees: "the CSR (public key and names)"},
		"ca":                    {row: "cert-1", sees: "CA, account URI, profile"},
		"account_uri":           {row: "cert-1", sees: "account URI"},
		"profile":               {row: "cert-1", sees: "profile"},
		"serial":                {row: "cert-1", sees: "serial"},
		"not_before":            {row: "cert-1", sees: "validity"},
		"not_after":             {row: "cert-1", sees: "validity"},
		"ari_window_start":      {row: "cert-1", sees: "ARI window"},
		"ari_window_end":        {row: "cert-1", sees: "ARI window"},
		"state":                 {row: "cert-1", sees: "state and successor"},
		"state_time":            {row: "cert-1", sees: "the time of its latest state"},
		"successor_cert_id":     {row: "cert-1", sees: "state and successor"},
		"chain":                 {row: "cert-1", sees: "issued chains until 30 d after expiry or revocation"},
		"revocation_reason":     {row: "cert-1", sees: "a requested revocation's reason"},
		"custom_host":           {row: "cert-1", sees: "per custom row its host and domain"},
		"custom_domain":         {row: "cert-1", sees: "per custom row its host and domain"},
		"custom_reason":         {row: "cert-1", sees: "and a reason"},
		"wait_ms":               {nowhere: "a wait computed for this answer from the budgets' spends and the holds"},
		"host_ready":            {row: "dns-1", sees: "map version and readiness"},
		"owner":                 {row: "dns-1", sees: "custom-host maps"},
	},
	reflect.TypeFor[sidecar.TlsCertsResult](): {
		"certs":       {nowhere: "a list of TlsCertRecord, whose fields are mapped above"},
		"queued_csrs": {row: "cert-1", sees: "queued CSRs (v1)"},
		"accounts":    {nowhere: "a list of TlsCustomAccount, whose fields are mapped below"},
	},
	reflect.TypeFor[sidecar.TlsCertOrderArgs](): {
		"csr":         {row: "cert-1", sees: "the CSR (public key and names)"},
		"attestation": {row: "cert-1", sees: "the identity-key attestation"},
		"replaces":    {nowhere: "plan-TLS-small-readings#7: replaces rides the request and no row stores it"},
	},
	reflect.TypeFor[sidecar.TlsCertOrderResult](): {
		"cert_id":        {row: "cert-1", sees: "cert_id"},
		"state":          {row: "cert-1", sees: "state and successor"},
		"retry_after_ms": {nowhere: "a wait computed for this answer from the queue's holds"},
	},
	reflect.TypeFor[sidecar.TlsCertOrderStatus](): {
		"state":            {row: "cert-1", sees: "state and successor"},
		"retry_after_ms":   {nowhere: "a wait computed for this answer from the queue's holds"},
		"chain":            {row: "cert-1", sees: "issued chains until 30 d after expiry or revocation"},
		"ari_window_start": {row: "cert-1", sees: "ARI window"},
		"ari_window_end":   {row: "cert-1", sees: "ARI window"},
	},
	reflect.TypeFor[sidecar.TlsCertRegisterArgs](): {
		"cert_id":          {row: "cert-1", sees: "cert_id"},
		"claim_seq":        {row: "cert-1", sees: "the claim sequence"},
		"chain":            {row: "cert-1", sees: "Team custom-domain chains"},
		"account_uri":      {row: "cert-1", sees: "account URI"},
		"ari_window_start": {row: "cert-1", sees: "ARI window"},
		"ari_window_end":   {row: "cert-1", sees: "ARI window"},
	},
	reflect.TypeFor[sidecar.TlsCustomRefusal](): {
		"reason":         {nowhere: "a refusal's word, computed for this answer"},
		"retry_after_ms": {nowhere: "a wait computed for this answer from the lease, the spends or the holds"},
		"cert_id":        {row: "cert-1", sees: "cert_id"},
		"key_seq":        {row: "cert-1", sees: "key sequence"},
	},
	reflect.TypeFor[sidecar.TlsCustomAccount](): {
		"domain":              {row: "cert-1", sees: "per domain the account's URI"},
		"ca":                  {row: "cert-1", sees: "CA, key sequence"},
		"account_uri":         {row: "cert-1", sees: "per domain the account's URI"},
		"key_seq":             {row: "cert-1", sees: "key sequence"},
		"key_thumbprint":      {row: "cert-1", sees: "the current and next key's thumbprints (public)"},
		"key_repo_id":         {row: "cert-1", sees: "the ids of the secret repos holding the key file"},
		"next_key_thumbprint": {row: "cert-1", sees: "the current and next key's thumbprints (public)"},
		"next_key_repo_id":    {row: "cert-1", sees: "the ids of the secret repos holding the key file"},
		"lock_sidecar_id":     {row: "cert-1", sees: "the lock's holder sidecar"},
		"lock_retry_after_ms": {nowhere: "a wait computed for this answer from the lock's lease"},
		"hold_new_ms":         {nowhere: "a wait computed for this answer from the rate-limit holds"},
		"hold_all_ms":         {nowhere: "a wait computed for this answer from the rate-limit holds"},
		"acme_name":           {row: "api-3", sees: "each domain's acme_token"},
	},
	reflect.TypeFor[sidecar.TlsCustomClaimArgs](): {
		"domain":  {row: "cert-1", sees: "per domain the account's URI"},
		"purpose": {row: "cert-1", sees: "the lock's holder sidecar, purpose, row and lease"},
		"cert_id": {row: "cert-1", sees: "cert_id"},
		"key_seq": {row: "cert-1", sees: "key sequence"},
	},
	reflect.TypeFor[sidecar.TlsCustomClaimResult](): {
		"claim_seq":     {row: "cert-1", sees: "the claim sequence"},
		"lease_ms":      {nowhere: "a wait computed for this answer from the lock's lease"},
		"record":        {nowhere: "a TlsCertRecord, whose fields are mapped above"},
		"order_url":     {row: "cert-1", sees: "the ACME order's URL"},
		"may_order":     {nowhere: "the budgets' grant, computed for this answer"},
		"replaces_leaf": {row: "cert-1", sees: "issued chains until 30 d after expiry or revocation"},
	},
	reflect.TypeFor[sidecar.TlsCustomProgressArgs](): {
		"domain":         {row: "cert-1", sees: "per domain the account's URI"},
		"claim_seq":      {row: "cert-1", sees: "the claim sequence"},
		"cert_id":        {row: "cert-1", sees: "cert_id"},
		"event":          {nowhere: "what the holder learned, which moves the row's state and is not kept"},
		"order_url":      {row: "cert-1", sees: "the ACME order's URL"},
		"retry_after_ms": {row: "cert-1", sees: "rate-limit holds"},
		"reason":         {row: "cert-1", sees: "and a reason"},
		"ari":            {nowhere: "a list of TlsCustomAri, whose fields are mapped below"},
	},
	reflect.TypeFor[sidecar.TlsCustomAri](): {
		"cert_id":          {row: "cert-1", sees: "cert_id"},
		"ari_window_start": {row: "cert-1", sees: "ARI window"},
		"ari_window_end":   {row: "cert-1", sees: "ARI window"},
	},
	reflect.TypeFor[sidecar.TlsCustomAccountArgs](): {
		"domain":         {row: "cert-1", sees: "per domain the account's URI"},
		"op":             {nowhere: "the operation asked, which moves the account row and is not kept"},
		"account_uri":    {row: "cert-1", sees: "per domain the account's URI"},
		"key_seq":        {row: "cert-1", sees: "key sequence"},
		"key_thumbprint": {row: "cert-1", sees: "the current and next key's thumbprints (public)"},
		"key_repo_id":    {row: "cert-1", sees: "the ids of the secret repos holding the key file"},
		"claim_seq":      {row: "cert-1", sees: "the claim sequence"},
	},
	reflect.TypeFor[sidecar.TlsCustomChallengeArgs](): {
		"domain": {row: "api-3", sees: "verified domains"},
		"value":  {row: "dns-1", sees: "challenge TXT values"},
	},
	reflect.TypeFor[sidecar.TlsCustomChallengeResult](): {
		"challenge_id": {row: "dns-1", sees: "serials"},
		"readiness":    {nowhere: "GET /dns/ready's answer, passed through"},
	},
	reflect.TypeFor[sidecar.TlsCertRevokeArgs](): {
		"cert_id":        {row: "cert-1", sees: "cert_id"},
		"key_compromise": {row: "cert-1", sees: "a requested revocation's reason"},
	},
	reflect.TypeFor[sidecar.TlsSuspendArgs](): {
		"network_id": {row: "tls-4", sees: "kill-switch entries"},
		"host":       {row: "tls-4", sees: "a host or all the network's hosts"},
		"reason":     {row: "tls-4", sees: "a host or all the network's hosts, reason, until"},
		"until":      {row: "tls-4", sees: "a host or all the network's hosts, reason, until"},
	},
	reflect.TypeFor[sidecar.TlsKillEntry](): {
		"host":   {row: "tls-4", sees: "a host or all the network's hosts"},
		"reason": {row: "tls-4", sees: "a host or all the network's hosts, reason, until"},
		"until":  {row: "tls-4", sees: "a host or all the network's hosts, reason, until"},
	},
}

// The JSON names of a struct's fields.
func testTlsJsonNames(structType reflect.Type) []string {
	names := []string{}
	for field := range structType.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name != "" && name != "-" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func TestTlsApiFieldsAreEachPlaced(t *testing.T) {
	for structType, fields := range testTlsApiFields {
		if got, want := testTlsJsonNames(structType), slices.Sorted(maps.Keys(fields)); !slices.Equal(got, want) {
			t.Errorf("%s has fields %q, and this file places %q", structType.Name(), got, want)
		}
		for name, field := range fields {
			placed := 0
			for _, placement := range []string{field.sees, field.pending, field.nowhere} {
				if placement != "" {
					placed += 1
				}
			}
			if placed != 1 || (field.nowhere == "") != (field.row != "") {
				t.Errorf("%s.%s is placed %+v", structType.Name(), name, field)
			}
		}
	}
}

func TestTlsApiFieldsQuoteLiveRows(t *testing.T) {
	list, err := LoadMetadataList()
	if err != nil {
		t.Fatal(err)
	}
	for structType, fields := range testTlsApiFields {
		for _, name := range slices.Sorted(maps.Keys(fields)) {
			field := fields[name]
			if field.row == "" {
				continue
			}
			row := list.Row(field.row)
			if row == nil || !row.Live() {
				t.Errorf("%s.%s names %s, which is withdrawn or no row", structType.Name(), name, field.row)
				continue
			}
			if field.pending != "" {
				t.Logf("%s.%s waits on %s", structType.Name(), name, field.pending)
				continue
			}
			if !strings.Contains(row.Sees, field.sees) {
				t.Errorf("%s.%s: %s no longer says %q", structType.Name(), name, field.row, field.sees)
			}
		}
	}
}
