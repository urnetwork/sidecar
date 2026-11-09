//go:build !sidecar_http

// I-18 for §9's route bodies (socket_api.go, and socket_ticket.go's key): each field a caller shows sockets names the
// §2.8 row that shows it, in that row's own words, and each the service only answers with says why no row needs it, so
// a field added to a body cannot reach the service unnoticed. Find's protocol, minimum version and ALPN stay off the
// wire until sock-2 names them (plan-SOCK-metadata-rows), so they carry no JSON name and do not appear here.

package sidecartest

import (
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// Where one body field lives: a row and words of its sees, or why no row needs it.
type testSocketApiField struct {
	row     string
	sees    string
	nowhere string
}

// Every JSON field of every body, by type and name.
var testSocketApiFields = map[reflect.Type]map[string]testSocketApiField{
	reflect.TypeFor[sidecar.SocketRegistrationsArgs](): {
		"set_version":   {row: "sock-5", sees: "a client's set_version"},
		"key_start":     {nowhere: "a page's range rides its request, and the keys it bounds are sock-5's entries"},
		"key_end":       {nowhere: "a page's range rides its request, and the keys it bounds are sock-5's entries"},
		"registrations": {nowhere: "a list of SocketRegistration, whose fields are placed below"},
	},
	reflect.TypeFor[sidecar.SocketRegistration](): {
		"name":        {row: "sock-1", sees: "for tls/, smtp/ and ur/, in plaintext"},
		"name_token":  {row: "sock-1", sees: "the name as a token path"},
		"sealed_name": {row: "sock-1", sees: "the sealed name"},
		"listen_id":   {row: "sock-1", sees: "listen_id"},
		"protocol":    {row: "sock-1", sees: "protocol, version, ALPN"},
		"version":     {row: "sock-1", sees: "protocol, version, ALPN"},
		"alpn":        {row: "sock-1", sees: "protocol, version, ALPN"},
		"app_mode":    {row: "sock-1", sees: "application mode (http or raw"},
		"weight":      {row: "sock-1", sees: "weight"},
		"max_streams": {row: "sock-1", sees: "max_streams"},
		"exclusive":   {row: "sock-1", sees: "flags (exclusive, affinity, serving, draining)"},
		"affinity":    {row: "sock-1", sees: "flags (exclusive, affinity, serving, draining)"},
		"serving":     {row: "sock-1", sees: "flags (exclusive, affinity, serving, draining)"},
		"draining":    {row: "sock-1", sees: "flags (exclusive, affinity, serving, draining)"},
		"inflight":    {row: "sock-1", sees: "reported in-flight"},
		"claim":       {row: "sock-1", sees: "its Signed claim (the sidecar's identity key)"},
	},
	reflect.TypeFor[sidecar.SocketRegistrationsResult](): {
		"statuses":        {nowhere: "the service's verdict on each entry, made for this answer"},
		"set_version":     {row: "sock-5", sees: "a client's set_version"},
		"server_time":     {nowhere: "the service's clock, read for this answer"},
		"ticket_keys":     {nowhere: "the service's own public keys (§9.8), which are no caller's"},
		"urnetwork_edge":  {nowhere: "the platform network's id from config/<env>/sidecar.yml, which is no caller's"},
		"streams_stopped": {nowhere: "§20.7's spent mark for the caller's network, read for this answer"},
		"error":           {nowhere: "a refusal made for this answer"},
	},
	reflect.TypeFor[sidecar.SocketError](): {
		"code":           {nowhere: "a refusal made for this answer"},
		"retry_after_ms": {nowhere: "a wait made for this answer"},
	},
	reflect.TypeFor[sidecar.SocketTicketKey](): {
		"key_id":             {nowhere: "the service's own public key (§9.8), which is no caller's"},
		"public_key":         {nowhere: "the service's own public key (§9.8), which is no caller's"},
		"expire_time_millis": {nowhere: "the service's own public key (§9.8), which is no caller's"},
	},
	reflect.TypeFor[sidecar.SocketFindArgs](): {
		"name":       {row: "sock-2", sees: "token path or edge name"},
		"name_token": {row: "sock-2", sees: "token path or edge name"},
		// the network whose group a Find reads, which sock-1 keys
		"network_id":     {row: "sock-1", sees: "network_id"},
		"affinity_key":   {row: "sock-2", sees: "affinity key (tlsedge's keyed /24 or /48 hash, never stored)"},
		"failed_tickets": {nowhere: "a list of SocketFailedTicket, whose fields are placed below"},
		"client_ids":     {row: "sock-2", sees: "edges add their K client ids"},
	},
	reflect.TypeFor[sidecar.SocketFailedTicket](): {
		"ticket": {row: "sock-2", sees: "the failed tickets a retry reports"},
		"reason": {row: "sock-2", sees: "reported accept timeouts"},
	},
	reflect.TypeFor[sidecar.SocketFindTicket](): {
		"ticket": {row: "sock-2", sees: "issued tickets"},
		"claim":  {row: "sock-1", sees: "its Signed claim (the sidecar's identity key)"},
	},
	reflect.TypeFor[sidecar.SocketFindResult](): {
		"primary": {nowhere: "a SocketFindTicket, whose fields are placed above"},
		"backup":  {nowhere: "a SocketFindTicket, whose fields are placed above"},
		"error":   {nowhere: "a refusal made for this answer"},
	},
	reflect.TypeFor[sidecar.SocketListName](): {
		"name":        {row: "sock-4", sees: "edge names"},
		"name_token":  {row: "sock-4", sees: "registered token paths"},
		"sealed_name": {row: "sock-4", sees: "with sealed names"},
	},
	reflect.TypeFor[sidecar.SocketListResult](): {
		"names":       {nowhere: "a list of SocketListName, whose fields are placed above"},
		"next_cursor": {nowhere: "a position in sock-4's listing, made for this answer"},
		"error":       {nowhere: "a refusal made for this answer"},
	},
	reflect.TypeFor[sidecar.SocketKeysResult](): {
		"keys": {nowhere: "a list of SocketTicketKey, whose fields are placed above"},
	},
}

// The JSON names of a struct's fields, "-" left out, since such a field never reaches the wire.
func testSocketJsonNames(structType reflect.Type) []string {
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

func TestSocketApiFieldsAreEachPlaced(t *testing.T) {
	for structType, fields := range testSocketApiFields {
		if got, want := testSocketJsonNames(structType), slices.Sorted(maps.Keys(fields)); !slices.Equal(got, want) {
			t.Errorf("%s has fields %q, and this file places %q", structType.Name(), got, want)
		}
		for name, field := range fields {
			if (field.nowhere == "") == (field.row == "") || (field.row == "") != (field.sees == "") {
				t.Errorf("%s.%s is placed %+v", structType.Name(), name, field)
			}
		}
	}
}

func TestSocketApiFieldsQuoteLiveRows(t *testing.T) {
	list, err := LoadMetadataList()
	if err != nil {
		t.Fatal(err)
	}
	for structType, fields := range testSocketApiFields {
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
			if !strings.Contains(row.Sees, field.sees) {
				t.Errorf("%s.%s: %s no longer says %q", structType.Name(), name, field.row, field.sees)
			}
		}
	}
}

// Find's filter has no row yet, so its fields carry no JSON name: a tag change here is a change to what the service
// sees, and it starts with sock-2's row (plan-SOCK-metadata-rows).
func TestSocketFindFilterStaysOffTheWire(t *testing.T) {
	findArgs := reflect.TypeFor[sidecar.SocketFindArgs]()
	for _, name := range []string{"Protocol", "MinVersion", "Alpn"} {
		field, ok := findArgs.FieldByName(name)
		if !ok {
			t.Errorf("SocketFindArgs has no %s", name)
			continue
		}
		if tag := field.Tag.Get("json"); tag != "-" {
			t.Errorf("SocketFindArgs.%s has the JSON name %q", name, tag)
		}
	}
}
