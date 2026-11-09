// §7.7's client names (config_names.go). Pure, on every leg.

package sidecar

import (
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Duplicates take -2, -3 in admission order, the first free one, admitted_at then sidecar_id deciding; a name for
// a sidecar not yet admitted waits; a row's tombstone keeps its place.
func TestConfigNamesTakeSuffixesInAdmissionOrder(t *testing.T) {
	laptop := testConfigId("laptop")
	phone := testConfigId("phone")
	tablet := testConfigId("tablet")
	desktop := testConfigId("desktop")
	pending := testConfigId("pending")
	table := &protocol.ConfigNameTable{Names: []*protocol.ConfigName{
		{SidecarId: phone.Bytes(), Name: "alice"},
		{SidecarId: laptop.Bytes(), Name: "alice"},
		{SidecarId: tablet.Bytes(), Name: "alice"},
		{SidecarId: desktop.Bytes(), Name: "alice-2"},
		{SidecarId: pending.Bytes(), Name: "bob"},
	}}
	rows := []*bridge.SidecarRow{
		{SidecarId: tablet.Bytes(), AdmittedAt: 9},
		{SidecarId: phone.Bytes(), AdmittedAt: 5},
		{SidecarId: laptop.Bytes(), AdmittedAt: 2, RevokedAt: 11},
		{SidecarId: desktop.Bytes(), AdmittedAt: 7},
	}
	labels, err := ConfigNames(table, rows, nil)
	if err != nil {
		t.Fatal(err)
	}
	for sidecarId, want := range map[Id]string{laptop: "alice", phone: "alice-2", desktop: "alice-2-2", tablet: "alice-3"} {
		if labels[sidecarId] != want {
			t.Fatalf("%s: %q, want %q (all: %v)", sidecarId, labels[sidecarId], want, labels)
		}
	}
	if _, ok := labels[pending]; ok {
		t.Fatal("a sidecar not yet admitted was named")
	}

	// equal admission positions fall back to the id, so every reader agrees
	tied := []*bridge.SidecarRow{{SidecarId: phone.Bytes(), AdmittedAt: 3}, {SidecarId: laptop.Bytes(), AdmittedAt: 3}, {SidecarId: tablet.Bytes(), AdmittedAt: 3}}
	first, err := ConfigNames(table, tied, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ConfigNames(table, []*bridge.SidecarRow{tied[2], tied[0], tied[1]}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for sidecarId, label := range first {
		if second[sidecarId] != label {
			t.Fatalf("%s: %q and %q", sidecarId, label, second[sidecarId])
		}
	}
}

// Signers and verifiers refuse a reserved name, a word-number label and a scope label, and what is no label.
func TestConfigClientNamesRefuseReservedNames(t *testing.T) {
	for _, name := range []string{"laptop", "a", "alice-2", "build-box-7"} {
		if err := ValidateConfigClientName(name, nil); err != nil {
			t.Fatalf("%q: %v", name, err)
		}
	}
	for name, want := range map[string]error{
		"":                       ErrConfigClientNameInvalid,
		"Laptop":                 ErrConfigClientNameInvalid,
		"-laptop":                ErrConfigClientNameInvalid,
		"laptop-":                ErrConfigClientNameInvalid,
		"xn--laptop":             ErrConfigClientNameInvalid,
		"lap_top":                ErrConfigClientNameInvalid,
		"laptop.home":            ErrConfigClientNameInvalid,
		string(make([]byte, 51)): ErrConfigClientNameInvalid,
		"mail":                   ErrConfigClientNameReserved,
		"blue-4242":              ErrConfigClientNameReserved,
		"engineering":            ErrConfigClientNameReserved,
	} {
		if err := ValidateConfigClientName(name, []string{"engineering"}); !errors.Is(err, want) {
			t.Fatalf("%q: err = %v, want %v", name, err, want)
		}
	}

	// a table with one refused name is refused whole, as is one naming a sidecar twice
	phone := testConfigId("phone")
	rows := []*bridge.SidecarRow{{SidecarId: phone.Bytes(), AdmittedAt: 1}}
	if _, err := ConfigNames(&protocol.ConfigNameTable{Names: []*protocol.ConfigName{{SidecarId: phone.Bytes(), Name: "mail"}}}, rows, nil); !errors.Is(err, ErrConfigClientNameReserved) {
		t.Fatalf("a reserved name: %v", err)
	}
	twice := &protocol.ConfigNameTable{Names: []*protocol.ConfigName{{SidecarId: phone.Bytes(), Name: "one"}, {SidecarId: phone.Bytes(), Name: "two"}}}
	if _, err := ConfigNames(twice, rows, nil); !errors.Is(err, ErrConfigNamesMalformed) {
		t.Fatalf("a sidecar named twice: %v", err)
	}
}
