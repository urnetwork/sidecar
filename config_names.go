//go:build !ios_extension

// §7.7's client names: DNS labels keyed on the sidecar_id, from the config head's names file, duplicates taking -2, -3
// in admission order (RA:948-971), from which private names derive (owner decision 85, §12.9). Signers and verifiers
// refuse as a client name a reserved name or owner (§12.5, §12.7), a word-number label (§15.9) and a scope label
// (§13.8), so a name a device shows never shadows a platform name, a burner or a Team scope.
//
// A client name is a lowercase LDH label of 1 to 50 bytes with no dash at either end and no two dashes as its third
// and fourth characters, so -2, -3 and on stay within a DNS label's 63 bytes. The names file is sealed in the config
// repo: names never reach rows or a server (§22.7's privacy canaries).
//
// On every leg, with no connect import. Nothing here creates, derives or unwraps a key. Package-level functions are
// safe for concurrent use.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A client name's longest form, before a duplicate's suffix. A format value: -N for any admission count stays within
// a DNS label.
const configClientNameMaxByteCount = 50

var (
	// Not a client name: not a 1 to 50 byte lowercase LDH label, a dash at an end, or two dashes at the third and
	// fourth characters.
	ErrConfigClientNameInvalid = errors.New("client name must be 1 to 50 lowercase letters, digits and dashes, with no dash at either end")
	// A name the platform keeps: reserved (§12.5's list, §12.7's owners), a word-number label (§15.9) or a scope label
	// (§13.8).
	ErrConfigClientNameReserved = errors.New("client name is reserved")
	// The names file names one sidecar twice.
	ErrConfigNamesMalformed = errors.New("config names malformed")
)

// Whether name may be a client's name, given the network's Team scope labels (§13.8; none before M6).
func ValidateConfigClientName(name string, scopeLabels []string) error {
	if len(name) == 0 || configClientNameMaxByteCount < len(name) || !isDnsLowerBytes(name, "-") {
		return ErrConfigClientNameInvalid
	}
	if name[0] == '-' || name[len(name)-1] == '-' {
		return ErrConfigClientNameInvalid
	}
	if 4 <= len(name) && name[2:4] == "--" {
		return ErrConfigClientNameInvalid
	}
	if IsReservedDnsLabel(name) || IsWordNumberDnsLabel(name) || slices.Contains(scopeLabels, name) {
		return ErrConfigClientNameReserved
	}
	return nil
}

// The label each named sidecar resolves to: its name, or for a duplicate the name with -2, -3 and on, in admission
// order, the first free one. Admission order is SidecarRow.admitted_at, then sidecar_id. Only sidecars rows has are
// named, tombstones included, so a revoked sidecar keeps its place until its row drops; a name for a sidecar not yet
// admitted waits for its admission. A refused name in the table refuses the table, as signers and verifiers refuse it.
func ConfigNames(table *protocol.ConfigNameTable, sidecars []*bridge.SidecarRow, scopeLabels []string) (map[Id]string, error) {
	names := map[Id]string{}
	for _, entry := range table.GetNames() {
		sidecarId, err := IdFromBytes(entry.GetSidecarId())
		if err != nil {
			return nil, fmt.Errorf("%w: a sidecar_id of %d bytes", ErrConfigNamesMalformed, len(entry.GetSidecarId()))
		}
		if _, ok := names[sidecarId]; ok {
			return nil, fmt.Errorf("%w: %s is named twice", ErrConfigNamesMalformed, sidecarId)
		}
		if err := ValidateConfigClientName(entry.GetName(), scopeLabels); err != nil {
			return nil, fmt.Errorf("%s: %w", sidecarId, err)
		}
		names[sidecarId] = entry.GetName()
	}

	admitted := []*bridge.SidecarRow{}
	for _, row := range sidecars {
		sidecarId, err := IdFromBytes(row.GetSidecarId())
		if err != nil {
			return nil, fmt.Errorf("%w: a row's sidecar_id", ErrConfigNamesMalformed)
		}
		if _, ok := names[sidecarId]; ok {
			admitted = append(admitted, row)
		}
	}
	slices.SortFunc(admitted, func(a *bridge.SidecarRow, b *bridge.SidecarRow) int {
		if a.GetAdmittedAt() != b.GetAdmittedAt() {
			if a.GetAdmittedAt() < b.GetAdmittedAt() {
				return -1
			}
			return 1
		}
		return bytes.Compare(a.GetSidecarId(), b.GetSidecarId())
	})

	labels := map[Id]string{}
	taken := map[string]bool{}
	for _, row := range admitted {
		sidecarId, _ := IdFromBytes(row.GetSidecarId())
		name := names[sidecarId]
		label := name
		for suffix := 2; taken[label]; suffix += 1 {
			label = name + "-" + strconv.Itoa(suffix)
		}
		taken[label] = true
		labels[sidecarId] = label
	}
	return labels, nil
}
