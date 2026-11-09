// §12.14's ResolveNetworkLabel on the client (D-DNS-2, X5): the <net> of `.ur`, a git remote, a §9.4
// address or a typed command, to the network it names. On every leg, with no connect.
//
// A client resolves only the networks it belongs to, from NetworkLabelTable: each network's id, its
// label, its alias, the aliases still retiring and its legacy network_name, kept in a sealed file and
// refreshed from api (GET /sidecar/label, plan-DNS-labels-before-m5; GET /dns/zone from M5). Text is
// matched against the label first, then the alias, then a retiring alias, and against the legacy name
// only when a person typed it (interactive), so `.ur` and git remotes, which pass false, never match a
// name another network may later take: network names are released and reused, labels and aliases
// never are (§12.5). A text no row holds is ErrNetworkLabelUnknown, never a guess, and another
// network's label is one, since §6.4 keeps other networks on their ids. Empty text is the only
// network; with two or more it is §5.8's FAILED_PRECONDITION, NetworkLabelAmbiguousError, naming them.
//
// Until api serves labels the table holds each network with no label, so only the empty text resolves.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
)

// The table's file in its store.
const networkLabelTableName = "network_labels.json"

// The table file's format: a reader refuses a higher one rather than misread it.
const networkLabelTableFormat = 1

// What a text matched.
type NetworkLabelKind string

const (
	// The network's label (owner decision 14).
	NetworkLabelKindLabel NetworkLabelKind = "label"
	// Its live alias.
	NetworkLabelKindAlias NetworkLabelKind = "alias"
	// An alias changed or released within its 90 days of retiring (§12.5). It names no other network
	// then or ever, and the caller may tell the person to move to the label.
	NetworkLabelKindRetiringAlias NetworkLabelKind = "retiring_alias"
	// The legacy network_name, which only a person's typed input matches (D-DNS-2).
	NetworkLabelKindLegacyName NetworkLabelKind = "legacy_name"
	// The empty text, for the only network.
	NetworkLabelKindOnly NetworkLabelKind = "only"
)

// A text that names no network this client belongs to, or an interactive-only match for a caller that
// is not.
var ErrNetworkLabelUnknown = errors.New("network label unknown")

// The empty text while this client belongs to several networks, or a text two networks' rows match
// alike: §5.8's FAILED_PRECONDITION, which names the networks for the person to choose from.
type NetworkLabelAmbiguousError struct {
	// Each network's id, in the table's order.
	NetworkIds []Id
	// Each one's label, or its id where it has none yet, in the same order.
	Names []string
}

// The networks, by label where they have one.
func (self *NetworkLabelAmbiguousError) Error() string {
	return "network is ambiguous: one of " + strings.Join(self.Names, ", ")
}

// §12.14's ResolveNetworkLabel(root, text, interactive) -> (networkId, kind), which §8, §9, §13 and
// §15's client code call. root is the user root, such as the one dns.yml names; text a label, an alias
// or, when interactive, a legacy network name, in any ASCII case, with or without .<root>. Safe for
// concurrent use.
type NetworkLabelResolver interface {
	ResolveNetworkLabel(root string, text string, interactive bool) (Id, NetworkLabelKind, error)
}

// One network this client belongs to, under one root.
type NetworkLabelRow struct {
	// The user root, lowercase with no trailing dot.
	Root      string `json:"root"`
	NetworkId Id     `json:"network_id"`
	// Empty until api allocates one.
	Label string `json:"label,omitempty"`
	// Empty while the network has none.
	Alias string `json:"alias,omitempty"`
	// Aliases in their 90 days of retiring, which still name this network.
	RetiringAliases []string `json:"retiring_aliases,omitempty"`
	// network_name as api last gave it.
	LegacyName string `json:"legacy_name,omitempty"`
}

// The table's file.
type networkLabelTableFile struct {
	Format int               `json:"format"`
	Rows   []NetworkLabelRow `json:"rows"`
}

// The client's NetworkLabelResolver: a table of the networks this client belongs to, kept in one
// sealed file so `.ur` and git remotes resolve while api is unreachable. Every change is written
// before it is seen, so a reader never resolves through a row a crash would lose. Safe for concurrent
// use.
type NetworkLabelTable struct {
	store SidecarStore

	// one change at a time: each is read, written to the store and then installed, in that order
	writeLock sync.Mutex

	stateLock sync.Mutex
	rows      []NetworkLabelRow
}

// The table in store, empty when the store holds none.
func OpenNetworkLabelTable(store SidecarStore) (*NetworkLabelTable, error) {
	if store == nil {
		return nil, errors.New("network labels: no store")
	}
	table := &NetworkLabelTable{store: store}
	reader, err := store.Open(networkLabelTableName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return table, nil
	}
	if err != nil {
		return nil, fmt.Errorf("network labels: %w", err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("network labels: %w", err)
	}
	file := &networkLabelTableFile{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(file); err != nil {
		return nil, fmt.Errorf("network labels: %s is not a table: %w", networkLabelTableName, err)
	}
	if file.Format != networkLabelTableFormat {
		return nil, fmt.Errorf("network labels: %s has format %d, and this release reads %d", networkLabelTableName, file.Format, networkLabelTableFormat)
	}
	for index := range file.Rows {
		row, err := canonicalNetworkLabelRow(file.Rows[index])
		if err != nil {
			return nil, err
		}
		file.Rows[index] = row
	}
	if err := checkNetworkLabelRows(file.Rows); err != nil {
		return nil, err
	}
	table.rows = file.Rows
	return table, nil
}

// A root as rows keep it: ASCII lowercase, with no trailing dot.
func canonicalNetworkLabelRoot(root string) string {
	return strings.TrimSuffix(dnsAsciiLower(strings.TrimSpace(root)), ".")
}

// Whether root is a name of lowercase LDH labels, two or more.
func isNetworkLabelRoot(root string) bool {
	labels := strings.Split(root, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !isDnsLowerLdhLabel(label) {
			return false
		}
	}
	return true
}

// row with its names folded to lowercase, or why it cannot be a row. Names are held to the LDH shape
// alone: an alias claimed under older rules stays this network's after the rules move.
func canonicalNetworkLabelRow(row NetworkLabelRow) (NetworkLabelRow, error) {
	row.Root = canonicalNetworkLabelRoot(row.Root)
	if !isNetworkLabelRoot(row.Root) {
		return row, fmt.Errorf("network labels: root %q is not a domain name", row.Root)
	}
	if row.NetworkId == (Id{}) {
		return row, errors.New("network labels: a row with no network id")
	}
	row.Label = dnsAsciiLower(row.Label)
	if row.Label != "" && !isDnsLowerLdhLabel(row.Label) {
		return row, fmt.Errorf("network labels: label %q is not a label", row.Label)
	}
	row.Alias = dnsAsciiLower(row.Alias)
	if row.Alias != "" && !isDnsLowerLdhLabel(row.Alias) {
		return row, fmt.Errorf("network labels: alias %q is not a label", row.Alias)
	}
	retiringAliases := []string{}
	for _, alias := range row.RetiringAliases {
		alias = dnsAsciiLower(alias)
		if !isDnsLowerLdhLabel(alias) {
			return row, fmt.Errorf("network labels: retiring alias %q is not a label", alias)
		}
		if !slices.Contains(retiringAliases, alias) {
			retiringAliases = append(retiringAliases, alias)
		}
	}
	slices.Sort(retiringAliases)
	row.RetiringAliases = retiringAliases
	row.LegacyName = dnsAsciiLower(strings.TrimSpace(row.LegacyName))
	return row, nil
}

// Whether rows can stand together: one row a network under a root, and no label or alias that one
// row holds also held by another under the same root, which dns_label's key (root, label) never allows.
func checkNetworkLabelRows(rows []NetworkLabelRow) error {
	type rootName struct {
		root string
		name string
	}
	networks := map[rootName]bool{}
	holders := map[rootName]Id{}
	for _, row := range rows {
		networkKey := rootName{root: row.Root, name: row.NetworkId.String()}
		if networks[networkKey] {
			return fmt.Errorf("network labels: network %s twice under %s", row.NetworkId, row.Root)
		}
		networks[networkKey] = true
		names := slices.Clone(row.RetiringAliases)
		if row.Label != "" {
			names = append(names, row.Label)
		}
		if row.Alias != "" {
			names = append(names, row.Alias)
		}
		for _, name := range names {
			key := rootName{root: row.Root, name: name}
			if holder, ok := holders[key]; ok && holder != row.NetworkId {
				return fmt.Errorf("network labels: %s names two networks under %s", name, row.Root)
			}
			holders[key] = row.NetworkId
		}
	}
	return nil
}

// A copy of every row, in root then network id order.
func (self *NetworkLabelTable) Networks() []NetworkLabelRow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	rows := make([]NetworkLabelRow, 0, len(self.rows))
	for _, row := range self.rows {
		row.RetiringAliases = slices.Clone(row.RetiringAliases)
		rows = append(rows, row)
	}
	return rows
}

// Applies change to a copy of the rows, writes the result, and only then installs it, so a failed
// write changes nothing.
func (self *NetworkLabelTable) update(change func(rows []NetworkLabelRow) ([]NetworkLabelRow, error)) error {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	rows, err := change(self.Networks())
	if err != nil {
		return err
	}
	slices.SortFunc(rows, func(first NetworkLabelRow, second NetworkLabelRow) int {
		if order := strings.Compare(first.Root, second.Root); order != 0 {
			return order
		}
		return bytes.Compare(first.NetworkId[:], second.NetworkId[:])
	})
	if err := checkNetworkLabelRows(rows); err != nil {
		return err
	}
	data, err := json.Marshal(&networkLabelTableFile{Format: networkLabelTableFormat, Rows: rows})
	if err != nil {
		return err
	}
	if err := func() error {
		writer, err := self.store.Create(networkLabelTableName)
		if err != nil {
			return err
		}
		defer writer.Close()
		if _, err := writer.Write(data); err != nil {
			return err
		}
		return writer.Commit()
	}(); err != nil {
		return fmt.Errorf("network labels: %w", err)
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.rows = rows
	}()
	return nil
}

// Adds a network this client belongs to, or replaces its row under the same root.
func (self *NetworkLabelTable) SetNetwork(row NetworkLabelRow) error {
	row, err := canonicalNetworkLabelRow(row)
	if err != nil {
		return err
	}
	return self.update(func(rows []NetworkLabelRow) ([]NetworkLabelRow, error) {
		rows = slices.DeleteFunc(rows, func(held NetworkLabelRow) bool {
			return held.Root == row.Root && held.NetworkId == row.NetworkId
		})
		return append(rows, row), nil
	})
}

// Drops a network this client left, under every root. Nothing there is not an error.
func (self *NetworkLabelTable) RemoveNetwork(networkId Id) error {
	return self.update(func(rows []NetworkLabelRow) ([]NetworkLabelRow, error) {
		return slices.DeleteFunc(rows, func(held NetworkLabelRow) bool {
			return held.NetworkId == networkId
		}), nil
	})
}

// Sets networkId's label and alias under root from api's GET /sidecar/label, keeping its retiring
// aliases and recording legacyName, the network_name its token carries. An answer about another
// network is refused and changes nothing, as does a refusal, which leaves a row with no label
// resolving only as the only network.
func (self *NetworkLabelTable) Refresh(ctx context.Context, api *SidecarApi, root string, networkId Id, legacyName string) error {
	answer, err := api.GetSidecarLabel(ctx)
	if err != nil {
		return err
	}
	if answer.NetworkId != networkId {
		return fmt.Errorf("sidecar api %s: %w", sidecarLabelRoute, ErrSidecarApiReply)
	}
	row, err := canonicalNetworkLabelRow(NetworkLabelRow{
		Root:       root,
		NetworkId:  networkId,
		Label:      answer.Label,
		Alias:      answer.Alias,
		LegacyName: legacyName,
	})
	if err != nil {
		return err
	}
	return self.update(func(rows []NetworkLabelRow) ([]NetworkLabelRow, error) {
		for index := range rows {
			if rows[index].Root == row.Root && rows[index].NetworkId == row.NetworkId {
				row.RetiringAliases = slices.DeleteFunc(rows[index].RetiringAliases, func(alias string) bool {
					return alias == row.Alias
				})
				rows[index] = row
				return rows, nil
			}
		}
		return append(rows, row), nil
	})
}

// See NetworkLabelResolver.
func (self *NetworkLabelTable) ResolveNetworkLabel(root string, text string, interactive bool) (Id, NetworkLabelKind, error) {
	root = canonicalNetworkLabelRoot(root)
	text = dnsAsciiLower(strings.TrimSpace(text))
	text = strings.TrimSuffix(strings.TrimSuffix(text, "."), "."+root)
	rows := []NetworkLabelRow{}
	for _, row := range self.Networks() {
		if row.Root == root {
			rows = append(rows, row)
		}
	}
	ambiguous := func(matched []NetworkLabelRow) error {
		err := &NetworkLabelAmbiguousError{}
		for _, row := range matched {
			err.NetworkIds = append(err.NetworkIds, row.NetworkId)
			name := row.Label
			if name == "" {
				name = row.NetworkId.String()
			}
			err.Names = append(err.Names, name)
		}
		return err
	}
	if text == "" {
		switch len(rows) {
		case 0:
			return Id{}, "", ErrNetworkLabelUnknown
		case 1:
			return rows[0].NetworkId, NetworkLabelKindOnly, nil
		}
		return Id{}, "", ambiguous(rows)
	}
	steps := []struct {
		kind  NetworkLabelKind
		holds func(row NetworkLabelRow) bool
	}{
		{kind: NetworkLabelKindLabel, holds: func(row NetworkLabelRow) bool { return row.Label == text }},
		{kind: NetworkLabelKindAlias, holds: func(row NetworkLabelRow) bool { return row.Alias == text }},
		{kind: NetworkLabelKindRetiringAlias, holds: func(row NetworkLabelRow) bool { return slices.Contains(row.RetiringAliases, text) }},
		{kind: NetworkLabelKindLegacyName, holds: func(row NetworkLabelRow) bool { return interactive && row.LegacyName == text }},
	}
	for _, step := range steps {
		matched := []NetworkLabelRow{}
		for _, row := range rows {
			if step.holds(row) {
				matched = append(matched, row)
			}
		}
		switch len(matched) {
		case 0:
			continue
		case 1:
			return matched[0].NetworkId, step.kind, nil
		}
		return Id{}, "", ambiguous(matched)
	}
	return Id{}, "", ErrNetworkLabelUnknown
}
