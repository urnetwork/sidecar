//go:build !ios_extension

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
// A changed or released alias retires for 90 days (§12.5, D-DNS-10), and the table keeps it for them: an answer of
// api's that gives the network another alias or none leaves the one the table held retiring, and each retiring alias
// an answer names comes with its tombstone time, which bounds it from then on. An alias no answer gave a time, one the
// table saw leave or was handed with none, is bounded by NetworkLabelTableSettings.RetiringWindow from when the table
// took it, so never before api's own end, whose window started when the alias left. From its tombstone time a retiring
// alias names no network here, as a tombstone names none anywhere (I-14). Holding one past api's end names no other
// network either, since dns_label never gives a name to another, so a late bound only lets the name resolve longer.
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
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
)

// The table's file in its store.
const networkLabelTableName = "network_labels.json"

// The table file's format: a reader refuses a higher one rather than misread it. A row's retiring aliases' times
// came in format 1 as a field a reader that does not know it passes over, keeping the aliases unbounded as it did.
const networkLabelTableFormat = 1

// The label table's bound on retiring aliases (the file's comment).
type NetworkLabelTableSettings struct {
	// How long an alias stays retiring here when no answer of api's gave its tombstone time: one the table saw leave
	// its network, or was handed with none. §12.5's 90 days (D-DNS-10), counted from when the table took it, so never
	// before api's own end, whose 90 days started when the alias left. Non-positive keeps no such alias.
	RetiringWindow time.Duration
}

// A fresh value each call.
func DefaultNetworkLabelTableSettings() *NetworkLabelTableSettings {
	return &NetworkLabelTableSettings{
		RetiringWindow: 90 * 24 * time.Hour,
	}
}

// A retiring alias as api's label answers give it (GET /sidecar/label, GET /dns/zone): an alias its network changed
// or released, which names the network until TombstoneTime and no network ever after (§12.5, D-DNS-10).
type NetworkLabelRetiringAlias struct {
	// A label with no root.
	Alias string `json:"alias"`
	// When its 90 days of retiring end and it tombstones.
	TombstoneTime time.Time `json:"tombstone_time"`
}

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
	// When each of RetiringAliases tombstones, by alias. A table bounds an alias it takes with none (the file's
	// comment), and from an alias's time on leaves it out of every read.
	RetiringAliasTombstoneTimes map[string]time.Time `json:"retiring_alias_tombstone_times,omitempty"`
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
// before it is seen, so a reader never resolves through a row a crash would lose. Its retiring
// aliases are bounded by its clock (the file's comment). A table built in memory with no store
// takes the default settings and real time, and no change. Safe for concurrent use.
type NetworkLabelTable struct {
	store    SidecarStore
	settings *NetworkLabelTableSettings
	clock    Clock

	// one change at a time: each is read, written to the store and then installed, in that order
	writeLock sync.Mutex

	stateLock sync.Mutex
	rows      []NetworkLabelRow
	// the rows differ from the store's file, since the open bounded or dropped a retiring alias there, so the next
	// change writes even one that changes nothing else
	unwritten bool
}

// The table in store, empty when the store holds none, with the default settings and real time.
func OpenNetworkLabelTable(store SidecarStore) (*NetworkLabelTable, error) {
	return OpenNetworkLabelTableWithSettings(store, nil, nil)
}

// The table in store, empty when the store holds none, bounding its retiring aliases by settings on clock: nil
// settings take the defaults and a nil clock real time. A retiring alias the file holds with no time is bounded from
// now, and one past its time is dropped, each written at the next change.
func OpenNetworkLabelTableWithSettings(store SidecarStore, settings *NetworkLabelTableSettings, clock Clock) (*NetworkLabelTable, error) {
	if store == nil {
		return nil, errors.New("network labels: no store")
	}
	if settings == nil {
		settings = DefaultNetworkLabelTableSettings()
	}
	table := &NetworkLabelTable{store: store, settings: settings, clock: clock}
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
	now := table.now()
	for index := range file.Rows {
		row, err := canonicalNetworkLabelRow(file.Rows[index])
		if err != nil {
			return nil, err
		}
		bounded := table.boundRetiringAliases(row, nil, now)
		if !equalNetworkLabelRow(bounded, row) {
			table.unwritten = true
		}
		file.Rows[index] = bounded
	}
	if err := checkNetworkLabelRows(file.Rows); err != nil {
		return nil, err
	}
	table.rows = file.Rows
	return table, nil
}

// The table's clock's now.
func (self *NetworkLabelTable) now() time.Time {
	return clockOrReal(self.clock).Now()
}

// How long an alias with no time from api stays retiring (NetworkLabelTableSettings).
func (self *NetworkLabelTable) retiringWindow() time.Duration {
	if self.settings == nil {
		return DefaultNetworkLabelTableSettings().RetiringWindow
	}
	return self.settings.RetiringWindow
}

// row with its retiring aliases as the table keeps them at now: one its label or alias names is live and left out; one
// with no time takes held's time for it, held being the row the table held for the network, else now plus the
// retiring window; and one whose time has come is left out.
func (self *NetworkLabelTable) boundRetiringAliases(row NetworkLabelRow, held *NetworkLabelRow, now time.Time) NetworkLabelRow {
	retiringAliases := []string{}
	tombstoneTimes := map[string]time.Time{}
	for _, alias := range row.RetiringAliases {
		if alias == row.Label || alias == row.Alias {
			continue
		}
		tombstoneTime, ok := row.RetiringAliasTombstoneTimes[alias]
		if !ok && held != nil {
			tombstoneTime, ok = held.RetiringAliasTombstoneTimes[alias]
		}
		if !ok {
			window := self.retiringWindow()
			if window <= 0 {
				continue
			}
			tombstoneTime = now.Add(window).UTC()
		}
		if !now.Before(tombstoneTime) {
			continue
		}
		retiringAliases = append(retiringAliases, alias)
		tombstoneTimes[alias] = tombstoneTime
	}
	row.RetiringAliases = retiringAliases
	row.RetiringAliasTombstoneTimes = nil
	if 0 < len(tombstoneTimes) {
		row.RetiringAliasTombstoneTimes = tombstoneTimes
	}
	return row
}

// A copy of row as a read at now sees it: each retiring alias whose time has come left out, and one with no time kept,
// as a row a table built in memory holds.
func networkLabelRowAt(row NetworkLabelRow, now time.Time) NetworkLabelRow {
	tombstoneTimes := row.RetiringAliasTombstoneTimes
	row.RetiringAliases = slices.DeleteFunc(slices.Clone(row.RetiringAliases), func(alias string) bool {
		tombstoneTime, ok := tombstoneTimes[alias]
		return ok && !now.Before(tombstoneTime)
	})
	row.RetiringAliasTombstoneTimes = nil
	for _, alias := range row.RetiringAliases {
		if tombstoneTime, ok := tombstoneTimes[alias]; ok {
			if row.RetiringAliasTombstoneTimes == nil {
				row.RetiringAliasTombstoneTimes = map[string]time.Time{}
			}
			row.RetiringAliasTombstoneTimes[alias] = tombstoneTime
		}
	}
	return row
}

// Whether two rows hold the same names and times.
func equalNetworkLabelRow(row NetworkLabelRow, other NetworkLabelRow) bool {
	return row.Root == other.Root && row.NetworkId == other.NetworkId && row.Label == other.Label &&
		row.Alias == other.Alias && row.LegacyName == other.LegacyName && slices.Equal(row.RetiringAliases, other.RetiringAliases) &&
		maps.EqualFunc(row.RetiringAliasTombstoneTimes, other.RetiringAliasTombstoneTimes, time.Time.Equal)
}

// A root as rows keep it: ASCII lowercase, with no trailing dot.
func canonicalNetworkLabelRoot(root string) string {
	return strings.TrimSuffix(dnsAsciiLower(strings.TrimSpace(root)), ".")
}

// row with its names folded to lowercase, or why it cannot be a row. Names are held to the LDH shape
// alone: an alias claimed under older rules stays this network's after the rules move. A retiring
// alias's time is kept in UTC, the earlier where two spellings of one alias give two, and a time for
// no retiring alias, or a zero one, is dropped.
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
	tombstoneTimes := map[string]time.Time{}
	for alias, tombstoneTime := range row.RetiringAliasTombstoneTimes {
		alias = dnsAsciiLower(alias)
		if tombstoneTime.IsZero() || !slices.Contains(retiringAliases, alias) {
			continue
		}
		if held, ok := tombstoneTimes[alias]; !ok || tombstoneTime.Before(held) {
			tombstoneTimes[alias] = tombstoneTime.UTC()
		}
	}
	row.RetiringAliases = retiringAliases
	row.RetiringAliasTombstoneTimes = nil
	if 0 < len(tombstoneTimes) {
		row.RetiringAliasTombstoneTimes = tombstoneTimes
	}
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

// A copy of every row, in root then network id order, each retiring alias whose tombstone time has come
// left out.
func (self *NetworkLabelTable) Networks() []NetworkLabelRow {
	return self.networksAt(self.now())
}

// Networks as a read at now sees them.
func (self *NetworkLabelTable) networksAt(now time.Time) []NetworkLabelRow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	rows := make([]NetworkLabelRow, 0, len(self.rows))
	for _, row := range self.rows {
		rows = append(rows, networkLabelRowAt(row, now))
	}
	return rows
}

// Applies change to a copy of the rows as a read now sees them, bounds each row's retiring aliases
// (boundRetiringAliases), writes the result, and only then installs it, so a failed write changes
// nothing. A change that leaves every row as it was writes nothing: a DnsClient feeds the table each
// zone it fetches, and an unchanged zone costs no sealed write.
func (self *NetworkLabelTable) update(change func(rows []NetworkLabelRow) ([]NetworkLabelRow, error)) error {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	now := self.now()
	held := self.networksAt(now)
	rows, err := change(self.networksAt(now))
	if err != nil {
		return err
	}
	for index := range rows {
		heldIndex := slices.IndexFunc(held, func(heldRow NetworkLabelRow) bool {
			return heldRow.Root == rows[index].Root && heldRow.NetworkId == rows[index].NetworkId
		})
		var heldRow *NetworkLabelRow
		if 0 <= heldIndex {
			heldRow = &held[heldIndex]
		}
		rows[index] = self.boundRetiringAliases(rows[index], heldRow, now)
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
	unwritten := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.unwritten
	}()
	if !unwritten && slices.EqualFunc(rows, held, equalNetworkLabelRow) {
		return nil
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
		self.unwritten = false
	}()
	return nil
}

// Adds a network this client belongs to, or replaces its row under the same root. A retiring alias the
// row gives no time keeps the time the table held for it, else is bounded from now.
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
// aliases, the one it held live when the answer gives another or none among them, taking the retiring
// aliases the answer names with their tombstone times (networkLabelAnsweredRow), and recording
// legacyName, the network_name its token carries. An answer about another network, or one whose
// label or alias, or a retiring alias, is not a label, is not the route's (ErrSidecarApiReply) and
// changes nothing, as does a refusal, which leaves a row with no label resolving only as the only
// network. A root that is not one asks api nothing, since the read allocates a label on first need.
// dns_label_refresh.go calls it at each client generation.
func (self *NetworkLabelTable) Refresh(ctx context.Context, api *SidecarApi, root string, networkId Id, legacyName string) error {
	if !isNetworkLabelRoot(canonicalNetworkLabelRoot(root)) {
		return fmt.Errorf("network labels: root %q is not a domain name", root)
	}
	answer, err := api.GetSidecarLabel(ctx)
	if err != nil {
		return err
	}
	if answer.NetworkId != networkId {
		return fmt.Errorf("sidecar api %s: %w", sidecarLabelRoute, ErrSidecarApiReply)
	}
	row, err := networkLabelAnswerRow(NetworkLabelRow{
		Root:       root,
		NetworkId:  networkId,
		Label:      answer.Label,
		Alias:      answer.Alias,
		LegacyName: legacyName,
	}, answer.RetiringAliases)
	if err != nil {
		return fmt.Errorf("sidecar api %s: %w: %w", sidecarLabelRoute, ErrSidecarApiReply, err)
	}
	return self.update(func(rows []NetworkLabelRow) ([]NetworkLabelRow, error) {
		for index := range rows {
			if rows[index].Root == row.Root && rows[index].NetworkId == row.NetworkId {
				rows[index] = networkLabelAnsweredRow(row, rows[index])
				return rows, nil
			}
		}
		return append(rows, row), nil
	})
}

// The row an answer of api's gives, canonical: answered's names, with the retiring aliases the answer names and their
// tombstone times, a zero time standing for none given. Why it cannot be a row otherwise.
func networkLabelAnswerRow(answered NetworkLabelRow, retiringAliases []NetworkLabelRetiringAlias) (NetworkLabelRow, error) {
	answered.RetiringAliases = nil
	answered.RetiringAliasTombstoneTimes = map[string]time.Time{}
	for _, retiring := range retiringAliases {
		answered.RetiringAliases = append(answered.RetiringAliases, retiring.Alias)
		answered.RetiringAliasTombstoneTimes[retiring.Alias] = retiring.TombstoneTime
	}
	return canonicalNetworkLabelRow(answered)
}

// answered, the canonical row an answer of api's gives a network, beside held, the row the table held for it: held's
// retiring aliases and the answer's, an answer's tombstone time standing over held's for an alias both name, and
// held's alias when the answer gives another or none, since a changed or released alias retires (§12.5). The update
// bounds an alias that has no time, which held's live alias has not unless the answer named it, and leaves out the
// one that is live again (boundRetiringAliases).
func networkLabelAnsweredRow(answered NetworkLabelRow, held NetworkLabelRow) NetworkLabelRow {
	retiringAliases := slices.Clone(held.RetiringAliases)
	if held.Alias != "" && held.Alias != answered.Alias {
		retiringAliases = append(retiringAliases, held.Alias)
	}
	tombstoneTimes := maps.Clone(held.RetiringAliasTombstoneTimes)
	if tombstoneTimes == nil {
		tombstoneTimes = map[string]time.Time{}
	}
	for _, alias := range answered.RetiringAliases {
		retiringAliases = append(retiringAliases, alias)
		if tombstoneTime, ok := answered.RetiringAliasTombstoneTimes[alias]; ok {
			tombstoneTimes[alias] = tombstoneTime
		}
	}
	slices.Sort(retiringAliases)
	answered.RetiringAliases = slices.Compact(retiringAliases)
	answered.RetiringAliasTombstoneTimes = tombstoneTimes
	return answered
}

// See NetworkLabelResolver.
func (self *NetworkLabelTable) ResolveNetworkLabel(root string, text string, interactive bool) (Id, NetworkLabelKind, error) {
	return resolveNetworkLabelRows(self.Networks(), root, text, interactive)
}

// §12.14's rule over rows, one a network this client belongs to under a root, as NetworkLabelResolver states it: the
// rows under root alone, text matched against each one's label, then its alias, then a retiring alias, and its legacy
// name only when interactive, a step two networks match answering ambiguous; the empty text is the only network. A
// text two networks hold as a label, an alias or a retiring alias, in whichever kinds, is ambiguous too, since
// dns_label's key never lets one name name two networks: one table's rows never hold that (checkNetworkLabelRows), and
// rows a daemon gathers from several networks' tables (daemon_labels.go) are refused for it rather than resolved by
// the order. A legacy name is the one kind a later network may take, so only the order decides it.
func resolveNetworkLabelRows(held []NetworkLabelRow, root string, text string, interactive bool) (Id, NetworkLabelKind, error) {
	root = canonicalNetworkLabelRoot(root)
	text = dnsAsciiLower(strings.TrimSpace(text))
	text = strings.TrimSuffix(strings.TrimSuffix(text, "."), "."+root)
	rows := []NetworkLabelRow{}
	for _, row := range held {
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
	holders := []NetworkLabelRow{}
	for _, row := range rows {
		holds := row.Label == text || row.Alias == text || slices.Contains(row.RetiringAliases, text)
		if holds && !slices.ContainsFunc(holders, func(holder NetworkLabelRow) bool { return holder.NetworkId == row.NetworkId }) {
			holders = append(holders, row)
		}
	}
	if 1 < len(holders) {
		return Id{}, "", ambiguous(holders)
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
