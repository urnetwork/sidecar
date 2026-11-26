//go:build !js && !ios && !android && !sdk_mobile_bind

// The daemon's labels (§5.8, §11.11's names row, §12.5's label row, §12.14, D-DNS-2): a Daemon whose settings give no
// resolver resolves the <net> of `.ur`, a call's network argument, a git session and a socket address through the
// label tables of the networks it hosts, each the network's own in its dns/ directory (Sidecar.NetworkLabels), which
// its DnsClient feeds from GET /dns/zone and its label refresh from GET /sidecar/label (dns_label_refresh.go), under
// DaemonSettings.LabelRoot. So a daemon hosting several networks picks each by its label, alias or retiring alias.
//
// Each table speaks for its own network alone: a row one network's table holds about another network is never read,
// so no network's state names another, and a name two networks' tables each claim for themselves, which dns_label's
// key never allows, is refused as ambiguous rather than resolved to either (resolveNetworkLabelRows). A table that
// does not open, as while the keychain is locked, gives its network no name, so a name it holds resolves to no
// network rather than to another. A legacy network_name, the one kind another network may hold since, resolves for a
// person's typed input only while every hosted network's table was read, since the network that holds it now may be
// the one unread. With no root nothing resolves by name.
//
// Safe for concurrent use: it reads the daemon's registry and each table under their own locks, holding neither while
// it reads the other.

package sidecar

// §12.14's NetworkLabelResolver over a daemon's hosted networks' own tables (the file's comment).
type daemonHostedLabels struct {
	daemon *Daemon
}

// The resolver the daemon resolves names through: the one its settings give, else its hosted networks' tables.
func (self *Daemon) labels() NetworkLabelResolver {
	if self.settings.Labels != nil {
		return self.settings.Labels
	}
	return &daemonHostedLabels{daemon: self}
}

// The hosted networks in network order, each one's rows about itself from its own table, and whether every hosted
// network's table was read.
func (self *daemonHostedLabels) hostedRows() ([]DaemonNetwork, map[Id][]NetworkLabelRow, bool) {
	hosted := self.daemon.Sidecars()
	networkIdRows := map[Id][]NetworkLabelRow{}
	read := true
	for _, network := range hosted {
		table, err := network.Sidecar.NetworkLabels()
		if err != nil {
			read = false
			continue
		}
		for _, row := range table.Networks() {
			if row.NetworkId == network.NetworkId {
				networkIdRows[network.NetworkId] = append(networkIdRows[network.NetworkId], row)
			}
		}
	}
	return hosted, networkIdRows, read
}

// See NetworkLabelResolver. A hosted network with no row under root takes part as a network with no name, so the empty
// text answers the only hosted network, and an ambiguous one names every hosted network, by its id where it has no
// label.
func (self *daemonHostedLabels) ResolveNetworkLabel(root string, text string, interactive bool) (Id, NetworkLabelKind, error) {
	root = canonicalNetworkLabelRoot(root)
	if !isNetworkLabelRoot(root) {
		return Id{}, "", ErrNetworkLabelUnknown
	}
	hosted, networkIdRows, read := self.hostedRows()
	rows := make([]NetworkLabelRow, 0, len(hosted))
	for _, network := range hosted {
		row := NetworkLabelRow{Root: root, NetworkId: network.NetworkId}
		for _, held := range networkIdRows[network.NetworkId] {
			if held.Root == root {
				row = held
			}
		}
		rows = append(rows, row)
	}
	// a legacy name the network that took it since may hold in a table not read: no legacy name then
	return resolveNetworkLabelRows(rows, root, text, interactive && read)
}

// Every hosted network's own rows, under every root, in network order: what the daemon names its networks by
// (hostedNetworkNames).
func (self *daemonHostedLabels) Networks() []NetworkLabelRow {
	hosted, networkIdRows, _ := self.hostedRows()
	rows := []NetworkLabelRow{}
	for _, network := range hosted {
		rows = append(rows, networkIdRows[network.NetworkId]...)
	}
	return rows
}
