// Shared blocks (§17.4's uniqueness row; BRIDGE-M6-06): a block is unique within its network alone (owner decision 23),
// and ur daemon hosts several networks (CORE-M6-01), so two of them can hold the same /16. The device routes such a
// block only to the network it joined first, sidecar.json's order of enrollment (SidecarInstance.Networks):
//
//	owner     of each block, the first-joined network whose bridge runs here and holds it, as its block or the one it
//	          drains
//	withheld  every later network's copy of it: ur tun, carrying such a network, puts none of its addresses, routes or
//	          names inside the block on the device and drops anything bound there (tun_device.go), so its hosts in the
//	          block are not reached from this device; its routes outside the block, its exits and the flows it hosts
//	          stay its own
//	warning   ur status names each withheld block with the network that routes it here, and the network that loses
//	          one raises bridge_alarm shared_block once, again only after a cycle has cleared it and a later change
//	          brought it back
//
// A network whose bridge does not run on this device routes nothing here, so it holds no block: the judgment covers the
// bridges the daemon runs, and runs again whenever one of them changes, starts or ends, and every SharedBlockInterval
// regardless, for a drain that ends with no change of state. When an admin cycles either block, the next judgment finds
// them apart and the tun routes the block again. Logs name network ids alone (I-13); ur status shows the block, on the
// person's own terminal.

package main

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"

	"github.com/urnetwork/sidecar"
)

// The control method ur status reads the shared blocks by.
const urMethodStatusSharedBlocks = "status.shared_blocks"

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urSharedBlockMethods)
	urStatusSections = append(urStatusSections, printUrStatusSharedBlocks)
}

// A block a network does not route on this device, since a network the device joined earlier holds it too.
type urSharedBlock struct {
	// The network's block, its current one or the one it drains.
	Block netip.Prefix
	// The network that does not route it here.
	NetworkId sidecar.Id
	// The first-joined network holding it, which routes it here.
	OwnerNetworkId sidecar.Id
}

// Each block a network loses to one this device joined earlier: order ranks the networks, oldest join first, and blocks
// holds each running network's current and draining blocks. A network order does not name ranks after every one it
// does, by id, so the judgment never depends on a map's order. A block's owner is the first-ranked network holding a
// block that overlaps it.
func urSharedBlocksOf(order []sidecar.Id, blocks map[sidecar.Id][]netip.Prefix) []urSharedBlock {
	rank := map[sidecar.Id]int{}
	for i, networkId := range order {
		if _, ranked := rank[networkId]; !ranked {
			rank[networkId] = i
		}
	}
	networkIds := make([]sidecar.Id, 0, len(blocks))
	for networkId := range blocks {
		networkIds = append(networkIds, networkId)
	}
	slices.SortFunc(networkIds, func(a sidecar.Id, b sidecar.Id) int {
		rankA, rankedA := rank[a]
		rankB, rankedB := rank[b]
		switch {
		case rankedA && rankedB && rankA != rankB:
			return cmp.Compare(rankA, rankB)
		case rankedA && !rankedB:
			return -1
		case !rankedA && rankedB:
			return 1
		}
		return a.Cmp(b)
	})
	shared := []urSharedBlock{}
	for i, networkId := range networkIds {
		lost := []netip.Prefix{}
		for _, block := range blocks[networkId] {
			if !block.IsValid() || slices.Contains(lost, block.Masked()) {
				continue
			}
			block = block.Masked()
			for _, earlier := range networkIds[:i] {
				if slices.ContainsFunc(blocks[earlier], func(held netip.Prefix) bool {
					return held.IsValid() && held.Masked().Overlaps(block)
				}) {
					shared = append(shared, urSharedBlock{Block: block, NetworkId: networkId, OwnerNetworkId: earlier})
					lost = append(lost, block)
					break
				}
			}
		}
	}
	return shared
}

// The shares that withhold networkId's blocks.
func urSharedBlocksFor(shared []urSharedBlock, networkId sidecar.Id) []urSharedBlock {
	withheld := []urSharedBlock{}
	for _, share := range shared {
		if share.NetworkId == networkId {
			withheld = append(withheld, share)
		}
	}
	return withheld
}

// Judges the shared blocks again on each wake, every SharedBlockInterval of the daemon's clock regardless, until the
// daemon ends. No judgment starts once the daemon has ended, a wake or a timer taken as it ended included, so no
// shared_block alarm is raised and no status kept past the end.
func (self *urBridgeDaemon) runSharedBlocks() {
	defer close(self.sharedDone)
	// select takes any of its ready cases at random: a wake or a timer taken as the daemon ended reads as the end
	for self.ctx.Err() == nil {
		select {
		case <-self.ctx.Done():
		case <-self.sharedWake:
		case <-self.clock.After(self.settings.SharedBlockInterval):
		}
		if self.ctx.Err() != nil {
			return
		}
		self.judgeSharedBlocks()
	}
}

// Wakes the judgment, coalescing with a wake already pending. Never blocks: each bridge's change callback.
func (self *urBridgeDaemon) wantSharedBlocks() {
	select {
	case self.sharedWake <- struct{}{}:
	default:
	}
}

// Judges the shared blocks of the bridges that run now: each share that is new raises bridge_alarm shared_block on the
// network that loses the block, and the tun syncs where what it withholds changed. Judgments run one at a time.
func (self *urBridgeDaemon) judgeSharedBlocks() {
	self.sharedJudgeLock.Lock()
	defer self.sharedJudgeLock.Unlock()
	var networks []*urBridgeNetwork
	var tun *urTun
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		networks = make([]*urBridgeNetwork, 0, len(self.networks))
		for _, network := range self.networks {
			networks = append(networks, network)
		}
		tun = self.tun
	}()
	blocks := map[sidecar.Id][]netip.Prefix{}
	for _, network := range networks {
		status := network.bridge.Status()
		held := []netip.Prefix{}
		for _, block := range []netip.Prefix{status.Block, status.PreviousBlock} {
			if block.IsValid() && block.Addr().Is4() {
				held = append(held, block)
			}
		}
		blocks[network.networkId] = held
	}
	var order []sidecar.Id
	if self.joinOrder != nil {
		order = self.joinOrder()
	}
	shared := urSharedBlocksOf(order, blocks)
	// the app's VPN component, judged as often (bridge_discovery_app.go)
	self.judgeAppViewing(networks, tun)
	var previous []urSharedBlock
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		previous = self.sharedBlocks
		self.sharedBlocks = shared
	}()
	for _, share := range shared {
		if slices.Contains(previous, share) {
			continue
		}
		self.log.Warningf("[bridge]%s holds a block network %s holds too, which joined this device first and alone "+
			"routes it here", share.NetworkId, share.OwnerNetworkId)
		for _, network := range networks {
			if network.networkId == share.NetworkId && network.alarm != nil {
				network.alarm(sidecar.SidecarBridgeAlarmSharedBlock)
			}
		}
	}
	if tun != nil && !slices.Equal(urSharedBlocksFor(previous, tun.networkId), urSharedBlocksFor(shared, tun.networkId)) {
		tun.wantSync()
	}
}

// The blocks networkId does not route on this device, as the last judgment found them.
func (self *urBridgeDaemon) sharedBlocksFor(networkId sidecar.Id) []urSharedBlock {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return urSharedBlocksFor(self.sharedBlocks, networkId)
}

// status.shared_blocks' reply: each block a network does not route on this device, and the network that does.
type urStatusSharedBlocksReply struct {
	Shared []*urStatusSharedBlock `json:"shared,omitempty"`
}

// One withheld block, as ur status shows it. Nothing secret.
type urStatusSharedBlock struct {
	Block          string     `json:"block"`
	NetworkId      sidecar.Id `json:"network_id"`
	OwnerNetworkId sidecar.Id `json:"owner_network_id"`
}

// The shared blocks' method over a target that hosts its networks' bridges.
func urSharedBlockMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	network, ok := target.(*urDaemonNetwork)
	if !ok || network.bridges == nil {
		return nil
	}
	bridges := network.bridges
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodStatusSharedBlocks,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				return urStatusSharedBlocksOf(bridges), nil
			},
		},
	}
}

// The shared blocks now: judged again first, so ur status shows what the bridges hold at its call.
func urStatusSharedBlocksOf(bridges *urBridgeDaemon) *urStatusSharedBlocksReply {
	bridges.judgeSharedBlocks()
	reply := &urStatusSharedBlocksReply{}
	func() {
		bridges.stateLock.Lock()
		defer bridges.stateLock.Unlock()
		for _, share := range bridges.sharedBlocks {
			reply.Shared = append(reply.Shared, &urStatusSharedBlock{
				Block:          share.Block.String(),
				NetworkId:      share.NetworkId,
				OwnerNetworkId: share.OwnerNetworkId,
			})
		}
	}()
	return reply
}

// The warnings, after status's own lines. A daemon that does not answer the method, one with no bridges, prints nothing:
// status already said what it could of the daemon.
func printUrStatusSharedBlocks(ctx context.Context, cli *urCli) {
	reply := &urStatusSharedBlocksReply{}
	if err := cli.callDaemon(ctx, urMethodStatusSharedBlocks, struct{}{}, false, reply); err != nil {
		return
	}
	printUrSharedBlocksReply(cli, reply)
}

// Each withheld block as a warning line.
func printUrSharedBlocksReply(cli *urCli, reply *urStatusSharedBlocksReply) {
	for _, share := range reply.Shared {
		fmt.Fprintf(cli.stdout, "warning:    network %s holds the block %s, as network %s does, which joined this device "+
			"first and alone routes it here: network %s's hosts in it are not reached from this device until an admin "+
			"of either cycles one (ur bridge block cycle)\n", share.NetworkId, share.Block, share.OwnerNetworkId,
			share.NetworkId)
	}
}
