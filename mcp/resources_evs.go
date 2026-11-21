//go:build !js && !ios && !android && !sdk_mobile_bind

// ur://evs/{repo}/{+path} (§16.5; D-MCP-17, I-9; MCP-M3-13): a file's newest version, or the network and revision
// an oversized evs_read result selected, under the
// same guard, allow, trust and taint rule (tools_evs.go's header): its trust by its push's sealed provenance, own or
// member for an untainted run's version, and an untrusted one, a tainted run's or an import's, tainting the run
// before it returns (QD-042, QD-851).
//
//	subscribe  judged at once: the guard on the repo and path, then §8's allow of read, so a subscription on a refused
//	           repo refuses at subscribe, never at its first event; then §11's token-prefix subscription on the path
//	           is leased (EvsRepo.Subscribe), once per network and URI, and each change it hears goes out as the URI's
//	           resources/updated, which carries the URI alone
//
// A lease is taken at the first subscription and kept for the daemon's life: unsubscribe does not end it (go-sdk's
// unsubscribe reaches no family), so a URI's leases outlive its sessions, and each change still sends only its URI.

package mcp

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

const mcpEvsUriPrefix = "ur://evs/"

// The URI of a path's resource: its names each escaped, joined by /.
func McpEvsUri(repoId sidecar.Id, path string) string {
	names := strings.Split(path, "/")
	for i, name := range names {
		names[i] = url.PathEscape(name)
	}
	return mcpEvsUriPrefix + repoId.String() + "/" + strings.Join(names, "/")
}

// The selected network and version of an EVS result link. A plain path reads the head in the session's network.
func mcpEvsResourcePin(uri string) (string, uint64, error) {
	_, rawQuery, pinned := strings.Cut(uri, "?")
	if !pinned {
		return "", 0, nil
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil || len(values) != 2 || len(values["network"]) != 1 || len(values["version"]) != 1 {
		return "", 0, errMcpResourceNotFound()
	}
	networkId, err := sidecar.ParseId(values.Get("network"))
	if err != nil || networkId == (sidecar.Id{}) {
		return "", 0, errMcpResourceNotFound()
	}
	version, err := strconv.ParseUint(values.Get("version"), 10, 64)
	if err != nil || version == 0 {
		return "", 0, errMcpResourceNotFound()
	}
	return networkId.String(), version, nil
}

// The network a session's subscription acts on, resolved as a call's is, and ready.
func (self *McpServer) sessionNetwork(session *McpSession, name string) (sidecar.Id, McpNetwork, error) {
	hello := session.hello
	networkId, err := self.daemon.ResolveNetwork(&hello, name)
	if err != nil {
		return sidecar.Id{}, nil, newMcpError(McpCodeFailedPrecondition, "no network to act on: name one in the project's .ur", false)
	}
	network, ok := self.daemon.Network(networkId)
	if !ok {
		return sidecar.Id{}, nil, newMcpError(McpCodeFailedPrecondition, "no sidecar runs for that network: run ur status in your own terminal", false)
	}
	switch network.Status().State {
	case sidecar.SidecarStateLocked:
		return sidecar.Id{}, nil, errMcpLocked
	case sidecar.SidecarStateUnenrolled, sidecar.SidecarStateRevoked:
		return sidecar.Id{}, nil, errMcpUnenrolled
	}
	return networkId, network, nil
}

// The leases of subscribed ur://evs URIs, one per network and URI.
type mcpEvsLeases struct {
	stateLock sync.Mutex
	leased    map[mcpEvsLeaseKey]*sidecar.EvsSubscription
}

// One lease's key.
type mcpEvsLeaseKey struct {
	networkId sidecar.Id
	uri       string
}

// Leases path's subscription in repo once for networkId's uri, its changes notifying uri.
func (self *mcpEvsLeases) lease(ctx context.Context, networkId sidecar.Id, uri string, path string, repo McpEvsRepo, resources *McpResources) error {
	key := mcpEvsLeaseKey{networkId: networkId, uri: uri}
	leased := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		_, ok := self.leased[key]
		return ok
	}()
	if leased {
		return nil
	}
	subscription, err := repo.Subscribe(ctx, &sidecar.EvsSubscribeArgs{
		Paths:   []string{path},
		Changes: func(change *sidecar.EvsRepoChange) { resources.Notify(uri) },
	})
	if err != nil {
		return mcpEvsError(err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.leased[key]; ok {
		// another session's lease landed first
		subscription.Close()
		return nil
	}
	self.leased[key] = subscription
	return nil
}

func init() {
	registerMcpResources(func(resources *McpResources, server *McpServer) {
		addEvsResource(resources, server)
	})
}

// The repo and path of a URI's variables.
func mcpEvsUriVariables(variables map[string]string) (sidecar.Id, string, error) {
	repoId, err := mcpEvsRepoId(variables["repo"])
	if err != nil {
		return sidecar.Id{}, "", err
	}
	path, err := mcpEvsPath(variables["path"], false)
	if err != nil {
		return sidecar.Id{}, "", err
	}
	return repoId, path, nil
}

// Adds ur://evs/{repo}/{+path} to resources, its subscriptions resolved through server.
func addEvsResource(resources *McpResources, server *McpServer) {
	leases := &mcpEvsLeases{leased: map[mcpEvsLeaseKey]*sidecar.EvsSubscription{}}
	readAccess := func(network McpToolNetwork, repoId sidecar.Id, call *McpCall) error {
		check, installed := network.Allow(protocol.AclAction_ACL_ACTION_READ, mcpEvsAccess(repoId, protocol.AclAction_ACL_ACTION_READ)[0].Resource, mcpCallNow(call))
		if !installed {
			return errMcpNoPolicy
		}
		if !check.Allowed {
			return errMcpNotAllowed
		}
		return nil
	}
	resources.Add(&McpResourceSpec{
		UriTemplate: "ur://evs/{repo}/{+path}",
		Name:        "evs",
		Description: "A file of a repo at its newest version or the revision named in an evs_read result link. Content a tainted run wrote or an import brought in from outside comes back marked untrusted, and reading it taints the run.",
		Read: func(ctx context.Context, call *McpCall, uri string, variables map[string]string, result *McpResult) (any, error) {
			repoId, path, err := mcpEvsUriVariables(variables)
			if err != nil {
				return nil, err
			}
			if refusal := McpGuard([]McpTarget{mcpEvsTarget(call, repoId, McpRepoRead, path)}); refusal != nil {
				return nil, refusal
			}
			network, ok := mcpToolNetworkOf(call)
			if !ok {
				return nil, errMcpNoToolNetwork
			}
			if err := readAccess(network, repoId, call); err != nil {
				return nil, err
			}
			_, repo, err := mcpEvsRepoOf(call, repoId)
			if err != nil {
				return nil, err
			}
			_, version, err := mcpEvsResourcePin(uri)
			if err != nil {
				return nil, err
			}
			return mcpEvsRead(ctx, call, repoId, repo, path, version, result)
		},
		Subscribe: func(ctx context.Context, session *McpSession, uri string, variables map[string]string) error {
			repoId, path, err := mcpEvsUriVariables(variables)
			if err != nil {
				return err
			}
			name, _, err := mcpEvsResourcePin(uri)
			if err != nil {
				return err
			}
			networkId, network, err := server.sessionNetwork(session, name)
			if err != nil {
				return err
			}
			toolNetwork, ok := network.(McpToolNetwork)
			if !ok {
				return errMcpNoToolNetwork
			}
			call := &McpCall{Session: session, NetworkId: networkId, Network: network}
			if refusal := McpGuard([]McpTarget{mcpEvsTarget(call, repoId, McpRepoRead, path)}); refusal != nil {
				return refusal
			}
			if toolNetwork.Identity() == nil || !toolNetwork.PolicyInstalled() {
				return errMcpNoPolicy
			}
			if err := readAccess(toolNetwork, repoId, call); err != nil {
				return err
			}
			_, repo, err := mcpEvsRepoOf(call, repoId)
			if err != nil {
				return err
			}
			return leases.lease(ctx, networkId, uri, path, repo, resources)
		},
	})
}
