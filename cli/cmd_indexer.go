// ur indexer (TEAM-M2-18, TEAM-M10-01; §7.9's IndexerSet, owner decisions 150, 175, 178; D-TEAM-27):
//
//	ur indexer add [--scope=<scope>] [--services=<services>]   designate this device, network or member scope, for
//	                                                            mail, mirror and search (the default all three)
//	ur indexer rm [--scope=<scope>]                             retire this device's designation at a scope
//	ur indexer ls                                               the network's indexers
//
// add and rm sign an IndexerSet only for a command confirmed on /dev/tty, never through MCP (D-CORE-13); add refuses
// search on an app host, which an indexer never is (owner decision 197), and installs the daemon's unit if absent
// (CORE-M2-09's installDaemonUnitIfAbsent), so the indexer restarts at login. A network designation needs an Owner's or
// Admin's device; a member one this device's member's consented device. The services ride sealed to the config's
// current generation, so the server never sees them.

package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The control methods ur indexer calls.
const (
	urMethodIndexerList      = "indexer.list"
	urMethodIndexerDesignate = "indexer.designate"
	urMethodIndexerRetireOne = "indexer.retire_scope"
)

func init() {
	registerUrCommand(&urCommand{
		name: "indexer",
		usage: strings.Join([]string{
			"  ur indexer add [--scope=<scope>] [--services=<services>]",
			"  ur indexer rm [--scope=<scope>]",
			"  ur indexer ls",
		}, "\n"),
		summary: "designate this device as the network's or its member's indexer, retire it, or list indexers",
		run:     runUrIndexer,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urIndexerDesignationMethods)
}

// What the designation methods act on.
type urIndexerDesignationTarget interface {
	listIndexers() ([]sidecar.ConfigIndexer, error)
	designateIndexer(ctx context.Context, scope protocol.IndexerScope, services []protocol.IndexerService) error
	retireIndexerScope(ctx context.Context, scope protocol.IndexerScope) error
}

func (self *urDaemonNetwork) listIndexers() ([]sidecar.ConfigIndexer, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	return running.Indexers()
}

// A confirmed control call. ur's daemon is never an app host.
func (self *urDaemonNetwork) designateIndexer(ctx context.Context, scope protocol.IndexerScope, services []protocol.IndexerService) error {
	running, err := self.onlySidecar()
	if err != nil {
		return err
	}
	return running.DesignateIndexer(ctx, scope, services, false, nil, sidecar.SidecarActConfirmed, nil)
}

// A confirmed control call.
func (self *urDaemonNetwork) retireIndexerScope(ctx context.Context, scope protocol.IndexerScope) error {
	running, err := self.onlySidecar()
	if err != nil {
		return err
	}
	return running.RetireIndexerScope(ctx, scope, sidecar.SidecarActConfirmed, nil)
}

// indexer.designate's and indexer.retire_scope's params.
type urIndexerParams struct {
	Scope    int32   `json:"scope"`
	Services []int32 `json:"services,omitempty"`
}

// One indexer as indexer.list answers it.
type urIndexerItem struct {
	SidecarId sidecar.Id `json:"sidecar_id"`
	Scope     string     `json:"scope"`
	At        uint64     `json:"at"`
}

type urIndexersReply struct {
	Items []*urIndexerItem `json:"items"`
}

// The designation methods over target, when it hosts a Sidecar.
func urIndexerDesignationMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	indexers, ok := target.(urIndexerDesignationTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodIndexerList,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				list, err := indexers.listIndexers()
				if err != nil {
					return nil, err
				}
				reply := &urIndexersReply{Items: []*urIndexerItem{}}
				for _, indexer := range list {
					reply.Items = append(reply.Items, &urIndexerItem{SidecarId: indexer.SidecarId, Scope: urIndexerScopeName(indexer.Scope), At: indexer.At})
				}
				return reply, nil
			},
		},
		{
			Name:    urMethodIndexerDesignate,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urIndexerParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				services := []protocol.IndexerService{}
				for _, service := range params.Services {
					services = append(services, protocol.IndexerService(service))
				}
				return nil, indexers.designateIndexer(ctx, protocol.IndexerScope(params.Scope), services)
			},
		},
		{
			Name:    urMethodIndexerRetireOne,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urIndexerParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				return nil, indexers.retireIndexerScope(ctx, protocol.IndexerScope(params.Scope))
			},
		},
	}
}

// A scope's word.
func urIndexerScopeName(scope protocol.IndexerScope) string {
	switch scope {
	case protocol.IndexerScope_INDEXER_SCOPE_NETWORK:
		return "network"
	case protocol.IndexerScope_INDEXER_SCOPE_MEMBER:
		return "member"
	}
	return "unknown"
}

// --scope's value, network unless member.
func urIndexerScope(options docopt.Opts) (protocol.IndexerScope, error) {
	scope, _ := options.String("--scope")
	switch scope {
	case "", "network":
		return protocol.IndexerScope_INDEXER_SCOPE_NETWORK, nil
	case "member":
		return protocol.IndexerScope_INDEXER_SCOPE_MEMBER, nil
	}
	return 0, fmt.Errorf("--scope is network or member: %q", scope)
}

// --services' value: a comma list of mail, mirror and search, all three when absent.
func urIndexerServices(options docopt.Opts) ([]protocol.IndexerService, error) {
	text, _ := options.String("--services")
	if text == "" {
		text = "mail,mirror,search"
	}
	services := []protocol.IndexerService{}
	for _, word := range strings.Split(text, ",") {
		switch strings.TrimSpace(word) {
		case "mail":
			services = append(services, protocol.IndexerService_INDEXER_SERVICE_MAIL)
		case "mirror":
			services = append(services, protocol.IndexerService_INDEXER_SERVICE_MIRROR)
		case "search":
			services = append(services, protocol.IndexerService_INDEXER_SERVICE_SEARCH)
		default:
			return nil, fmt.Errorf("--services takes mail, mirror and search: %q", word)
		}
	}
	return services, nil
}

// ur indexer: the list, or a designation or retirement confirmed on the terminal.
func runUrIndexer(ctx context.Context, cli *urCli, options docopt.Opts) error {
	if urOptionBool(options, "ls") {
		reply := &urIndexersReply{}
		if err := cli.callDaemon(ctx, urMethodIndexerList, nil, false, reply); err != nil {
			return err
		}
		if len(reply.Items) == 0 {
			cli.printf("no indexer\n")
		}
		for _, item := range reply.Items {
			cli.printf("%s  %s  from %d\n", item.SidecarId, item.Scope, item.At)
		}
		return nil
	}
	scope, err := urIndexerScope(options)
	if err != nil {
		return err
	}
	if urOptionBool(options, "rm") {
		confirmed, err := confirmOnTty(cli, fmt.Sprintf("retire this device's %s indexer designation?", urIndexerScopeName(scope)))
		if err != nil {
			return err
		}
		if !confirmed {
			cli.printf("nothing changed\n")
			return nil
		}
		return cli.callDaemon(ctx, urMethodIndexerRetireOne, &urIndexerParams{Scope: int32(scope)}, true, nil)
	}
	services, err := urIndexerServices(options)
	if err != nil {
		return err
	}
	names := []string{}
	params := &urIndexerParams{Scope: int32(scope)}
	for _, service := range services {
		params.Services = append(params.Services, int32(service))
		names = append(names, strings.ToLower(strings.TrimPrefix(service.String(), "INDEXER_SERVICE_")))
	}
	question := fmt.Sprintf("designate this device as the %s indexer for %s?", urIndexerScopeName(scope), strings.Join(names, ", "))
	confirmed, err := confirmOnTty(cli, question)
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	if err := cli.callDaemon(ctx, urMethodIndexerDesignate, params, true, nil); err != nil {
		return err
	}
	// an indexer restarts at login: its unit, installed if absent (CORE-M2-09)
	if _, err := installDaemonUnitIfAbsent(ctx, cli); err != nil {
		return fmt.Errorf("designated, and the daemon's unit did not install: %w", err)
	}
	cli.printf("this device is the %s indexer\n", urIndexerScopeName(scope))
	return nil
}
