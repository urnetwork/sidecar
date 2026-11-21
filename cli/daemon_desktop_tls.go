// The CLI's TLS publisher and custom-domain ordering desktop (§13.8–§13.10).
package main

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/urnetwork/sidecar"
)

// Starts TLS after enrollment and after this network's config follower has verified its state.
// Published listeners and the ordering desktop outlive transport reconnects and end when the Sidecar closes.
func startUrDesktopTls(ctx context.Context, running *sidecar.Sidecar, follower *sidecar.SidecarConfigFollower, stateDirectory string, network *urDaemonNetwork, log sidecar.Logger) {
	ctx, cancel := context.WithCancel(ctx)
	service := &urDesktopTls{running: running, follower: follower, stateDirectory: stateDirectory, network: network, cancel: cancel, done: make(chan struct{})}
	if _, err := running.AddComponent(service); err != nil {
		cancel()
		log.Warningf("[ur]starting the desktop TLS service: %s", err)
		return
	}
	go service.run(ctx, log)
}

type urDesktopTls struct {
	running        *sidecar.Sidecar
	follower       *sidecar.SidecarConfigFollower
	stateDirectory string
	network        *urDaemonNetwork
	cancel         context.CancelFunc
	done           chan struct{}
}

func (self *urDesktopTls) Name() string { return "desktop-tls" }

func (self *urDesktopTls) Attach(env *sidecar.SidecarEnv) error { return nil }

func (self *urDesktopTls) Close() {
	self.cancel()
	<-self.done
}

func (self *urDesktopTls) run(ctx context.Context, log sidecar.Logger) {
	defer close(self.done)
	if _, err := self.follower.WaitStanding(ctx); err != nil {
		return
	}
	settings := self.network.tlsSettings
	if settings == nil {
		return
	}
	for ctx.Err() == nil {
		remove, err := self.install(ctx, log)
		if err == nil {
			defer remove()
			break
		}
		if log.V(1).Enabled() {
			log.Infof("[ur]TLS is waiting for its verified state and keys: %s", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(settings.IdlePollInterval):
		}
	}
	if settings.DirectoryUrl == "" {
		<-ctx.Done()
		return
	}
	for ctx.Err() == nil {
		host, err := newUrTlsCustomHost(ctx, self.running, settings)
		if err == nil {
			host.orderer.Run(ctx, nil)
			return
		}
		// DNS and the secret repo may become available after publication starts.
		select {
		case <-ctx.Done():
			return
		case <-time.After(settings.IdlePollInterval):
		}
	}
}

// The publisher uses the same verified names, device key, approval filer and socket path as the rest of the daemon.
func (self *urDesktopTls) install(ctx context.Context, log sidecar.Logger) (func(), error) {
	engine := self.follower.AclEngine()
	if engine == nil {
		return nil, sidecar.ErrTlsPublishUnavailable
	}
	args, err := self.running.TlsComponentArgs()
	if err != nil {
		return nil, err
	}
	grants := sidecar.NewAclGrantFiler(self.running, engine)
	args.Publish = &sidecar.TlsPublishArgs{
		Grants:      grants,
		ClientNames: func() ([]string, error) { return self.clientNames(ctx) },
		DaemonPorts: func() []int { return urTlsDaemonPorts(self.network.localListeners()) },
		RecordProbeRefusal: func(reason sidecar.TlsProbeRefusal) {
			log.Warningf("[ur]TLS publish target refused: %s", reason)
		},
	}
	if self.stateDirectory != "" {
		args.Publish.ClientCertificateDirectory = filepath.Join(self.stateDirectory, "tls", args.Manager.NetworkId.String())
	}
	component, err := sidecar.NewTlsComponent(ctx, args)
	if err != nil {
		if args.CloseCtSources != nil {
			args.CloseCtSources()
		}
		return nil, err
	}
	remove, err := self.running.AddComponent(component)
	if err != nil {
		component.Close()
		return nil, err
	}
	unregister := self.running.RegisterEffectLookup(sidecar.SidecarActionPublish, grants.Lookup)
	return func() {
		unregister()
		remove()
	}, nil
}

// Names reserved by §7.7 at the exact config head this follower verified.
func (self *urDesktopTls) clientNames(ctx context.Context) ([]string, error) {
	state := self.follower.VerifiedState()
	heads := self.follower.Heads()
	if state == nil || self.follower.AclEngine() == nil || heads == nil || state.Base() == nil {
		return nil, errors.New("the verified client names are unavailable")
	}
	base := state.Base()
	head, err := heads.ReadConfigHead(ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
	if err != nil {
		return nil, err
	}
	if head == nil {
		return nil, errors.New("the verified config head is unavailable")
	}
	table, err := head.Names()
	if err != nil {
		return nil, err
	}
	scopes := state.TeamScopeLabels()
	names, err := sidecar.ConfigNames(table, state.Rows().GetSidecars(), scopes)
	if err != nil {
		return nil, err
	}
	reserved := slices.Clone(scopes)
	for _, name := range names {
		reserved = append(reserved, name)
	}
	slices.Sort(reserved)
	return slices.Compact(reserved), nil
}

// A publish target cannot be any of the daemon's bound ports, including its IPv6 listeners.
func urTlsDaemonPorts(listeners []sidecar.DaemonLocalListenerStatus) []int {
	var ports []int
	for _, listener := range listeners {
		for _, address := range listener.Addresses {
			_, port, err := net.SplitHostPort(address)
			if err != nil {
				continue
			}
			value, err := strconv.Atoi(port)
			if err == nil {
				ports = append(ports, value)
			}
		}
	}
	slices.Sort(ports)
	return slices.Compact(ports)
}
