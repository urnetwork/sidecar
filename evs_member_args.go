//go:build !ios_extension

// The authenticated transport, sealed storage and verified state used by app and browser EVS clients.
package sidecar

import (
	"context"
	"fmt"
)

// The args an EvsClient takes from this Sidecar for the network it is enrolled in: the service url, SidecarApi's
// transport, ServiceToken and ForgetServiceToken, Sign, the identity, the evs component's sealed directory, events,
// the clock, the log, settings.Evs, the team directory's hooks around a create (§16.11's default and private rows,
// QD-748), and SignProvenance with settings.AgentSubkeys, so the agent's subkey in this network's keychain.ur signs a
// push made for its agent_id and a reader holds certificates to this sidecar's bound (evs_provenance.go; owner decision
// 470). gkm, the verified config state and the statement poster are the caller's, from KEYS, TEAM and CORE-M2-02 as
// each lands.
func (self *Sidecar) EvsClientArgs(gkm GkmClient, config EvsConfigFunction, fileStatement EvsFileStatementFunction) (*EvsClientArgs, error) {
	networkId := self.enrolledNetworkId()
	if networkId == nil {
		return nil, fmt.Errorf("%w: evs needs an enrolled network", errInvalidSettings)
	}
	store, err := self.instance.Store(networkId).Directory(evsComponentName, evsComponentName)
	if err != nil {
		return nil, err
	}
	args := &EvsClientArgs{
		NetworkId:          *networkId,
		EvsUrl:             self.settings.EvsUrl,
		Transport:          self.sidecarApi.Transport(),
		ServiceToken:       self.ServiceToken,
		ForgetServiceToken: self.ForgetServiceToken,
		Sign:               self.Sign,
		Identity:           self.currentIdentity,
		Gkm:                gkm,
		Store:              store,
		Config:             config,
		FileStatement:      fileStatement,
		Emit:               self.emitEvent,
		Clock:              self.clock,
		Log:                self.log,
		Settings:           self.settings.Evs,
		RepoCreated:        self.announceCreatedRepo,
		ConfigFollow:       self.evsConfigFollow,
		SignProvenance:     self.SignProvenance,
		AgentSubkeys:       self.settings.AgentSubkeys,
	}
	self.setMemberEvsHooks(args)
	return args, nil
}

// EvsClientArgs.ConfigFollow: one follow of the network's authorization log through the config follower's client
// (ConfigClient.CatchUp, within its FollowTimeout). Nothing where no follower stands yet, which follows on its own.
func (self *Sidecar) evsConfigFollow(ctx context.Context) error {
	follower := self.ConfigFollower()
	if follower == nil {
		return nil
	}
	client := follower.Client()
	if client == nil {
		return nil
	}
	return client.CatchUp(ctx)
}
