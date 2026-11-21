//go:build !ios_extension && !sidecar_http

// A connect generation delivers team hints through its subprotocol.
package sidecar

import "context"

// Registers the network follower for every local client generation.
func (self *Sidecar) attachConfigFollower(follower *SidecarConfigFollower) (func(), error) {
	return self.AddComponent(follower)
}

// Begins following this generation's identity and passes team notices until the generation ends.
func (self *SidecarConfigFollower) Attach(env *SidecarEnv) error {
	if err := self.followIdentity(env.Identity); err != nil {
		return err
	}
	if env.Subprotocol != nil {
		if hints := self.args.Hints; hints != nil {
			for _, topic := range []string{PushTopicGkm, PushTopicGkmGroupPrefix} {
				if remove, err := env.Subprotocol.Subscribe(topic, hints.Receive); err == nil {
					context.AfterFunc(env.Ctx, remove)
				}
			}
			hints.Resync()
		}
		if unsubscribe, err := env.Subprotocol.Subscribe(PushTopicTeam, self.receiveNotice); err == nil {
			context.AfterFunc(env.Ctx, unsubscribe)
		}
	}
	return nil
}

// The connect component subscribes at attachment, including while the follower is joining.
// Public reads use Evs only after the enrolled anchor has been checked.
func (self *MemberReplica) EvsComponent() *EvsComponent {
	self.evs.EnablePrefixRules(self.running.EvsPrefixRulesArgs())
	return NewEvsComponent(self.evs)
}
