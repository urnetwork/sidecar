// ur keys add-presence, rm and ls (MCP-M3-09; §16.6's register, remove, first key and labels rows, D-MCP-19, FS-124),
// cmd_keys.go's other parts:
//
//	ur keys add-presence   a new presence key on this host's authenticator, its KeyRegister signed after the person's
//	                       yes on /dev/tty, never through MCP or a hook: the key's own proof, and the countersignature
//	                       of a live key this device registered where it holds one; a member's first key registers so
//	ur keys rm <key_id>    the KeyRevoke of one of the member's keys, after the same yes, only from a device that
//	                       registered a live presence key of its own, under its countersignature
//	ur keys ls             the member's live presence keys, each with its registering device, its position in the log
//	                       and whether this host holds it
//
// The deciding methods are Confirm methods, so only a confirmed control call reaches them. The authenticator asks the
// person itself, for biometry, a passcode or a touch: a refusal or a failure signs nothing.

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur keys calls for presence keys.
const (
	urMethodKeysList        = "keys.list"
	urMethodKeysAddPresence = "keys.add_presence"
	urMethodKeysRemove      = "keys.remove"
)

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urKeysPresenceMethods)
}

// What the presence key methods act on: a target hosting a Sidecar, on a daemon with or without an authenticator.
type urKeysPresenceTarget interface {
	// The member's live presence keys, and whether this host has an authenticator.
	presenceKeys() ([]*sidecar.SidecarPresenceKey, bool, error)
	// A confirmed call's new key.
	addPresenceKey(ctx context.Context) (*sidecar.SidecarPresenceKey, error)
	// A confirmed call's removal.
	removeKey(ctx context.Context, keyId []byte) error
}

func (self *urDaemonNetwork) presenceKeys() ([]*sidecar.SidecarPresenceKey, bool, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, false, err
	}
	provider := self.daemon.PresenceProvider()
	keys, err := running.PresenceKeys(provider)
	return keys, provider != nil, err
}

func (self *urDaemonNetwork) addPresenceKey(ctx context.Context) (*sidecar.SidecarPresenceKey, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	provider := self.daemon.PresenceProvider()
	if provider == nil {
		return nil, sidecar.ErrPresenceUnavailable
	}
	return running.RegisterPresenceKey(ctx, provider, sidecar.SidecarActConfirmed, self.daemon.PresencePrompt(running))
}

func (self *urDaemonNetwork) removeKey(ctx context.Context, keyId []byte) error {
	running, err := self.onlySidecar()
	if err != nil {
		return err
	}
	return running.RevokePresenceKey(ctx, keyId, self.daemon.PresenceProvider(), sidecar.SidecarActConfirmed, self.daemon.PresencePrompt(running))
}

// One key as keys.list answers it: ids, positions and times, never a public key.
type urPresenceKeyItem struct {
	KeyId                string     `json:"key_id"`
	Alg                  string     `json:"alg"`
	RegisteringSidecarId sidecar.Id `json:"registering_sidecar_id"`
	Position             uint64     `json:"position"`
	NotAfterMillis       int64      `json:"not_after_millis"`
	Held                 bool       `json:"held,omitempty"`
}

// keys.list's reply.
type urPresenceKeysReply struct {
	Keys []*urPresenceKeyItem `json:"keys"`
	// whether this host has an authenticator a new key can be made on
	Authenticator bool `json:"authenticator,omitempty"`
}

// keys.remove's params.
type urKeysRemoveParams struct {
	KeyId string `json:"key_id"`
}

// A key as keys.list answers it.
func urPresenceKeyItemOf(key *sidecar.SidecarPresenceKey) *urPresenceKeyItem {
	return &urPresenceKeyItem{
		KeyId:                hex.EncodeToString(key.KeyId),
		Alg:                  key.Alg.String(),
		RegisteringSidecarId: key.RegisteringSidecarId,
		Position:             key.Position,
		NotAfterMillis:       key.NotAfter.UnixMilli(),
		Held:                 key.Held,
	}
}

// The presence key methods over target, when it hosts a Sidecar.
func urKeysPresenceMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	keys, ok := target.(urKeysPresenceTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodKeysList,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				presenceKeys, authenticator, err := keys.presenceKeys()
				if err != nil {
					return nil, err
				}
				reply := &urPresenceKeysReply{Keys: []*urPresenceKeyItem{}, Authenticator: authenticator}
				for _, key := range presenceKeys {
					reply.Keys = append(reply.Keys, urPresenceKeyItemOf(key))
				}
				return reply, nil
			},
		},
		{
			Name:    urMethodKeysAddPresence,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				key, err := keys.addPresenceKey(ctx)
				if err != nil {
					return nil, err
				}
				return urPresenceKeyItemOf(key), nil
			},
		},
		{
			Name:    urMethodKeysRemove,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urKeysRemoveParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, errors.New("a removal takes a key id")
				}
				keyId, err := hex.DecodeString(params.KeyId)
				if err != nil || len(keyId) == 0 {
					return nil, errors.New("a removal takes a key id in hex")
				}
				return nil, keys.removeKey(ctx, keyId)
			},
		},
	}
}

// ur keys add-presence: after the person's yes on /dev/tty, a new key on this host's authenticator.
func runUrKeysAddPresence(ctx context.Context, cli *urCli) error {
	confirmed, err := confirmOnTty(cli, "Register a presence key on this host? The authenticator asks for biometry, a passcode or a touch.")
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	return urAddPresenceKey(ctx, cli)
}

// The confirmed call that registers a key, and its line.
func urAddPresenceKey(ctx context.Context, cli *urCli) error {
	key := &urPresenceKeyItem{}
	if err := cli.callDaemon(ctx, urMethodKeysAddPresence, nil, true, key); err != nil {
		return err
	}
	cli.printf("presence key %s registered, %s\n", key.KeyId, key.Alg)
	return nil
}

// ur keys rm <key_id>: after the person's yes on /dev/tty, the key's KeyRevoke.
func runUrKeysRemove(ctx context.Context, cli *urCli, options docopt.Opts) error {
	keyIdText, _ := options.String("<key_id>")
	if _, err := hex.DecodeString(keyIdText); err != nil || keyIdText == "" {
		return fmt.Errorf("%q is not a key id", keyIdText)
	}
	confirmed, err := confirmOnTty(cli, fmt.Sprintf("Remove key %s? Nothing it signed is undone.", keyIdText))
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	if err := cli.callDaemon(ctx, urMethodKeysRemove, &urKeysRemoveParams{KeyId: keyIdText}, true, nil); err != nil {
		return err
	}
	cli.printf("key %s removed\n", keyIdText)
	return nil
}

// ur keys ls: the member's live presence keys, one a line.
func runUrKeysList(ctx context.Context, cli *urCli) error {
	reply := &urPresenceKeysReply{}
	if err := cli.callDaemon(ctx, urMethodKeysList, nil, false, reply); err != nil {
		return err
	}
	if len(reply.Keys) == 0 {
		cli.printf("no presence key\n")
	}
	for _, key := range reply.Keys {
		held := ""
		if key.Held {
			held = ", on this host"
		}
		cli.printf("%s  %s  registered by %s at %d, until %s%s\n", key.KeyId, key.Alg, key.RegisteringSidecarId, key.Position,
			time.UnixMilli(key.NotAfterMillis).UTC().Format(time.RFC3339), held)
	}
	return nil
}

// ur login's offer (§16.6's first run row): where this host has an authenticator and holds no key of the member, the
// person is asked on /dev/tty to register one, so a single-device member need not rest on harness evidence. With no
// terminal, or no authenticator, nothing is offered.
func urOfferPresenceKey(ctx context.Context, cli *urCli) error {
	reply := &urPresenceKeysReply{}
	if err := cli.callDaemon(ctx, urMethodKeysList, nil, false, reply); err != nil || !reply.Authenticator {
		return nil
	}
	for _, key := range reply.Keys {
		if key.Held {
			return nil
		}
	}
	confirmed, err := confirmOnTty(cli, "Register a presence key on this host, so approvals here need biometry, a passcode or a touch?")
	if err != nil || !confirmed {
		return nil
	}
	return urAddPresenceKey(ctx, cli)
}
