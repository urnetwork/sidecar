// The generator wrapper (§17.9's sign, C13, D-BRIDGE-17, I-3): what a host's link builds its window clients through,
// so no contract leaves one unsigned or unchecked. NewBridgeLinkGenerator wraps the host's connect.MultiClientGenerator
// and, at each NewClient, before the client is handed to the window and so before it can send:
//
//	sign    reads the client's id, its ClientKey's public key and its token's exp, the strict_exp a delegation's
//	        not_after_ms may not pass (ByJwt.ExpireTime), and calls the link's sign, which the host was handed; per
//	        NewClient rather than per mint, so a window client is never left with another's delegation
//	carry   ContractManager.SetWindowDelegation, so every non-companion CreateContract carries the bytes unchanged
//	check   ContractManager.SetContractDestinationCheck, so every contract answers to the client key the target's
//	        verified binding names (bridge_link.go's pin row)
//	watch   contract statuses and encryption events, which the link's health reads (plan-BRIDGE-small-readings #15)
//	resign  each window client set up is kept until the window removes it, so a share's new signer (§17.9's sign row;
//	        Bridge.ResignShares) signs it again and its later contracts carry the new delegation
//
// A step that fails retires the client with its args and returns no client: the window opens no contract, and the link
// fails closed. The window then hands the args back once, which the wrapper takes without retiring them again. A
// generator made from a context that no link's build handed its host refuses every client.
//
// The wrapper forwards MultiClientGenerator's own methods. A connect window reads its generator's optional capabilities
// by type, and the host generator's are not forwarded: a link's window takes connect's legacy setup path, which the
// window still bounds by its setup deadline, and runs without transport migration or discovery narrowing, which a
// fixed window of one target does not use.

package device

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/connect"
)

// The wrapper. See the file's comment.
type bridgeLinkGenerator struct {
	connect.MultiClientGenerator
	// the link's build, nil when the context named none
	built *bridgeLinkBuilt
	sign  func(windowClientId connect.Id, windowClientPublicKey []byte, notAfter time.Time) ([]byte, error)

	stateLock sync.Mutex
	// args whose client the wrapper retired with them, which the window hands back once
	retiredArgs map[*connect.MultiClientGeneratorClientArgs]bool
	// the window clients set up and not yet removed, which resign signs again
	live map[*connect.Client]bridgeLinkLiveClient
}

// What a live window client was signed for: its ClientKey and its strict_exp.
type bridgeLinkLiveClient struct {
	publicKey []byte
	notAfter  time.Time
}

// Wraps generator for the link whose build handed the host ctx: every window client it builds is signed for by sign,
// the argument the host's NewBridgeLink got, and holds its contracts to the link's target. Pass the context and sign
// NewBridgeLink was called with; any other context makes a generator that refuses every client.
func NewBridgeLinkGenerator(
	ctx context.Context,
	generator connect.MultiClientGenerator,
	sign func(windowClientId connect.Id, windowClientPublicKey []byte, notAfter time.Time) ([]byte, error),
) connect.MultiClientGenerator {
	built, _ := ctx.Value(bridgeLinkContextKey{}).(*bridgeLinkBuilt)
	self := &bridgeLinkGenerator{
		MultiClientGenerator: generator,
		built:                built,
		sign:                 sign,
		retiredArgs:          map[*connect.MultiClientGeneratorClientArgs]bool{},
		live:                 map[*connect.Client]bridgeLinkLiveClient{},
	}
	if built != nil {
		built.addGenerator(self)
	}
	return self
}

// connect.MultiClientGenerator: the host generator's client, signed for and checked before it is returned, or none.
func (self *bridgeLinkGenerator) NewClient(
	ctx context.Context,
	args *connect.MultiClientGeneratorClientArgs,
	clientSettings *connect.ClientSettings,
) (*connect.Client, error) {
	if self.built == nil || self.sign == nil {
		return nil, fmt.Errorf("%w: a generator no link's build made", ErrBridgeLinkRefused)
	}
	client, err := self.MultiClientGenerator.NewClient(ctx, args, clientSettings)
	if err != nil {
		return client, err
	}
	if client == nil {
		return nil, fmt.Errorf("%w: the host's generator built no client", ErrBridgeLinkRefused)
	}
	err = self.setUp(client, args)
	if err != nil {
		testHookBarrier("bridge_link_generator.retire.before", "")
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.retiredArgs[args] = true
		}()
		self.MultiClientGenerator.RemoveClientWithArgs(client, args)
		client.Cancel()
		testHookBarrier("bridge_link_generator.retire.after", "")
		return nil, err
	}
	return client, nil
}

// The file's sign, carry, check and watch rows, on a client nothing has sent through.
func (self *bridgeLinkGenerator) setUp(client *connect.Client, args *connect.MultiClientGeneratorClientArgs) error {
	if args == nil || args.ClientAuth == nil {
		return fmt.Errorf("%w: a window client with no token", ErrBridgeLinkRefused)
	}
	byJwt, err := connect.ParseByJwtUnverified(args.ClientAuth.ByJwt)
	if err != nil {
		return fmt.Errorf("%w: a window client token that does not parse", ErrBridgeLinkRefused)
	}
	if byJwt.ClientId != client.ClientId() {
		return fmt.Errorf("%w: a window client token naming another client", ErrBridgeLinkRefused)
	}
	// a token with no exp bounds nothing, so it gets no delegation (connect's ByJwt.ExpireTime)
	if byJwt.ExpireTime.IsZero() {
		return fmt.Errorf("%w: a window client token with no exp", ErrBridgeLinkRefused)
	}
	keyManager := client.ClientKeyManager()
	if keyManager == nil {
		return fmt.Errorf("%w: a window client with no ClientKey", ErrBridgeLinkRefused)
	}
	delegation, err := self.sign(client.ClientId(), keyManager.PublicKey(), byJwt.ExpireTime)
	if err != nil {
		return err
	}
	contractManager := client.ContractManager()
	contractManager.SetContractDestinationCheck(self.built.destinationAllowed)
	contractManager.SetWindowDelegation(delegation)
	contractManager.AddContractStatusCallback(self.built.contractStatus)
	if sessions := client.EncryptionSessionManager(); sessions != nil {
		sessions.AddEncryptionEventCallback(self.built.encryptionEvent)
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.live[client] = bridgeLinkLiveClient{publicKey: keyManager.PublicKey(), notAfter: byJwt.ExpireTime}
	}()
	return nil
}

// connect.MultiClientGenerator: a window client the window removes leaves the live ones before the host's generator
// retires it.
func (self *bridgeLinkGenerator) RemoveClientWithArgs(client *connect.Client, args *connect.MultiClientGeneratorClientArgs) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.live, client)
	}()
	self.MultiClientGenerator.RemoveClientWithArgs(client, args)
}

// Signs each live window client again with the link's sign and carries the new delegation on its later contracts (the
// file's resign row). Off the packet path, outside every lock: sign may wait on §18.6's channel. Answers how many were
// signed, and the failures joined; a client whose signing fails keeps the delegation it had.
func (self *bridgeLinkGenerator) resign() (int, error) {
	type liveClient struct {
		client *connect.Client
		live   bridgeLinkLiveClient
	}
	clients := func() []liveClient {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		clients := make([]liveClient, 0, len(self.live))
		for client, live := range self.live {
			clients = append(clients, liveClient{client: client, live: live})
		}
		return clients
	}()
	count := 0
	var failed error
	for _, held := range clients {
		delegation, err := self.sign(held.client.ClientId(), held.live.publicKey, held.live.notAfter)
		if err != nil {
			failed = errors.Join(failed, err)
			continue
		}
		held.client.ContractManager().SetWindowDelegation(delegation)
		count += 1
	}
	return count, failed
}

// connect.MultiClientGenerator: args the window hands back, retired by the host's generator unless the wrapper retired
// them already with their client.
func (self *bridgeLinkGenerator) RemoveClientArgs(args *connect.MultiClientGeneratorClientArgs) {
	retired := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.retiredArgs[args] {
			return false
		}
		delete(self.retiredArgs, args)
		return true
	}()
	if retired {
		return
	}
	self.MultiClientGenerator.RemoveClientArgs(args)
}
