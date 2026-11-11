// Ticket issuance (§9.6, D-SOCK-4, D-SOCK-12; DESIGN-DETAILS 13.2.3's find step 9), and the failed tickets a
// Find carries back (§9.6's dialer paragraph).
//
//   - A ticket names the listener's network, its name or its token path (never both), the listener and its
//     listen, and the dialer, which is the Required session's source: the caller, or for an urnetwork-edge
//     caller one of its K clients, ids[h(listener_client_id) mod K], so a listener's edge streams share one
//     client (§13.6). It carries the log position the signer's own state allowed it at and the grant and grant
//     expiry of the verdict the Find rests on.
//   - It lives TicketLifetime, 30 s, and is signed by the newest key that signs, through
//     sidecar.SignSocketTicket, which refuses one past §9.6's bounds, so a Find never hands out a ticket a
//     listener must refuse. The bytes it signs are the bytes it returns.
//   - A failed ticket counts only once it verifies under a key the service publishes, is unexpired, names this
//     Find's group, and names the caller as its dialer, one of its K for an edge, so only holders report and a
//     report cannot be replayed past the ticket's life. An edge reports only accept timeouts (§9.6).
//
// No key is created, derived or unwrapped here, so nothing calls testHookSecret: the signing key comes from
// SocketTicketKeys. Safe for concurrent use.

package socketsservice

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A ticket_id's bytes (§9.6).
const socketTicketIdByteCount = 16

// No key signs: the engine is not ready, and a Find answers unavailable.
var errSocketNoSigningKey = errors.New("no socket ticket key signs")

// One of the edge's K clients for listenerClientId: ids[h(listener_client_id) mod K], h the first 8 bytes of
// SHA-256 of the id, so the same listener always maps to the same client of the same K (§9.6, §13.6).
func socketEdgeDialerClientId(clientIds []connect.Id, listenerClientId connect.Id) connect.Id {
	digest := sha256.Sum256(listenerClientId.Bytes())
	return clientIds[binary.BigEndian.Uint64(digest[:8])%uint64(len(clientIds))]
}

// 16 random bytes for a ticket's id.
func newSocketTicketId() ([]byte, error) {
	ticketId := make([]byte, socketTicketIdByteCount)
	if _, err := rand.Read(ticketId); err != nil {
		return nil, err
	}
	return ticketId, nil
}

// One uniform 32-bit draw for a pick (§9.7's step 2), from the system's randomness.
func socketCryptoDraw() uint32 {
	var drawBytes [4]byte
	if _, err := rand.Read(drawBytes[:]); err != nil {
		// crypto/rand does not fail on a supported system; a fixed draw only skews one pick
		return 0
	}
	return binary.BigEndian.Uint32(drawBytes[:])
}

// What one listener's ticket rests on.
type socketTicketGrant struct {
	grantId           []byte
	grantExpireMillis uint64
}

// What a Find signs for one listener.
type socketTicketArgs struct {
	networkId       connect.Id
	name            *socketParsedName
	listener        *SocketStoreListener
	dialerClientId  connect.Id
	dialerNetworkId connect.Id
	policyVersion   uint64
	grant           *socketTicketGrant
	backup          bool
	now             time.Time
}

// The signed ticket's bytes for StreamOpen.ticket, as SignSocketTicket made them.
func (self *SocketsService) signTicket(args *socketTicketArgs) ([]byte, error) {
	ticketKeys, signs := self.currentTicketKeys()
	if !signs {
		return nil, errSocketNoSigningKey
	}
	keyId, privateKey, signs := ticketKeys.SigningKey()
	if !signs {
		return nil, errSocketNoSigningKey
	}
	ticketId, err := newSocketTicketId()
	if err != nil {
		return nil, err
	}
	issueMillis := uint64(max(args.now.UnixMilli(), 0))
	ticket := &protocol.SocketTicket{
		TicketId:              ticketId,
		NetworkId:             args.networkId.Bytes(),
		Name:                  args.name.name,
		ListenerClientId:      args.listener.Candidate.ListenerClientId.Bytes(),
		ListenId:              args.listener.Candidate.ListenId.Bytes(),
		DialerClientId:        args.dialerClientId.Bytes(),
		DialerNetworkId:       args.dialerNetworkId.Bytes(),
		IssueTimeMillis:       issueMillis,
		ExpireTimeMillis:      issueMillis + uint64(self.settings.Store.Scheduler.TicketLifetime.Milliseconds()),
		PolicyVersion:         args.policyVersion,
		GrantId:               args.grant.grantId,
		Backup:                args.backup,
		GrantExpireTimeMillis: args.grant.grantExpireMillis,
		NameToken:             args.name.nameToken,
	}
	testHookBarrier("sockets.find.sign.before", "")
	signedTicket, err := sidecar.SignSocketTicket(keyId, privateKey, ticket)
	if err != nil {
		return nil, err
	}
	ticketBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(signedTicket)
	if err != nil {
		return nil, err
	}
	self.signedCount.Add(1)
	return ticketBytes, nil
}

// The failed tickets of a Find that count: each verified under a published key, unexpired at now, for this
// Find's group in networkId, held by the caller, and for an edge an accept timeout. Each is counted into
// failure_reports_total by its reason, or as dropped.
func (self *SocketsService) failedTicketReports(
	caller *socketCaller,
	edgeClientIds []connect.Id,
	networkId connect.Id,
	name *socketParsedName,
	failedTickets []*sidecar.SocketFailedTicket,
	now time.Time,
) []*SocketStoreReport {
	reports := []*SocketStoreReport{}
	if len(failedTickets) == 0 {
		return reports
	}
	ticketKeys, _ := self.currentTicketKeys()
	if ticketKeys == nil {
		for range failedTickets {
			self.metrics.failureReportCount.Add(1, socketFailureReasonDropped)
		}
		return reports
	}
	verifyKeys := ticketKeys.VerifyKeys()
	nowMillis := uint64(max(now.UnixMilli(), 0))
	seenTicketIds := map[string]bool{}
	held := func(dialerClientId []byte) bool {
		if !caller.edge {
			return bytes.Equal(dialerClientId, caller.principal.ClientId.Bytes())
		}
		for _, clientId := range edgeClientIds {
			if bytes.Equal(dialerClientId, clientId.Bytes()) {
				return true
			}
		}
		return false
	}
	for _, failed := range failedTickets {
		ticket, err := sidecar.VerifySocketTicket(failed.Ticket, verifyKeys, nowMillis)
		counts := err == nil &&
			nowMillis < ticket.GetExpireTimeMillis() &&
			bytes.Equal(ticket.GetNetworkId(), networkId.Bytes()) &&
			ticket.GetName() == name.name && bytes.Equal(ticket.GetNameToken(), name.nameToken) &&
			bytes.Equal(ticket.GetDialerNetworkId(), caller.principal.NetworkId.Bytes()) &&
			held(ticket.GetDialerClientId()) &&
			(!caller.edge || failed.Reason == sidecar.SocketFailedReasonTimeout) &&
			!seenTicketIds[string(ticket.GetTicketId())]
		if !counts {
			self.metrics.failureReportCount.Add(1, socketFailureReasonDropped)
			continue
		}
		listenerClientId, errListener := connect.IdFromBytes(ticket.GetListenerClientId())
		listenId, errListen := connect.IdFromBytes(ticket.GetListenId())
		if errListener != nil || errListen != nil {
			self.metrics.failureReportCount.Add(1, socketFailureReasonDropped)
			continue
		}
		seenTicketIds[string(ticket.GetTicketId())] = true
		self.metrics.failureReportCount.Add(1, string(failed.Reason))
		reports = append(reports, &SocketStoreReport{ListenerClientId: listenerClientId, ListenId: listenId})
	}
	return reports
}
