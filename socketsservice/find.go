// POST /socket/find (§9.6, D-SOCK-4, D-SOCK-5, D-SOCK-6, D-SOCK-12, D-SOCK-14, D-SOCK-15, C9), built to
// DESIGN-DETAILS 13.2.3's find path, which governs where it and §9.6 differ. A refusal signs nothing, and
// nothing is signed for a listener the signer's own state refuses at the position it holds when it signs
// (13.3's S1). The service never contacts a listener (D-SOCK-4).
//
//  1. authenticate (request.go); the Find's shape, invalid; §19.11's sockets gate for the name's network; one
//     token of the caller's bucket, the edge bound for an urnetwork-edge caller; a turn in the fair queue for
//     the name's network: unavailable
//  2. the kill set: denied
//  3. the view S of the name's network, unloaded or behind answering unavailable; then the dial check on S,
//     before any group is read, so refusals hide names: MayDial for the caller, an edge's as
//     autogroup:public with MayPublish on tls/. An smtp/ edge Find has no dial check here: each receiver's
//     own listen grant decides it at step 7 (§9.10, §15.4). denied
//  4. the paying network, the listener's for an edge Find and else the caller's, spent in §20.7's over-limit
//     snapshot: quota
//  5. the failed tickets: each verified and held by the caller, else dropped (tickets.go)
//  6. one Pick: no_listener, busy, or a primary and a backup, each with its stored lease
//  7. the newest view S', and if it moved, step 3's verdicts again on S'. Then the listener check on each
//     picked listener (checkListener). A refused listener is removed for cause at S''s position, which leaves
//     its tombstone, with its {svc_} pairs at that position when it holds no other edge name, and hinted
//     SOCKET_HINT_REVOKED. If the primary got no ticket the backup, if it passed,
//     is the primary; if every picked listener was refused, one more Pick, then no_listener; if no picked
//     listener could be judged, unavailable for BehindRetryAfter, by when this process has loaded
//  8. for an edge Find, the {svc_} pair of each listener of the answer, at S''s position, for the lesser of
//     its grant's remaining life and EdgePairTtl, unless this process wrote the same pair within
//     PairWriteInterval; a pair below its floor hands the floor to the gate as evidence, and the Find answers
//     unavailable
//  9. sign each: policy_version S''s position, the grant of the dial verdict, the publish verdict on tls/,
//     or the receiver's own listen verdict on smtp/
//
// Who may Find what (§9.4's table). tls/ and smtp/ names are their edges' to dial, so a sidecar's Find of one
// is denied; a blinded name is dialed within its own network (§6.4), so an edge's Find of one, or a sidecar's
// in another network, is denied; ur/ is SOCK-M9-01's, and every Find of it is denied until that lands. Only an
// urnetwork-edge caller sends client_ids. Nothing here logs a name or the affinity key, which lives for the
// request alone (sock-2). Safe for concurrent use.

package socketsservice

import (
	"net/http"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// What the listener check made of one picked listener.
type socketListenerCheck int

const (
	// It may take a ticket at the view's position.
	socketListenerPassed socketListenerCheck = iota + 1
	// The view refuses it: it is removed for cause.
	socketListenerRefused
	// A fresher process admitted it above the view's position, which this process cannot judge: no ticket,
	// and its position is evidence for the gate.
	socketListenerUnjudged
)

// A listener that passed its check, with the grant its ticket carries.
type socketTicketedListener struct {
	listener *SocketStoreListener
	grant    *socketTicketGrant
}

// Handles POST /socket/find.
func (self *SocketsService) serveFind(w http.ResponseWriter, r *http.Request) {
	startTime := self.clock.Now()
	result, refusal := self.find(r)
	label := socketFindResultOk
	switch {
	case refusal != nil && refusal.status != http.StatusOK:
		label = socketFindResultUnauthorized
		if refusal.status == http.StatusServiceUnavailable {
			label = socketFindResultUnavailable
		}
		writeSocketStatus(w, refusal)
	case refusal != nil:
		label = socketFindResultOf(refusal.code)
		writeSocketJson(w, &sidecar.SocketFindResult{Error: refusal.socketError()})
	default:
		writeSocketJson(w, result)
	}
	self.metrics.findCount.Add(1, label)
	self.metrics.findSeconds.Observe(self.clock.Now().Sub(startTime).Seconds())
}

// find_total's result for a refusal's code.
func socketFindResultOf(code sidecar.SocketErrorCode) string {
	switch code {
	case sidecar.SocketErrorCodeDenied:
		return socketFindResultDenied
	case sidecar.SocketErrorCodeQuota:
		return socketFindResultQuota
	case sidecar.SocketErrorCodeNoListener:
		return socketFindResultNoListener
	case sidecar.SocketErrorCodeBusy:
		return socketFindResultBusy
	case sidecar.SocketErrorCodeInvalid:
		return socketFindResultInvalid
	}
	return socketFindResultUnavailable
}

// Steps 1 to 9.
func (self *SocketsService) find(r *http.Request) (*sidecar.SocketFindResult, *socketRefusal) {
	// 1
	caller, refusal := self.authenticate(r)
	if refusal != nil {
		return nil, refusal
	}
	args := &sidecar.SocketFindArgs{}
	if err := readSocketJson(r, int64(self.settings.FindMaxBodyByteCount), args); err != nil {
		return nil, socketRefusalOf(sidecar.SocketErrorCodeInvalid, 0)
	}
	name, edgeClientIds, ok := socketFindFormed(caller, args, self.settings)
	if !ok {
		return nil, socketRefusalOf(sidecar.SocketErrorCodeInvalid, 0)
	}
	networkId := *args.NetworkId
	payerNetworkId := caller.principal.NetworkId
	if caller.edge {
		payerNetworkId = networkId
	}
	if refusal := self.gateRefusal(networkId); refusal != nil {
		return nil, refusal
	}
	if refusal := self.chargeRefusal(caller); refusal != nil {
		return nil, refusal
	}
	release, refusal := self.queueTurn(r.Context(), networkId)
	if refusal != nil {
		return nil, refusal
	}
	defer release()
	if !socketFindReaches(caller, networkId, name) {
		return nil, socketRefusalOf(sidecar.SocketErrorCodeDenied, 0)
	}

	// 2
	now := self.clock.Now()
	if self.killSet.kills(networkId, name, now) {
		return nil, socketRefusalOf(sidecar.SocketErrorCodeDenied, 0)
	}

	// 3
	if self.store == nil || self.gate == nil {
		return nil, socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.BehindRetryAfter)
	}
	view, err := self.gate.View(networkId)
	if err != nil {
		return nil, socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.BehindRetryAfter)
	}
	grant, allowed := self.dialCheck(caller, view, networkId, name, now)
	if !allowed {
		return nil, socketRefusalOf(sidecar.SocketErrorCodeDenied, 0)
	}

	// 4
	if self.gate.Spent(payerNetworkId) {
		return nil, socketRefusalOf(sidecar.SocketErrorCodeQuota, self.settings.QuotaRetryAfter)
	}

	// 5
	reports := self.failedTicketReports(caller, edgeClientIds, networkId, name, args.FailedTickets, now)

	// 6
	pickRequest := &SocketStorePickRequest{
		NetworkId:       networkId,
		NameKey:         name.nameKey(),
		DialerClientId:  caller.principal.ClientId,
		DialerNetworkId: caller.principal.NetworkId,
		Protocol:        args.Protocol,
		MinVersion:      args.MinVersion,
		Alpns:           args.Alpn,
		Reports:         reports,
	}
	pick, refusal := self.pick(pickRequest)
	if refusal != nil {
		return nil, refusal
	}

	// 7
	testHookBarrier("sockets.find.recheck.before", "")
	viewNow, err := self.gate.View(networkId)
	if err != nil {
		return nil, socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.BehindRetryAfter)
	}
	now = self.clock.Now()
	if viewNow.Position() != view.Position() {
		if grant, allowed = self.dialCheck(caller, viewNow, networkId, name, now); !allowed {
			return nil, socketRefusalOf(sidecar.SocketErrorCodeDenied, 0)
		}
	}
	position := viewNow.Position()
	ticketed, unjudged := self.checkPicked(viewNow, networkId, name, grant, pick, now)
	if len(ticketed) == 0 && !unjudged {
		// every picked listener was refused and removed: one more pick, with the reports already applied
		pickRequest.Reports = nil
		pick, refusal = self.pick(pickRequest)
		if refusal != nil {
			return nil, refusal
		}
		ticketed, unjudged = self.checkPicked(viewNow, networkId, name, grant, pick, now)
	}
	testHookBarrier("sockets.find.recheck.after", "")
	if len(ticketed) == 0 {
		if unjudged {
			return nil, socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.BehindRetryAfter)
		}
		return nil, socketRefusalOf(sidecar.SocketErrorCodeNoListener, 0)
	}

	// 8
	dialerClientIdOf := func(listener *SocketStoreListener) connect.Id {
		if caller.edge {
			return socketEdgeDialerClientId(edgeClientIds, listener.Candidate.ListenerClientId)
		}
		return caller.principal.ClientId
	}
	if caller.edge {
		for _, passed := range ticketed {
			if refusal := self.setPair(networkId, position, passed, dialerClientIdOf(passed.listener), now); refusal != nil {
				return nil, refusal
			}
		}
	}

	// 9
	result := &sidecar.SocketFindResult{}
	for index, passed := range ticketed {
		ticketBytes, err := self.signTicket(&socketTicketArgs{
			networkId:       networkId,
			name:            name,
			listener:        passed.listener,
			dialerClientId:  dialerClientIdOf(passed.listener),
			dialerNetworkId: caller.principal.NetworkId,
			policyVersion:   position,
			grant:           passed.grant,
			backup:          0 < index,
			now:             now,
		})
		if err != nil {
			return nil, socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.MaxRetryAfter)
		}
		findTicket := &sidecar.SocketFindTicket{Ticket: ticketBytes, Claim: passed.listener.Registration.Claim}
		if index == 0 {
			result.Primary = findTicket
		} else {
			result.Backup = findTicket
		}
	}
	return result, nil
}

// Step 1's shape, every size read from settings: one network, exactly one of an edge name in canonical form and
// a token path, failed tickets each whole and no more than a Find reports, an affinity key within its size, and
// client ids from an urnetwork-edge caller alone, which must send at least one. The name, and an edge's K ids in
// their order.
func socketFindFormed(caller *socketCaller, args *sidecar.SocketFindArgs, settings *SocketsSettings) (*socketParsedName, []connect.Id, bool) {
	if args.NetworkId == nil || *args.NetworkId == (connect.Id{}) {
		return nil, nil, false
	}
	name, ok := parseSocketRequestName(args.Name, args.NameToken)
	if !ok {
		return nil, nil, false
	}
	if settings.Format.FailedTicketMaxCount < len(args.FailedTickets) || settings.Format.AffinityKeyMaxByteCount < len(args.AffinityKey) {
		return nil, nil, false
	}
	for _, failed := range args.FailedTickets {
		if failed == nil || len(failed.Ticket) == 0 || settings.Format.TicketMaxByteCount < len(failed.Ticket) ||
			(failed.Reason != sidecar.SocketFailedReasonTimeout && failed.Reason != sidecar.SocketFailedReasonRefused) {
			return nil, nil, false
		}
	}
	if !caller.edge {
		return name, nil, len(args.ClientIds) == 0
	}
	if len(args.ClientIds) == 0 || settings.FindMaxClientIdCount < len(args.ClientIds) {
		return nil, nil, false
	}
	edgeClientIds := make([]connect.Id, 0, len(args.ClientIds))
	for _, clientId := range args.ClientIds {
		if clientId == nil || *clientId == (connect.Id{}) {
			return nil, nil, false
		}
		edgeClientIds = append(edgeClientIds, *clientId)
	}
	return name, edgeClientIds, true
}

// Whether the caller may Find a name of this namespace in networkId at all (§9.4's table), before any state is
// read: tls/ and smtp/ by an edge, a blinded name by a sidecar of its own network, and ur/ by nobody until
// SOCK-M9-01.
func socketFindReaches(caller *socketCaller, networkId connect.Id, name *socketParsedName) bool {
	switch name.namespace {
	case sidecar.SocketNamespaceTls, sidecar.SocketNamespaceSmtp:
		return caller.edge
	case sidecar.SocketNamespaceApplication:
		return !caller.edge && networkId == caller.principal.NetworkId
	}
	return false
}

// Step 3's dial check on view: the grant a ticket rests on, and whether the Find may go on. An smtp/ edge Find
// is checked per receiver at step 7, so it passes here with no grant.
func (self *SocketsService) dialCheck(caller *socketCaller, view SocketGateView, networkId connect.Id, name *socketParsedName, now time.Time) (*socketTicketGrant, bool) {
	if name.namespace == sidecar.SocketNamespaceSmtp {
		return nil, true
	}
	request := caller.gateRequest(networkId, name)
	dial := view.MayDial(request, now)
	if dial == nil || !dial.Allowed {
		return nil, false
	}
	if name.namespace != sidecar.SocketNamespaceTls {
		return &socketTicketGrant{grantId: dial.GrantId, grantExpireMillis: dial.GrantExpireMillis}, true
	}
	publish := view.MayPublish(request, now)
	if publish == nil || !publish.Allowed {
		return nil, false
	}
	return &socketTicketGrant{grantId: publish.GrantId, grantExpireMillis: publish.GrantExpireMillis}, true
}

// One Pick (step 6), as the engine answers it: found, or no_listener, busy or unavailable.
func (self *SocketsService) pick(request *SocketStorePickRequest) (*SocketStorePickResult, *socketRefusal) {
	request.FirstDraw = self.draw()
	request.SecondDraw = self.draw()
	request.SampleSeed = self.draw()
	result, err := func() (*SocketStorePickResult, error) {
		ctx, done := self.storeContext()
		defer done()
		testHookBarrier("sockets.find.pick.before", "")
		defer testHookBarrier("sockets.find.pick.after", "")
		return self.store.Pick(ctx, request)
	}()
	if err != nil {
		return nil, socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.MaxRetryAfter)
	}
	self.metrics.exclusionCount.Add(float64(result.ExclusionCount))
	self.metrics.ejectionCount.Add(float64(result.EjectionCount))
	switch result.Outcome {
	case SocketPickFound:
		if result.Primary == nil {
			return nil, socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.MaxRetryAfter)
		}
		return result, nil
	case SocketPickBusy:
		return nil, socketRefusalOf(sidecar.SocketErrorCodeBusy, 0)
	}
	return nil, socketRefusalOf(sidecar.SocketErrorCodeNoListener, 0)
}

// Step 7 for one pick: the picked listeners that passed, primary first, each with its ticket's grant, and
// whether one could not be judged. The refused are removed for cause at view's position and hinted.
func (self *SocketsService) checkPicked(
	view SocketGateView,
	networkId connect.Id,
	name *socketParsedName,
	dialGrant *socketTicketGrant,
	pick *SocketStorePickResult,
	now time.Time,
) ([]*socketTicketedListener, bool) {
	ticketed := []*socketTicketedListener{}
	refused := []*SocketStoreListener{}
	unjudged := false
	for _, listener := range []*SocketStoreListener{pick.Primary, pick.Backup} {
		if listener == nil {
			continue
		}
		check, listen := self.checkListener(view, networkId, name, listener, now)
		switch check {
		case socketListenerPassed:
			grant := dialGrant
			if grant == nil {
				// smtp/: the receiver's own listen grant is what the ticket rests on
				grant = &socketTicketGrant{}
				if listen != nil {
					grant = &socketTicketGrant{grantId: listen.GrantId, grantExpireMillis: listen.GrantExpireMillis}
				}
			}
			ticketed = append(ticketed, &socketTicketedListener{listener: listener, grant: grant})
		case socketListenerRefused:
			refused = append(refused, listener)
		default:
			unjudged = true
		}
	}
	if 0 < len(refused) {
		self.removeRefused(networkId, view.Position(), name, refused, now)
	}
	return ticketed, unjudged
}

// The listener check (DESIGN-DETAILS 13.2.3's find step 7), which SOCK-M5-07's revocation sweep applies to each
// lease too: whether this process's own state, view, lets listener take a ticket for name in networkId at now,
// and on a pass the listener's listen verdict, nil on ur/.
//
// Refused: the listener's client is in the removed-client set, or a kill names the name; else, on any name
// but ur/, MayListen for the listener's stored sidecar on the name, and on tls/ MayPublish for it, refuse, a
// grant that has run out by time since the listener's last heartbeat included. A ur/ listener is a platform
// client its service authorizes (§9.4), so nothing more is asked of it. A lease admitted above view's position
// is unjudged, and its position is handed to the gate as evidence. A lease written before leases kept their
// sidecar reads as none, which no gate allows: its next heartbeat writes it again.
func (self *SocketsService) checkListener(view SocketGateView, networkId connect.Id, name *socketParsedName, listener *SocketStoreListener, now time.Time) (socketListenerCheck, *SocketGateVerdict) {
	listenerClientId := listener.Candidate.ListenerClientId
	if self.removedClients.contains(listenerClientId, now) || self.killSet.kills(networkId, name, now) {
		return socketListenerRefused, nil
	}
	if name.namespace == sidecar.SocketNamespacePlatform {
		return socketListenerPassed, nil
	}
	if view.Position() < listener.PolicyVersion {
		self.gate.Observe(networkId, listener.PolicyVersion)
		return socketListenerUnjudged, nil
	}
	request := &SocketGateRequest{
		NetworkId:       networkId,
		CallerClientId:  listenerClientId,
		CallerNetworkId: networkId,
		SubjectClientId: listenerClientId,
		SidecarId:       listener.SidecarId,
		Name:            name.name,
		NameToken:       name.nameToken,
	}
	listen := view.MayListen(request, now)
	if listen == nil || !listen.Allowed {
		return socketListenerRefused, nil
	}
	if name.namespace == sidecar.SocketNamespaceTls {
		publish := view.MayPublish(request, now)
		if publish == nil || !publish.Allowed {
			return socketListenerRefused, nil
		}
	}
	return socketListenerPassed, listen
}

// Removes refused listeners' leases of name for cause at position (one RemoveEntries), which leaves each a
// tombstone, and hints each removed client SOCKET_HINT_REVOKED for its listen. A listener whose last edge name
// this removed loses its {svc_} pairs at position too, leaving their floor, as registration's step 9 removes
// them: its pairs stand for its edge grants, and it holds no edge name now. A removal the store keeps for a
// newer admission is evidence.
func (self *SocketsService) removeRefused(networkId connect.Id, position uint64, name *socketParsedName, refused []*SocketStoreListener, now time.Time) {
	refs := make([]*SocketStoreEntryRef, 0, len(refused))
	for _, listener := range refused {
		refs = append(refs, &SocketStoreEntryRef{ListenerClientId: listener.Candidate.ListenerClientId, NameKey: name.nameKey()})
	}
	removals, err := func() ([]*SocketStoreRemoval, error) {
		ctx, done := self.storeContext()
		defer done()
		testHookBarrier("sockets.find.remove.before", "")
		defer testHookBarrier("sockets.find.remove.after", "")
		return self.store.RemoveEntries(ctx, networkId, SocketRemoveRefused, position, refs)
	}()
	if err != nil || len(removals) != len(refused) {
		// nothing was signed for them, and the sweep or their next heartbeat judges them again
		return
	}
	for index, removal := range removals {
		switch {
		case removal.Removed != nil:
			if SocketPairNameKey(removal.Removed.NameKey) && !removal.EdgeEntriesRemain {
				self.removePairs(removal.Removed.ListenerClientId, position)
			}
			self.hintRevoked(refused[index], now)
		case removal.Kept && position < removal.PolicyVersion:
			self.gate.Observe(networkId, removal.PolicyVersion)
		}
	}
}

// Removes listenerClientId's {svc_} pairs at position, leaving their floor, once it holds no edge name (QD-656;
// DESIGN-DETAILS 13.2.3's registration step 9 and find step 7), and forgets this process's memos of them, so
// the next Find writes them again and the next accepted edge registration renews them. A failed call leaves
// the pairs to EdgePairTtl, which ends them within 15 minutes whatever happens here.
func (self *SocketsService) removePairs(listenerClientId connect.Id, position uint64) {
	err := func() error {
		ctx, done := self.storeContext()
		defer done()
		testHookBarrier("sockets.pairs.remove.before", "")
		defer testHookBarrier("sockets.pairs.remove.after", "")
		return self.store.RemoveServicePairs(ctx, listenerClientId, position)
	}()
	if err != nil {
		return
	}
	self.pairWrites.forgetListener(listenerClientId)
	self.pairTouches.forget(listenerClientId)
}

// SOCKET_HINT_REVOKED for listener's listen (§9.5): its client calls registrations at once, and that answer
// is authoritative. A hint is a hint, so a failed one costs only latency.
func (self *SocketsService) hintRevoked(listener *SocketStoreListener, now time.Time) {
	if self.host.Push == nil {
		return
	}
	body, err := proto.Marshal(&protocol.SocketHint{
		Kind:     protocol.SocketHintKind_SOCKET_HINT_REVOKED,
		ListenId: listener.Candidate.ListenId.Bytes(),
	})
	if err != nil {
		return
	}
	ctx, done := self.storeContext()
	defer done()
	self.host.Push.Hint(ctx, []connect.Id{listener.Candidate.ListenerClientId}, &sidecar.ClientHint{
		Topic:   sidecar.PushTopicSock,
		Version: uint64(max(now.UnixMilli(), 0)),
		Kind:    uint32(protocol.MessageType_SOCKET_HINT),
		Body:    body,
	})
}

// Step 8 for one listener of an edge Find: its {svc_} pair for dialerClientId at position (C9, QD-656). nil
// when it stands, else the Find's refusal.
func (self *SocketsService) setPair(networkId connect.Id, position uint64, passed *socketTicketedListener, dialerClientId connect.Id, now time.Time) *socketRefusal {
	listenerClientId := passed.listener.Candidate.ListenerClientId
	grantExpireMillis := passed.grant.grantExpireMillis
	ttl := self.settings.Store.EdgePairTtl
	if grantExpireMillis != 0 {
		remaining := time.Duration(int64(grantExpireMillis)-now.UnixMilli()) * time.Millisecond
		if remaining <= 0 {
			// the verdict allowed a grant that has just run out: the next Find refuses it
			return socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.BehindRetryAfter)
		}
		ttl = min(ttl, remaining)
	}
	writeKey := socketPairWriteKey{
		listenId:          passed.listener.Candidate.ListenId,
		dialerClientId:    dialerClientId,
		grantExpireMillis: grantExpireMillis,
	}
	if self.pairWrites.recent(listenerClientId, writeKey, now) {
		return nil
	}
	wrote, floor, err := func() (bool, uint64, error) {
		ctx, done := self.storeContext()
		defer done()
		testHookBarrier("sockets.find.pair.before", "")
		defer testHookBarrier("sockets.find.pair.after", "")
		return self.store.SetServicePair(ctx, listenerClientId, dialerClientId, grantExpireMillis, ttl, position)
	}()
	switch {
	case err != nil:
		return socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.MaxRetryAfter)
	case !wrote:
		// a removal at a newer position left the floor: this process is behind
		self.gate.Observe(networkId, floor)
		return socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.BehindRetryAfter)
	}
	self.pairWrites.wrote(listenerClientId, writeKey, now)
	return nil
}

// What makes two pair writes of one listener the same write.
type socketPairWriteKey struct {
	listenId          connect.Id
	dialerClientId    connect.Id
	grantExpireMillis uint64
}

// The pairs this process wrote within PairWriteInterval, by listener, so a busy edge writes each about once a
// minute (DESIGN-DETAILS 13.2.3's find step 8). Writes older than the interval are dropped at most once an
// interval. Safe for concurrent use.
type socketPairWrites struct {
	interval time.Duration

	stateLock              sync.Mutex
	listenerClientIdWrites map[connect.Id]map[socketPairWriteKey]time.Time
	lastSweepTime          time.Time
}

func newSocketPairWrites(interval time.Duration) *socketPairWrites {
	return &socketPairWrites{interval: interval, listenerClientIdWrites: map[connect.Id]map[socketPairWriteKey]time.Time{}}
}

// Whether this process wrote key for listenerClientId within the interval before now.
func (self *socketPairWrites) recent(listenerClientId connect.Id, key socketPairWriteKey, now time.Time) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	writeTime, found := self.listenerClientIdWrites[listenerClientId][key]
	return found && now.Sub(writeTime) < self.interval
}

// Records a write at now.
func (self *socketPairWrites) wrote(listenerClientId connect.Id, key socketPairWriteKey, now time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.interval <= now.Sub(self.lastSweepTime) {
		self.lastSweepTime = now
		for otherListenerClientId, writes := range self.listenerClientIdWrites {
			for otherKey, writeTime := range writes {
				if self.interval <= now.Sub(writeTime) {
					delete(writes, otherKey)
				}
			}
			if len(writes) == 0 {
				delete(self.listenerClientIdWrites, otherListenerClientId)
			}
		}
	}
	writes := self.listenerClientIdWrites[listenerClientId]
	if writes == nil {
		writes = map[socketPairWriteKey]time.Time{}
		self.listenerClientIdWrites[listenerClientId] = writes
	}
	writes[key] = now
}

// Forgets listenerClientId's writes once its pairs are removed, so the next Find writes them again.
func (self *socketPairWrites) forgetListener(listenerClientId connect.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.listenerClientIdWrites, listenerClientId)
}
