// POST /socket/registrations (§9.5, D-SOCK-3, D-SOCK-13, D-SOCK-14, D-SOCK-15), built to DESIGN-DETAILS
// 13.2.3's registration path, which governs where it and §9.5 differ. One call is one page of the calling
// client's set: the whole set within [key_start, key_end), so an entry the page lacks there unlistens at once.
//
//  1. authenticate: the caller's client, network and sidecar_id; none outside urnetwork-edge is denied, and
//     a removed client answers 401 (request.go); §19.11's sockets gate for the caller's network
//  2. one token of the caller's bucket, then a turn in the fair queue: unavailable with retry_after_ms. The body
//     is read between the two, so a slow upload holds no running call's place
//  3. the page's shape, whole, before anything is judged: at most 1,024 entries, sorted by name key, each
//     inside the range, each field within §9.5's sizes. A page that fails is invalid and writes nothing
//  4. the network's view S, taken once for the page: unloaded or behind answers unavailable
//  5. per entry, in memory: the entry's own values (invalid, and never passed to the store); the namespace,
//     plaintext only for tls/, smtp/ and ur/; the kill set; MayListen for the caller's subject; the claim
//     under the caller's sidecar's identity key in S, verified once per (client, claim bytes, key) and then
//     remembered; the namespace's ValidateListen, where an undecided one makes the page unavailable. Every
//     refusal is the same refusal, so the checks run cheapest first and the signature check after the gate's,
//     which changes no verdict; ValidateListen stays last, so a refused entry never makes a page unavailable
//  6. one ApplyPage: the allowed entries with defaults applied, S's position, the page's set_version, the
//     caller's sidecar_id, and the refused entries' name keys, whose leases end for cause at S's position
//  7. each entry's status from what the store did: ok, taken, revoked (refused, and its lease ended now) or
//     denied (refused, none ended). A put of an older page is stale, and the page answers §9.5's older-set
//     refusal. A put a newer removal fenced makes the page unavailable for FencedRetryAfter, its other
//     entries applied; a fence for cause, a lease a fresher process admitted above S and a removal the store
//     kept for a newer admission are each evidence handed to the gate (Observe), and the entry's own status
//     stands
//  8. FirstListen and LastUnlisten for the transitions the store reported, on edge names alone
//  9. pairs (QD-656): an accepted tls/ or smtp/ entry renews the client's pairs, at most once an
//     EdgePairTouchInterval in this process; a call after which the client's set holds no tls/ or smtp/ name,
//     having removed one, removes its pairs at S's position, leaving a floor
//  10. the answer: statuses, the stored set_version, server_time, ticket keys, the urnetwork-edge network,
//     and whether §20 has stopped the network's new streams
//
// Every verdict is the gate's, on the state it verified (X3); the store's positions only refuse writes. No
// SocketHint is sent: the caller holds its answer. Nothing here logs a name (I-13). Safe for concurrent use.

package socketsservice

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/http"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §9.5's protocol and app mode names, which a page's allowed entries reach the store with. The sizes a page's
// shape is held to, and the default weight and max_streams, are SocketsSettings.Format's (QD-702).
const (
	socketDefaultProtocol     = "tcp"
	socketDefaultTlsProtocol  = "tls"
	socketDefaultSmtpProtocol = "smtp-starttls"
	socketDefaultTlsAppMode   = "http"
	socketRawTlsAppMode       = "raw"
)

// How one entry of a page stands while the page is judged.
type socketEntryVerdict int

const (
	// The entry is malformed: invalid, and the store never sees it.
	socketEntryInvalid socketEntryVerdict = iota + 1
	// A check refused it: its name key goes to the store as refused.
	socketEntryRefused
	// Every check passed: it goes to the store as a put.
	socketEntryAllowed
)

// One entry of a page as the page is judged.
type socketPageEntry struct {
	registration *sidecar.SocketRegistration
	name         *socketParsedName
	verdict      socketEntryVerdict
	// The registration with §9.5's defaults applied, for an allowed entry.
	stored *sidecar.SocketRegistration
	status sidecar.SocketRegistrationStatus
}

// Handles POST /socket/registrations.
func (self *SocketsService) serveRegistrations(w http.ResponseWriter, r *http.Request) {
	result, refusal := self.registrations(r)
	switch {
	case refusal != nil && refusal.status != http.StatusOK:
		if refusal.status == http.StatusServiceUnavailable {
			self.countRegistrationCall(socketRegistrationResultUnavailable)
		} else {
			self.countRegistrationCall(socketRegistrationResultUnauthorized)
		}
		writeSocketStatus(w, refusal)
		return
	case refusal != nil:
		if result == nil {
			result = self.registrationAnswer(nil)
		}
		result.Statuses = nil
		result.Error = refusal.socketError()
		self.countRegistrationCall(socketRegistrationResultOf(refusal.code))
	default:
		self.countRegistrationCall(socketRegistrationResultOk)
	}
	writeSocketJson(w, result)
}

// Counts one answered call.
func (self *SocketsService) countRegistrationCall(result string) {
	self.metrics.registrationCallCount.Add(1, result)
}

// registration_calls_total's result for a refusal's code.
func socketRegistrationResultOf(code sidecar.SocketErrorCode) string {
	switch code {
	case sidecar.SocketErrorCodeStale:
		return socketRegistrationResultStale
	case sidecar.SocketErrorCodeInvalid:
		return socketRegistrationResultInvalid
	case sidecar.SocketErrorCodeDenied:
		return socketRegistrationResultDenied
	}
	return socketRegistrationResultUnavailable
}

// The answer's fixed part (step 10), for networkId's caller, nil before one is known.
func (self *SocketsService) registrationAnswer(networkId *connect.Id) *sidecar.SocketRegistrationsResult {
	result := &sidecar.SocketRegistrationsResult{
		ServerTimeMillis: uint64(max(self.clock.Now().UnixMilli(), 0)),
		TicketKeys:       []*sidecar.SocketTicketKey{},
	}
	if ticketKeys, _ := self.currentTicketKeys(); ticketKeys != nil {
		result.TicketKeys = ticketKeys.VerifyKeys()
	}
	if edgeNetworkId, set := self.host.GatesOrClosed().UrnetworkEdge(); set {
		result.UrnetworkEdge = &edgeNetworkId
	}
	if networkId != nil && self.gate != nil {
		result.StreamsStopped = self.gate.Spent(*networkId)
	}
	return result
}

// Steps 1 to 10. A refusal of the whole call comes back as refusal, with result's fixed part when one is
// known.
func (self *SocketsService) registrations(r *http.Request) (*sidecar.SocketRegistrationsResult, *socketRefusal) {
	// 1
	caller, refusal := self.authenticate(r)
	if refusal != nil {
		return nil, refusal
	}
	networkId := caller.principal.NetworkId
	if refusal := self.gateRefusal(networkId); refusal != nil {
		return nil, refusal
	}
	answer := self.registrationAnswer(&networkId)

	// 2, the body read between the token and the turn, so a slow upload holds no running call's place
	if refusal := self.chargeRefusal(caller); refusal != nil {
		return answer, refusal
	}
	args := &sidecar.SocketRegistrationsArgs{}
	readErr := readSocketJson(r, int64(self.settings.RegistrationsMaxBodyByteCount), args)
	release, refusal := self.queueTurn(r.Context(), networkId)
	if refusal != nil {
		return answer, refusal
	}
	defer release()

	// 3
	if readErr != nil || !socketPageFormed(args, self.settings.Format) {
		return answer, socketRefusalOf(sidecar.SocketErrorCodeInvalid, 0)
	}

	// 4
	if self.store == nil || self.gate == nil {
		return answer, socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.BehindRetryAfter)
	}
	testHookBarrier("sockets.registrations.view.before", "")
	view, err := self.gate.View(networkId)
	if err != nil {
		return answer, socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.BehindRetryAfter)
	}
	position := view.Position()
	testHookBarrier("sockets.registrations.view.after", "")

	// 5
	now := self.clock.Now()
	entries := make([]*socketPageEntry, len(args.Registrations))
	for index, registration := range args.Registrations {
		entry := self.judgeEntry(r, caller, view, networkId, registration, now)
		if entry == nil {
			// a namespace that cannot decide yet: the client retries and keeps what it held
			return answer, socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.MaxRetryAfter)
		}
		entries[index] = entry
	}

	// 6
	page := &SocketStorePage{
		NetworkId:        networkId,
		ListenerClientId: caller.principal.ClientId,
		SetVersion:       args.SetVersion,
		PolicyVersion:    position,
		SidecarId:        caller.principal.SidecarId,
		KeyStart:         args.KeyStart,
		KeyEnd:           args.KeyEnd,
		Registrations:    []*sidecar.SocketRegistration{},
		RefusedNameKeys:  [][]byte{},
	}
	allowedEntries := []*socketPageEntry{}
	refusedEntries := []*socketPageEntry{}
	for _, entry := range entries {
		switch entry.verdict {
		case socketEntryAllowed:
			page.Registrations = append(page.Registrations, entry.stored)
			allowedEntries = append(allowedEntries, entry)
		case socketEntryRefused:
			page.RefusedNameKeys = append(page.RefusedNameKeys, entry.name.nameKey())
			refusedEntries = append(refusedEntries, entry)
		default:
			entry.status = sidecar.SocketRegistrationStatusInvalid
		}
	}
	result, err := func() (*SocketStorePageResult, error) {
		ctx, done := self.storeContext()
		defer done()
		testHookBarrier("sockets.registrations.apply.before", "")
		defer testHookBarrier("sockets.registrations.apply.after", "")
		return self.store.ApplyPage(ctx, page)
	}()
	switch {
	case errors.Is(err, ErrSocketStoreRequest):
		// the page passed step 3, so this is the engine's bug, and the same page would fail again
		return answer, socketRefusalOf(sidecar.SocketErrorCodeInvalid, 0)
	case err != nil:
		// the store did not answer, so what it did is unknown: the next page heals it (§9.5)
		return answer, socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.MaxRetryAfter)
	}
	answer.SetVersion = result.SetVersion
	if result.Stale && len(result.Outcomes) == 0 {
		// refused as the call began: nothing was written
		return answer, socketRefusalOf(sidecar.SocketErrorCodeStale, 0)
	}
	if len(result.Outcomes) != len(allowedEntries) || len(result.RefusedOutcomes) != len(refusedEntries) {
		return answer, socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.MaxRetryAfter)
	}

	// 7
	stale := result.Stale
	fenced := false
	for index, outcome := range result.Outcomes {
		entry := allowedEntries[index]
		switch {
		case outcome.Fenced:
			fenced = true
			if outcome.FenceCause == SocketRemoveRefused {
				self.gate.Observe(networkId, outcome.FencePolicyVersion)
			}
		case outcome.Stale:
			stale = true
		case outcome.Taken:
			entry.status = sidecar.SocketRegistrationStatusTaken
		default:
			entry.status = sidecar.SocketRegistrationStatusOk
			if position < outcome.PriorPolicyVersion {
				self.gate.Observe(networkId, outcome.PriorPolicyVersion)
			}
		}
	}
	for index, removal := range result.RefusedOutcomes {
		entry := refusedEntries[index]
		switch {
		case removal.Removed != nil:
			entry.status = sidecar.SocketRegistrationStatusRevoked
		case removal.Kept:
			entry.status = sidecar.SocketRegistrationStatusDenied
			if position < removal.PolicyVersion {
				self.gate.Observe(networkId, removal.PolicyVersion)
			}
		default:
			entry.status = sidecar.SocketRegistrationStatusDenied
		}
	}

	// 8 and 9 follow what the store did, whatever the page answers
	self.notifyTransitions(networkId, allowedEntries, result)
	self.keepPairs(caller.principal.ClientId, position, allowedEntries, result, now)
	self.countLeases(caller.principal.ClientId, args.KeyStart, allowedEntries, now)

	// 10
	switch {
	case stale:
		return answer, socketRefusalOf(sidecar.SocketErrorCodeStale, 0)
	case fenced:
		return answer, socketRefusalOf(sidecar.SocketErrorCodeUnavailable, self.settings.FencedRetryAfter)
	}
	answer.Statuses = make([]sidecar.SocketRegistrationStatus, len(entries))
	for index, entry := range entries {
		answer.Statuses[index] = entry.status
	}
	return answer, nil
}

// Step 3: the page's shape and every field's size, before anything is judged, each size format's.
func socketPageFormed(args *sidecar.SocketRegistrationsArgs, format *sidecar.SocketFormatSettings) bool {
	if sidecar.SocketRegistrationPageMaxEntryCount < len(args.Registrations) ||
		socketNameKeyMaxByteCount < len(args.KeyStart) || socketNameKeyMaxByteCount < len(args.KeyEnd) {
		return false
	}
	if 0 < len(args.KeyEnd) && bytes.Compare(args.KeyStart, args.KeyEnd) >= 0 {
		return false
	}
	var previousNameKey []byte
	for index, registration := range args.Registrations {
		if registration == nil || registration.ListenId == nil {
			return false
		}
		if (registration.Name == "") == (len(registration.NameToken) == 0) {
			// a registration naming both or neither has no key (socket_api.go)
			return false
		}
		if registration.Name != "" {
			if socketNameMaxByteCount < len(registration.Name) || len(registration.SealedName) != 0 {
				return false
			}
		} else if !socketTokenPathFormed(registration.NameToken) || len(registration.SealedName) != socketSealedNameByteCount {
			return false
		}
		if format.ClaimMaxByteCount < len(registration.Claim) || format.ProtocolMaxByteCount < len(registration.Protocol) ||
			format.AlpnMaxCount < len(registration.Alpn) || format.AppModeMaxByteCount < len(registration.AppMode) {
			return false
		}
		for _, alpn := range registration.Alpn {
			if alpn == "" || format.AlpnMaxByteCount < len(alpn) {
				return false
			}
		}
		nameKey := registration.NameKey()
		if bytes.Compare(nameKey, args.KeyStart) < 0 || (0 < len(args.KeyEnd) && bytes.Compare(nameKey, args.KeyEnd) >= 0) {
			return false
		}
		if 0 < index && bytes.Compare(nameKey, previousNameKey) <= 0 {
			return false
		}
		previousNameKey = nameKey
	}
	return true
}

// Step 5 for one entry. nil when the namespace cannot decide, which makes the page unavailable.
func (self *SocketsService) judgeEntry(
	r *http.Request,
	caller *socketCaller,
	view SocketGateView,
	networkId connect.Id,
	registration *sidecar.SocketRegistration,
	now time.Time,
) *socketPageEntry {
	entry := &socketPageEntry{registration: registration, verdict: socketEntryInvalid}
	name, ok := parseSocketRequestName(registration.Name, registration.NameToken)
	if !ok {
		// a name in the clear that is not an edge name's, or not canonical (D-SOCK-13)
		return entry
	}
	entry.name = name
	stored, ok := socketStoredRegistration(registration, name, self.settings.Format)
	if !ok {
		return entry
	}
	entry.stored = stored
	entry.verdict = socketEntryRefused

	if self.killSet.kills(networkId, name, now) {
		return entry
	}
	listen := view.MayListen(caller.gateRequest(networkId, name), now)
	if listen == nil || !listen.Allowed {
		return entry
	}
	// ur/ listeners are platform clients, which hold no identity key; their namespace's owner authorizes them
	// (§9.4, SOCK-M9-01)
	if name.namespace != sidecar.SocketNamespacePlatform && !self.claimHolds(caller, view, networkId, registration, name) {
		return entry
	}
	switch name.namespace {
	case sidecar.SocketNamespaceTls, sidecar.SocketNamespaceSmtp, sidecar.SocketNamespacePlatform:
		hooks, registered := self.namespaces.lookup(name.namespace)
		if !registered {
			// an edge namespace nobody registered refuses every entry (§9.4)
			return entry
		}
		err := hooks.ValidateListen(r.Context(), &SocketListenCheck{
			NetworkId:        networkId,
			ListenerClientId: caller.principal.ClientId,
			SidecarId:        caller.principal.SidecarId,
			Name:             name.name,
			Namespace:        name.namespace,
			Registration:     stored,
			Listen:           listen,
		})
		switch {
		case errors.Is(err, ErrSocketListenRefused):
			return entry
		case err != nil:
			return nil
		}
	}
	entry.verdict = socketEntryAllowed
	return entry
}

// registration with §9.5's defaults applied, or false when one of its values is out of §9.5's bounds: a
// negative version, in-flight count or max_streams, a weight past format's most, an app_mode or ALPN ids on a
// name that takes none, or the zero listen id.
func socketStoredRegistration(registration *sidecar.SocketRegistration, name *socketParsedName, format *sidecar.SocketFormatSettings) (*sidecar.SocketRegistration, bool) {
	if registration.Version < 0 || registration.Inflight < 0 || registration.MaxStreams < 0 ||
		registration.Weight < 0 || format.MaxWeight < registration.Weight || *registration.ListenId == (connect.Id{}) {
		return nil, false
	}
	stored := *registration
	stored.Alpn = append([]string(nil), registration.Alpn...)
	listenId := *registration.ListenId
	stored.ListenId = &listenId
	if name.namespace == sidecar.SocketNamespaceTls {
		switch stored.AppMode {
		case "":
			stored.AppMode = socketDefaultTlsAppMode
		case socketDefaultTlsAppMode, socketRawTlsAppMode:
		default:
			return nil, false
		}
	} else if stored.AppMode != "" || 0 < len(stored.Alpn) {
		return nil, false
	}
	if stored.Protocol == "" {
		switch name.namespace {
		case sidecar.SocketNamespaceTls:
			stored.Protocol = socketDefaultTlsProtocol
		case sidecar.SocketNamespaceSmtp:
			stored.Protocol = socketDefaultSmtpProtocol
		default:
			stored.Protocol = socketDefaultProtocol
		}
	}
	if stored.Weight == 0 {
		stored.Weight = format.DefaultWeight
	}
	if stored.MaxStreams == 0 {
		stored.MaxStreams = format.DefaultMaxStreams
	}
	return &stored, true
}

// Whether the entry's claim is the caller's sidecar's, under its identity key in view, over exactly what the
// entry registers (§9.5): network, name or token path, listen id, protocol and app_mode as the page sent them.
// A claim this process has seen pass for the same client, bytes, key and entry passes from memory.
func (self *SocketsService) claimHolds(
	caller *socketCaller,
	view SocketGateView,
	networkId connect.Id,
	registration *sidecar.SocketRegistration,
	name *socketParsedName,
) bool {
	if caller.principal.SidecarId == nil || len(registration.Claim) == 0 {
		return false
	}
	publicKey, found := view.IdentityKey(*caller.principal.SidecarId)
	if !found || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	memoKey := socketClaimMemoKey(caller.principal.ClientId, publicKey, networkId, registration, name)
	if self.claimMemo.holds(memoKey) {
		return true
	}
	self.claimVerifyCount.Add(1)
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(registration.Claim, signed); err != nil {
		return false
	}
	err := bridge.VerifySigned(signed, sidecar.SocketRegistrationPurpose, bridge.SignedType_SIGNED_SOCKET_REGISTRATION, bridge.SignedKeyAlgEd25519, publicKey)
	if err != nil {
		return false
	}
	claim := &protocol.SocketRegistrationClaim{}
	if err := proto.Unmarshal(signed.GetBody(), claim); err != nil {
		return false
	}
	switch {
	case !bytes.Equal(claim.GetNetworkId(), networkId.Bytes()),
		!bytes.Equal(claim.GetListenId(), registration.ListenId.Bytes()),
		claim.GetProtocol() != registration.Protocol,
		claim.GetAppMode() != registration.AppMode:
		return false
	case name.name != "":
		if claim.GetName() != name.name || len(claim.GetNameToken()) != 0 {
			return false
		}
	default:
		if claim.GetName() != "" || !bytes.Equal(claim.GetNameToken(), name.nameToken) {
			return false
		}
	}
	self.claimMemo.add(memoKey)
	return true
}

// What the memo keys a passed claim by: the client, the key, the claim's bytes and every value it was matched
// against, each length-prefixed, so no two differ only in where one ends.
func socketClaimMemoKey(clientId connect.Id, publicKey []byte, networkId connect.Id, registration *sidecar.SocketRegistration, name *socketParsedName) [sha256.Size]byte {
	hash := sha256.New()
	write := func(value []byte) {
		hash.Write(binary.BigEndian.AppendUint32(nil, uint32(len(value))))
		hash.Write(value)
	}
	write([]byte("urnetwork-sidecar-v1/socket-claim-memo"))
	write(clientId.Bytes())
	write(publicKey)
	write(registration.Claim)
	write(networkId.Bytes())
	write([]byte(name.name))
	write(name.nameToken)
	write(registration.ListenId.Bytes())
	write([]byte(registration.Protocol))
	write([]byte(registration.AppMode))
	var key [sha256.Size]byte
	hash.Sum(key[:0])
	return key
}

// The claims this process has seen pass, in two generations: a lookup reads both and keeps what it finds in the
// newer, and the newer becomes the older once it holds half of count, so the memo holds at most count keys and
// keeps what heartbeats use. Safe for concurrent use.
type socketClaimMemo struct {
	generationCount int

	stateLock sync.Mutex
	current   map[[sha256.Size]byte]struct{}
	previous  map[[sha256.Size]byte]struct{}
}

// A memo of at most count keys.
func newSocketClaimMemo(count int) *socketClaimMemo {
	return &socketClaimMemo{
		generationCount: max(count/2, 1),
		current:         map[[sha256.Size]byte]struct{}{},
		previous:        map[[sha256.Size]byte]struct{}{},
	}
}

// Whether key passed before.
func (self *socketClaimMemo) holds(key [sha256.Size]byte) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, found := self.current[key]; found {
		return true
	}
	if _, found := self.previous[key]; found {
		self.addWithLock(key)
		return true
	}
	return false
}

// Remembers that key passed.
func (self *socketClaimMemo) add(key [sha256.Size]byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.addWithLock(key)
}

func (self *socketClaimMemo) addWithLock(key [sha256.Size]byte) {
	if self.generationCount <= len(self.current) {
		self.previous = self.current
		self.current = map[[sha256.Size]byte]struct{}{}
	}
	self.current[key] = struct{}{}
}

// Step 8: FirstListen for each allowed edge entry that took a group's first lease, LastUnlisten for each edge
// name whose last lease the call ended. A token path takes no hook. Hooks only note the change.
func (self *SocketsService) notifyTransitions(networkId connect.Id, allowedEntries []*socketPageEntry, result *SocketStorePageResult) {
	for index, outcome := range result.Outcomes {
		entry := allowedEntries[index]
		if !outcome.FirstListener || outcome.Fenced || outcome.Stale || outcome.Taken || entry.name.name == "" {
			continue
		}
		if hooks, registered := self.namespaces.lookup(entry.name.namespace); registered {
			hooks.FirstListen(networkId, entry.name.name)
		}
	}
	for _, removed := range result.Removed {
		if !removed.LastListener {
			continue
		}
		name := parseSocketNameKey(removed.NameKey)
		if name.name == "" {
			continue
		}
		if hooks, registered := self.namespaces.lookup(name.namespace); registered {
			hooks.LastUnlisten(removed.NetworkId, name.name)
		}
	}
}

// Step 9: the client's {svc_} pairs follow its edge registrations (QD-656). A failed pair call leaves the
// pairs to EdgePairTtl, which ends them within 15 minutes whatever happens here.
func (self *SocketsService) keepPairs(clientId connect.Id, position uint64, allowedEntries []*socketPageEntry, result *SocketStorePageResult, now time.Time) {
	edgeAccepted := false
	for index, outcome := range result.Outcomes {
		if allowedEntries[index].status == sidecar.SocketRegistrationStatusOk && allowedEntries[index].name.pairName() &&
			!outcome.Fenced && !outcome.Stale && !outcome.Taken {
			edgeAccepted = true
		}
	}
	edgeRemoved := false
	for _, removed := range result.Removed {
		if SocketPairNameKey(removed.NameKey) {
			edgeRemoved = true
		}
	}
	if edgeRemoved && !result.EdgeEntriesRemain {
		self.removePairs(clientId, position)
		return
	}
	if edgeAccepted && self.pairTouches.due(clientId, now) {
		err := func() error {
			ctx, done := self.storeContext()
			defer done()
			return self.store.TouchServicePairs(ctx, clientId)
		}()
		if err == nil {
			self.pairTouches.touched(clientId, now)
		}
	}
}

// When this process last renewed each client's pairs, so it renews them at most once an interval. Entries
// older than the interval are dropped at most once an interval, so the map holds the clients of about the
// last two. Safe for concurrent use.
type socketPairTouches struct {
	interval time.Duration

	stateLock          sync.Mutex
	clientIdTouchTimes map[connect.Id]time.Time
	lastSweepTime      time.Time
}

func newSocketPairTouches(interval time.Duration) *socketPairTouches {
	return &socketPairTouches{interval: interval, clientIdTouchTimes: map[connect.Id]time.Time{}}
}

// Whether clientId's pairs are due a renewal at now.
func (self *socketPairTouches) due(clientId connect.Id, now time.Time) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	touchTime, found := self.clientIdTouchTimes[clientId]
	return !found || self.interval <= now.Sub(touchTime)
}

// Records a renewal at now.
func (self *socketPairTouches) touched(clientId connect.Id, now time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.interval <= now.Sub(self.lastSweepTime) {
		self.lastSweepTime = now
		for otherClientId, touchTime := range self.clientIdTouchTimes {
			if self.interval <= now.Sub(touchTime) {
				delete(self.clientIdTouchTimes, otherClientId)
			}
		}
	}
	self.clientIdTouchTimes[clientId] = now
}

// Forgets clientId's renewal, once its pairs are gone.
func (self *socketPairTouches) forget(clientId connect.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.clientIdTouchTimes, clientId)
}

// One page's range of one client, which the registrations gauge counts leases by.
type socketPageRangeKey struct {
	clientId connect.Id
	keyStart string
}

// One range's leases as its newest page left them, and when that count lapses with the leases.
type socketPageLeaseCount struct {
	count      int
	expireTime time.Time
}

// §9.10's registrations gauge: the leases this process's newest page of each client range wrote, while those
// leases can still live. Safe for concurrent use.
type socketLeaseCounter struct {
	lease time.Duration
	gauge sidecar.MetricsGauge

	stateLock     sync.Mutex
	rangeCounts   map[socketPageRangeKey]*socketPageLeaseCount
	total         int
	lastSweepTime time.Time
}

func newSocketLeaseCounter(lease time.Duration, gauge sidecar.MetricsGauge) *socketLeaseCounter {
	return &socketLeaseCounter{lease: lease, gauge: gauge, rangeCounts: map[socketPageRangeKey]*socketPageLeaseCount{}}
}

// Records that clientId's page from keyStart wrote count leases at now, and sets the gauge, outside the lock: two
// pages racing may leave it a page behind until the next.
func (self *socketLeaseCounter) record(clientId connect.Id, keyStart []byte, count int, now time.Time) {
	total := func() int {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.lease <= now.Sub(self.lastSweepTime) {
			self.lastSweepTime = now
			for key, rangeCount := range self.rangeCounts {
				if !now.Before(rangeCount.expireTime) {
					self.total -= rangeCount.count
					delete(self.rangeCounts, key)
				}
			}
		}
		key := socketPageRangeKey{clientId: clientId, keyStart: string(keyStart)}
		if previous := self.rangeCounts[key]; previous != nil {
			self.total -= previous.count
		}
		if count == 0 {
			delete(self.rangeCounts, key)
		} else {
			self.rangeCounts[key] = &socketPageLeaseCount{count: count, expireTime: now.Add(self.lease)}
			self.total += count
		}
		return self.total
	}()
	self.gauge.Set(float64(total))
}

// Counts the page's written leases into the gauge.
func (self *SocketsService) countLeases(clientId connect.Id, keyStart []byte, allowedEntries []*socketPageEntry, now time.Time) {
	count := 0
	for _, entry := range allowedEntries {
		if entry.status == sidecar.SocketRegistrationStatusOk {
			count += 1
		}
	}
	self.leaseCounter.record(clientId, keyStart, count, now)
}
