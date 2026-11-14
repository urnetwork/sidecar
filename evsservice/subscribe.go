// POST|GET|DELETE /evs/v1/subscriptions (§11.10's lease, renew and caps rows; EVS1-M2-15): a client's leases on a
// repo's prefixes, which step 8 matches each commit against (hint.go).
//
//	lease  POST {repo_id, ref or *, path epoch, <= 16 token prefixes} (r on the repo) writes one lease per prefix
//	       into {evsl_<repo_id>} and raises {evsl_<repo_id>}v in the same script, then answers 200; an empty prefix,
//	       or none, is the whole ref; a lease expires 7 d after its last write, which a renewal repeats
//	delete DELETE with the same body removes the caller's leases it names, or with no prefix every lease of the
//	       caller's on that repo and ref, raising {evsl_<repo_id>}v the same way
//	list   GET ?repo_id= answers the caller's live leases on the repo
//	caps   the lease script counts the repo's distinct holders and refuses a new one at evs_subscribers_per_repo, or
//	       in the team directory at the network's config_admissions (§20.4, plan-EVS1-subscription-caps#1), with
//	       §20.7's QuotaRefusal naming the key; a limit this build does not know reads 0 and refuses
//	repos  before the lease script, a script on {evsc_<client_id>} counts the repos the client follows and refuses a
//	       new one at evs_repos_per_client (plan-EVS1-subscription-caps#2, QD-263, QD-749), with the same refusal
//	       naming that key; a renewal moves the repo's score and counts nothing twice, and a DELETE that leaves the
//	       client no live lease on the repo removes it
//	refuse each of the three, once its repo is authorized, takes §11.12's refused row as the guard gives a placed
//	       route (QD-665): the repo's place, then repo/ from the 5 s repo cache, a deleted repo answering 409
//	       REPO_DELETED and a shredding or shredded one 409 SHREDDING, a repo never placed 404
//	sweep  SweepLeases drops a repo's expired leases, for taskworker's daily sweep
//
// The fields of {evsl_<repo_id>}, holder|ref|epoch|prefix -> expiry ms in decimal: holder is the token's client and
// sidecar, <client>.<sidecar> in 32 lowercase hex each, the client to hint and the sidecar to check against the
// projection (evs-8: "per client"); ref is 32 lowercase hex, or * for every ref; epoch decimal; prefix the token
// path's 26-character tokens joined by /, empty for the whole ref. No field holds a name (I-13).
//
// {evsc_<client_id>} is a sorted set of the client's repo ids, 32 lowercase hex each, scored by the ms of its last
// subscribe or renewal on that repo. Its script drops the members whose score is a lease's life old, so a repo the
// client stopped renewing leaves the count when its leases lapse, and the key lives as long as {evsl_}'s. The two
// scripts are two calls, each on one hash tag (§11.10's slots row), so they are not one step: a lease the per-repo
// cap then refuses has its repo taken out again, and a DELETE racing the same client's POST on the same repo can
// leave a lease whose repo the set lacks until its next renewal, which counts low, never high.
//
// Every family here is soft state outside the rdb bundles (owner decision 136): a loss is a gap, which holders'
// hourly resync re-creates. A lost {evsc_} fails open, and renewals rebuild it within a day.

package evsservice

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §20.4's sidecar_abuse keys the caps read (plan-EVS1-subscription-caps#1).
const (
	evsSubscribersPerRepoLimitKey  = "evs_subscribers_per_repo"
	evsDirectoryAdmissionsLimitKey = "config_admissions"
	evsReposPerClientLimitKey      = "evs_repos_per_client"
)

// The route templates.
const (
	evsSubscriptionsPostTemplate   = "POST /evs/v1/subscriptions"
	evsSubscriptionsGetTemplate    = "GET /evs/v1/subscriptions"
	evsSubscriptionsDeleteTemplate = "DELETE /evs/v1/subscriptions"
)

// A ref field's value for every ref.
const evsLeaseEveryRef = "*"

// The family's hash tag prefix.
const leaseKeyPrefix = "{evsl_"

// A repo's leases: {evsl_<repo_id>}.
func LeaseKey(repoId sidecar.Id) string {
	return leaseKeyPrefix + sidecar.EvsKeyId(repoId) + "}"
}

// A repo's lease version: {evsl_<repo_id>}v, raised by every lease write.
func LeaseVersionKey(repoId sidecar.Id) string {
	return LeaseKey(repoId) + "v"
}

// The client repo family's hash tag prefix.
const clientRepoKeyPrefix = "{evsc_"

// The repos a client follows: {evsc_<client_id>}.
func ClientRepoKey(clientId sidecar.Id) string {
	return clientRepoKeyPrefix + sidecar.EvsKeyId(clientId) + "}"
}

// ClientRepoPutScript's replies.
const (
	evsClientRepoRefused = 0
	evsClientRepoAdded   = 1
	evsClientRepoRenewed = 2
)

// Counts a repo against its client, refusing a new one at the cap. KEYS[1] the client's repos; ARGV[1] now in ms,
// ARGV[2] the repo, ARGV[3] the cap, ARGV[4] the newest score that has lapsed, now less a lease's life, in ms,
// ARGV[5] the key's ttl in ms. 0 past the cap, 1 when the repo is new to the set, 2 when it was there and its score
// moved. The scores are ms since the epoch, exact in a double, and ZADD takes ARGV[1]'s own digits.
var ClientRepoPutScript = &sidecar.RedisScript{
	Name: "evs_client_repo_put",
	Source: `
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[4])
local held = redis.call('ZSCORE', KEYS[1], ARGV[2])
if not held and redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) then
  return 0
end
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[5])
if held then
  return 2
end
return 1
`,
}

// Takes a repo out of its client's count. KEYS[1] the client's repos; ARGV[1] the repo. Replies with how many went.
var ClientRepoRemoveScript = &sidecar.RedisScript{
	Name: "evs_client_repo_remove",
	Source: `
return redis.call('ZREM', KEYS[1], ARGV[1])
`,
}

// Writes leases, refusing a new holder at the cap. KEYS[1] the leases, KEYS[2] their version; ARGV[1] now in ms,
// ARGV[2] the holder, ARGV[3] the cap, ARGV[4] the keys' ttl in ms, then field and expiry pairs. 1 when written, 0
// past the cap. now and the expiries are ms since the epoch, exact in a double.
var LeasePutScript = &sidecar.RedisScript{
	Name: "evs_lease_put",
	Source: `
local now = tonumber(ARGV[1])
local holder = ARGV[2]
local fields = redis.call('HGETALL', KEYS[1])
local holders = {}
local count = 0
for i = 1, #fields, 2 do
  local fieldHolder = string.match(fields[i], '^([^|]*)|')
  if fieldHolder and tonumber(fields[i + 1]) > now and not holders[fieldHolder] then
    holders[fieldHolder] = true
    count = count + 1
  end
end
if not holders[holder] and count >= tonumber(ARGV[3]) then
  return 0
end
for i = 5, #ARGV, 2 do
  redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1])
end
redis.call('PEXPIRE', KEYS[1], ARGV[4])
redis.call('INCR', KEYS[2])
redis.call('PEXPIRE', KEYS[2], ARGV[4])
return 1
`,
}

// Removes leases. KEYS as LeasePutScript's; ARGV[1] "exact" or "prefix", then the fields, or the field prefixes
// whose every field goes. Replies with how many went.
var LeaseDeleteScript = &sidecar.RedisScript{
	Name: "evs_lease_delete",
	Source: `
local removed = 0
if ARGV[1] == 'prefix' then
  local names = redis.call('HKEYS', KEYS[1])
  for _, name in ipairs(names) do
    for i = 2, #ARGV do
      if string.sub(name, 1, string.len(ARGV[i])) == ARGV[i] then
        removed = removed + redis.call('HDEL', KEYS[1], name)
        break
      end
    end
  end
else
  for i = 2, #ARGV do
    removed = removed + redis.call('HDEL', KEYS[1], ARGV[i])
  end
end
if removed > 0 then
  redis.call('INCR', KEYS[2])
end
return removed
`,
}

// Drops leases whose expiry has passed. KEYS as LeasePutScript's; ARGV[1] now in ms. Replies with how many went.
var LeaseSweepScript = &sidecar.RedisScript{
	Name: "evs_lease_sweep",
	Source: `
local now = tonumber(ARGV[1])
local fields = redis.call('HGETALL', KEYS[1])
local removed = 0
for i = 1, #fields, 2 do
  if tonumber(fields[i + 1]) <= now then
    removed = removed + redis.call('HDEL', KEYS[1], fields[i])
  end
end
if removed > 0 then
  redis.call('INCR', KEYS[2])
end
return removed
`,
}

// One lease as the hash holds it.
type EvsLease struct {
	ClientId  sidecar.Id
	SidecarId sidecar.Id
	// The zero id for every ref.
	RefId     sidecar.Id
	EveryRef  bool
	PathEpoch uint64
	// Empty for the whole ref.
	Prefix    sidecar.EvsTokenPath
	ExpiresAt time.Time
}

// A holder's field prefix: <client>.<sidecar>|.
func evsLeaseHolder(clientId sidecar.Id, sidecarId sidecar.Id) string {
	return sidecar.EvsKeyId(clientId) + "." + sidecar.EvsKeyId(sidecarId)
}

// The lease's field.
func (self *EvsLease) field() string {
	ref := evsLeaseEveryRef
	if !self.EveryRef {
		ref = sidecar.EvsKeyId(self.RefId)
	}
	prefix := ""
	if 0 < len(self.Prefix) {
		prefix = self.Prefix.KeyString()
	}
	return evsLeaseHolder(self.ClientId, self.SidecarId) + "|" + ref + "|" + strconv.FormatUint(self.PathEpoch, 10) + "|" + prefix
}

// A lease from its field and value, false for one that does not parse, which matching skips.
func parseEvsLease(field string, value []byte) (*EvsLease, bool) {
	parts := strings.Split(field, "|")
	if len(parts) != 4 {
		return nil, false
	}
	holder := strings.Split(parts[0], ".")
	if len(holder) != 2 {
		return nil, false
	}
	clientId, err := parseEvsHexId(holder[0])
	if err != nil {
		return nil, false
	}
	sidecarId, err := parseEvsHexId(holder[1])
	if err != nil {
		return nil, false
	}
	lease := &EvsLease{ClientId: clientId, SidecarId: sidecarId}
	if parts[1] == evsLeaseEveryRef {
		lease.EveryRef = true
	} else if lease.RefId, err = parseEvsHexId(parts[1]); err != nil {
		return nil, false
	}
	if lease.PathEpoch, err = strconv.ParseUint(parts[2], 10, 64); err != nil {
		return nil, false
	}
	if parts[3] != "" {
		for _, component := range strings.Split(parts[3], "/") {
			token, err := sidecar.ParseEvsToken(component)
			if err != nil {
				return nil, false
			}
			lease.Prefix = append(lease.Prefix, token)
		}
	}
	expiresMs, err := strconv.ParseInt(string(value), 10, 64)
	if err != nil {
		return nil, false
	}
	lease.ExpiresAt = time.UnixMilli(expiresMs)
	return lease, true
}

// The subscription routes. Each names its repo in its body or query, so each authorizes itself and then takes the
// refused row (refuseDeletedRepo).
func (self *EvsEngine) subscriptionRoutes() []*EvsRoute {
	pattern := evsRoutePrefix + "subscriptions"
	return []*EvsRoute{
		{Method: http.MethodPost, Pattern: pattern, Name: evsSubscriptionsPostTemplate, RefuseDeleted: true, Serve: self.serveSubscribe},
		{Method: http.MethodGet, Pattern: pattern, Name: evsSubscriptionsGetTemplate, RefuseDeleted: true, Serve: self.serveSubscriptions},
		{Method: http.MethodDelete, Pattern: pattern, Name: evsSubscriptionsDeleteTemplate, RefuseDeleted: true, Serve: self.serveUnsubscribe},
	}
}

// §11.12's refused row for a route on no one repo whose RefuseDeleted is set, once AuthorizeRepo passed: the guard's
// step 8 and its refused check, which it cannot run before the body or query names the repo. false once answered.
func (self *EvsEngine) refuseDeletedRepo(request *EvsRequest) bool {
	if !request.route.RefuseDeleted {
		return true
	}
	return request.resolvePlace() && request.refuseDeleted()
}

// A lease request held to §11.10's shape, its repo authorized for r and not refused by §11.12's refused row: the
// leases it names, or false once answered.
func (self *EvsEngine) leasesOf(request *EvsRequest, body *protocol.EvsSubscriptionRequest, expiresAt time.Time) (sidecar.Id, []*EvsLease, bool) {
	repoId, err := sidecar.IdFromBytes(body.GetRepoId())
	if err != nil || body.GetPathEpoch() == 0 || self.settings.LeaseMaxPrefixCount < len(body.GetPrefixes()) {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return sidecar.Id{}, nil, false
	}
	if !request.AuthorizeRepo(repoId, sidecar.AclEvsRead) || !self.refuseDeletedRepo(request) {
		return sidecar.Id{}, nil, false
	}
	template := &EvsLease{
		ClientId:  sidecar.Id(request.Principal.ClientId),
		SidecarId: request.SidecarId,
		PathEpoch: body.GetPathEpoch(),
		ExpiresAt: expiresAt,
	}
	if len(body.GetRefId()) == 0 {
		template.EveryRef = true
	} else if template.RefId, err = sidecar.IdFromBytes(body.GetRefId()); err != nil {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return sidecar.Id{}, nil, false
	} else {
		request.NoteRefIds(template.RefId)
	}
	leases := []*EvsLease{}
	for _, prefix := range body.GetPrefixes() {
		lease := *template
		if 0 < len(prefix.GetToken()) {
			tokenPath, err := sidecar.ParseEvsChangedTokenPath(prefix.GetToken())
			if err != nil {
				request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
				return sidecar.Id{}, nil, false
			}
			lease.Prefix = tokenPath
		}
		leases = append(leases, &lease)
	}
	return repoId, leases, true
}

// POST: see the file header.
func (self *EvsEngine) serveSubscribe(request *EvsRequest) {
	body := &protocol.EvsSubscriptionRequest{}
	if !request.ReadMessage(body, self.settings.SubscriptionRequestMaxByteCount) {
		return
	}
	repoId, leases, ok := self.leasesOf(request, body, request.Now().Add(self.settings.LeaseLife))
	if !ok {
		return
	}
	if len(leases) == 0 {
		// none: the whole ref
		leases = []*EvsLease{self.wholeRefLease(request, body)}
	}
	if self.host.Redis == nil {
		request.Unavailable(nil)
		return
	}
	caps, ok := self.subscriptionCaps(request, repoId)
	if !ok {
		return
	}
	clientId := sidecar.Id(request.Principal.ClientId)
	// the client's repo count first, on its own hash tag (plan-EVS1-subscription-caps#2)
	counted, err := self.host.Redis.RunScript(request.Ctx, ClientRepoPutScript, []string{ClientRepoKey(clientId)}, []string{
		strconv.FormatInt(request.Now().UnixMilli(), 10),
		sidecar.EvsKeyId(repoId),
		strconv.FormatInt(caps.reposPerClient, 10),
		strconv.FormatInt(request.Now().Add(-self.settings.LeaseLife).UnixMilli(), 10),
		strconv.FormatInt(self.settings.LeaseKeyTtl.Milliseconds(), 10),
	})
	if err != nil {
		request.Unavailable(nil)
		return
	}
	switch counted.Integer {
	case evsClientRepoAdded, evsClientRepoRenewed:
	case evsClientRepoRefused:
		request.Refuse(evsQuotaRefusalReply(&sidecar.QuotaRefusal{LimitKey: evsReposPerClientLimitKey, Limit: caps.reposPerClient, Used: caps.reposPerClient}))
		return
	default:
		// a reply the script does not give: nothing is known of the count, so no lease is written
		request.Unavailable(nil)
		return
	}
	args := []string{
		strconv.FormatInt(request.Now().UnixMilli(), 10),
		evsLeaseHolder(clientId, request.SidecarId),
		strconv.FormatInt(caps.holdersPerRepo, 10),
		strconv.FormatInt(self.settings.LeaseKeyTtl.Milliseconds(), 10),
	}
	for _, lease := range leases {
		args = append(args, lease.field(), strconv.FormatInt(lease.ExpiresAt.UnixMilli(), 10))
	}
	reply, err := self.host.Redis.RunScript(request.Ctx, LeasePutScript, []string{LeaseKey(repoId), LeaseVersionKey(repoId)}, args)
	switch {
	case err != nil:
		request.Unavailable(nil)
	case reply.Integer != 1:
		if counted.Integer == evsClientRepoAdded {
			// the repo was counted for a lease the per-repo cap refused. An error here leaves it counted until its
			// score lapses, which counts high and so refuses no more than the cap would.
			self.uncountClientRepo(request, clientId, repoId)
		}
		request.Refuse(evsQuotaRefusalReply(&sidecar.QuotaRefusal{LimitKey: caps.holdersPerRepoLimitKey, Limit: caps.holdersPerRepo, Used: caps.holdersPerRepo}))
	default:
		request.Reply(nil)
	}
}

// Takes repoId out of the client's count once the client holds no live lease on it, under any of its sidecars: a
// DELETE of its last lease there, or a POST the per-repo cap refused. The read and the removal are on two hash tags,
// so a POST of the same client between them leaves a lease the set lacks until its renewal (the file header).
func (self *EvsEngine) uncountClientRepo(request *EvsRequest, clientId sidecar.Id, repoId sidecar.Id) error {
	leases, err := ReadLeases(request.Ctx, self.host.Redis, repoId)
	if err != nil {
		return err
	}
	for _, lease := range leases {
		if lease.ClientId == clientId && request.Now().Before(lease.ExpiresAt) {
			return nil
		}
	}
	_, err = self.host.Redis.RunScript(request.Ctx, ClientRepoRemoveScript, []string{ClientRepoKey(clientId)}, []string{sidecar.EvsKeyId(repoId)})
	return err
}

// The lease for the whole ref a request with no prefix names.
func (self *EvsEngine) wholeRefLease(request *EvsRequest, body *protocol.EvsSubscriptionRequest) *EvsLease {
	lease := &EvsLease{
		ClientId:  sidecar.Id(request.Principal.ClientId),
		SidecarId: request.SidecarId,
		PathEpoch: body.GetPathEpoch(),
		ExpiresAt: request.Now().Add(self.settings.LeaseLife),
	}
	if len(body.GetRefId()) == 0 {
		lease.EveryRef = true
	} else {
		lease.RefId = sidecar.Id(body.GetRefId())
	}
	return lease
}

// The caps one lease request is held to.
type evsSubscriptionCaps struct {
	// The repo's distinct holders, and the key that set it.
	holdersPerRepo         int64
	holdersPerRepoLimitKey string
	// The repos one client follows: evs_repos_per_client.
	reposPerClient int64
}

// The request's caps from its network's limits (§20.4; plan-EVS1-subscription-caps#1 and #2): the repo's holders at
// evs_subscribers_per_repo, or in the team directory config_admissions, and the client's repos at
// evs_repos_per_client. A key the limits lack reads 0, refusing every new holder or repo. false once answered.
func (self *EvsEngine) subscriptionCaps(request *EvsRequest, repoId sidecar.Id) (*evsSubscriptionCaps, bool) {
	if self.host.Quota == nil {
		request.Unavailable(nil)
		return nil, false
	}
	limitKey := evsSubscribersPerRepoLimitKey
	if facts, answer := self.deps.AuthState.Repo(request.Principal, repoId); answer == EvsAuthAllowed && facts.Kind == protocol.RepoKind_REPO_KIND_DIRECTORY {
		limitKey = evsDirectoryAdmissionsLimitKey
	}
	limits, err := self.host.Quota.Limits(request.Ctx, connect.Id(request.Principal.NetworkId))
	if err != nil || limits == nil {
		request.Unavailable(nil)
		return nil, false
	}
	return &evsSubscriptionCaps{
		holdersPerRepo:         evsSubscriptionCap(limits.Limits[limitKey]),
		holdersPerRepoLimitKey: limitKey,
		reposPerClient:         evsSubscriptionCap(limits.Limits[evsReposPerClientLimitKey]),
	}, true
}

// A limit as a script's cap: §20.4's no limit, a negative value, is a count no set reaches.
func evsSubscriptionCap(limit int64) int64 {
	if limit < 0 {
		return int64(^uint32(0))
	}
	return limit
}

// GET: the caller's live leases on ?repo_id=.
func (self *EvsEngine) serveSubscriptions(request *EvsRequest) {
	repoId, err := parseEvsHexId(request.Http.URL.Query().Get(evsRepoIdPathValue))
	if err != nil {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	if !request.AuthorizeRepo(repoId, sidecar.AclEvsRead) || !self.refuseDeletedRepo(request) {
		return
	}
	if self.host.Redis == nil {
		request.Unavailable(nil)
		return
	}
	leases, err := ReadLeases(request.Ctx, self.host.Redis, repoId)
	if err != nil {
		request.Unavailable(nil)
		return
	}
	clientId := sidecar.Id(request.Principal.ClientId)
	reply := &protocol.EvsSubscriptionsReply{}
	for _, lease := range leases {
		if lease.ClientId != clientId || lease.SidecarId != request.SidecarId || !request.Now().Before(lease.ExpiresAt) {
			continue
		}
		subscription := &protocol.EvsSubscription{PathEpoch: lease.PathEpoch, ExpiresMs: lease.ExpiresAt.UnixMilli()}
		if !lease.EveryRef {
			subscription.RefId = lease.RefId.Bytes()
		}
		if 0 < len(lease.Prefix) {
			subscription.Prefix = lease.Prefix.Proto()
		}
		reply.Subscriptions = append(reply.Subscriptions, subscription)
	}
	slices.SortFunc(reply.Subscriptions, func(a *protocol.EvsSubscription, b *protocol.EvsSubscription) int {
		return strings.Compare(a.String(), b.String())
	})
	request.Reply(reply)
}

// DELETE: see the file header.
func (self *EvsEngine) serveUnsubscribe(request *EvsRequest) {
	body := &protocol.EvsSubscriptionRequest{}
	if !request.ReadMessage(body, self.settings.SubscriptionRequestMaxByteCount) {
		return
	}
	repoId, leases, ok := self.leasesOf(request, body, time.Time{})
	if !ok {
		return
	}
	if self.host.Redis == nil {
		request.Unavailable(nil)
		return
	}
	args := []string{"exact"}
	if len(leases) == 0 {
		// every lease of the caller's on this ref, in every epoch
		whole := self.wholeRefLease(request, body)
		ref := evsLeaseEveryRef
		if !whole.EveryRef {
			ref = sidecar.EvsKeyId(whole.RefId)
		}
		args = []string{"prefix", evsLeaseHolder(whole.ClientId, whole.SidecarId) + "|" + ref + "|"}
	} else {
		for _, lease := range leases {
			args = append(args, lease.field())
		}
	}
	if _, err := self.host.Redis.RunScript(request.Ctx, LeaseDeleteScript, []string{LeaseKey(repoId), LeaseVersionKey(repoId)}, args); err != nil {
		request.Unavailable(nil)
		return
	}
	// the repo leaves the client's count with its last lease there; a retry of the DELETE repeats this
	if err := self.uncountClientRepo(request, sidecar.Id(request.Principal.ClientId), repoId); err != nil {
		request.Unavailable(nil)
		return
	}
	request.Reply(nil)
}

// Every lease the repo's hash holds, expired ones included, skipping a field that does not parse.
func ReadLeases(ctx context.Context, redis sidecar.Redis, repoId sidecar.Id) ([]*EvsLease, error) {
	fieldValues, err := redis.HashGetAll(ctx, LeaseKey(repoId))
	if err != nil {
		return nil, err
	}
	leases := make([]*EvsLease, 0, len(fieldValues))
	for field, value := range fieldValues {
		if lease, ok := parseEvsLease(field, value); ok {
			leases = append(leases, lease)
		}
	}
	return leases, nil
}

// Drops the repo's leases whose expiry passed at now, for taskworker's daily sweep (§11.10's renew row): how many
// went.
func SweepLeases(ctx context.Context, redis sidecar.Redis, repoId sidecar.Id, now time.Time) (int64, error) {
	if redis == nil {
		return 0, errors.New("no redis to sweep")
	}
	reply, err := redis.RunScript(ctx, LeaseSweepScript, []string{LeaseKey(repoId), LeaseVersionKey(repoId)},
		[]string{strconv.FormatInt(now.UnixMilli(), 10)})
	if err != nil {
		return 0, err
	}
	return reply.Integer, nil
}

// Every repo's expired leases dropped, for taskworker's daily sweep: each metadata cluster's repo/ objects listed,
// LeaseSweepListPageCount keys a LIST, each repo's hash swept. How many leases went. A host with no Redis has none to
// sweep. taskworker's job passes no settings, so the page is the defaults' until the review phase's settings sweep
// threads its own through (QD-706).
func SweepAllLeases(ctx context.Context, host *sidecar.ServiceHost, now time.Time) (int64, error) {
	if host == nil || host.Blobs == nil {
		return 0, errors.New("no host to sweep on")
	}
	if host.Redis == nil {
		return 0, nil
	}
	pageCount := DefaultEvsSettings().LeaseSweepListPageCount
	removed := int64(0)
	for _, clusterId := range host.Blobs.MetadataClusterIds() {
		cluster, err := host.Blobs.Cluster(clusterId)
		if err != nil {
			return removed, err
		}
		startAfter := ""
		for {
			objects, more, err := cluster.List(ctx, repoKeyPrefix, startAfter, pageCount)
			if err != nil {
				return removed, err
			}
			for _, info := range objects {
				startAfter = info.Key
				repoId, err := parseEvsHexId(strings.TrimPrefix(info.Key, repoKeyPrefix))
				if err != nil {
					continue
				}
				count, err := SweepLeases(ctx, host.Redis, repoId, now)
				if err != nil {
					return removed, err
				}
				removed += count
			}
			if !more || len(objects) == 0 {
				break
			}
		}
	}
	return removed, nil
}
