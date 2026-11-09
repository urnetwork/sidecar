// <root>'s budget at each CA (§13.8's Budget; cert-1): Redis {tcb_<ca>_<registered_domain>}, a sorted
// set of the window's new-set orders scored by their admission in ms, checked against the cap and added
// to in one script, as server/ip_ratelimit.go:105's sliding window is, and expiring BudgetTtl after its
// newest order.
//
// Redis holds soft state only (owner decision 136), so a lost key must never read as an empty budget:
// a rebuild writes a marker member with the entries, and the spend refuses to count without it. A key
// with no marker is rebuilt from network_tls_cert first (CertsStore.ListNewSetOrders): an order still
// under way scores now, an issued one its certificate's not_before, which LE backdates by an hour, so a
// rebuilt entry stays at least as long as LE counts it. An order that failed spent a unit at its
// admission and is not rebuilt, since no certificate came of it. A key that expired held no order
// inside BudgetTtl, so its rebuild finds none.
//
// The first rebuild wins: a second, from an older read of the rows, finds the key and writes nothing,
// so no spend made in between is lost. A spend is idempotent by its cert_id, so a retried admission
// spends once. Safe for concurrent use.

package certsservice

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/urnetwork/sidecar"
)

// The member a rebuild writes, scored 0, so no window ever removes it. Exported, with the scripts, for
// sidecartest's Go twins of them.
const CertsBudgetMarker = "rebuilt"

// What the spend script answers.
const (
	certsBudgetSpent    = 1
	certsBudgetFull     = 0
	certsBudgetUnseeded = -1
)

// The budget script's reply was not one of its own.
var errCertsBudgetReply = errors.New("certs budget script answered something else")

// KEYS[1] the budget key. ARGV: now in ms, the window in ms, the cap, the order's member, the key's ttl
// in ms. Answers 1 spent (or spent already), 0 full, -1 no marker: rebuild first.
var CertsBudgetSpendScript = &sidecar.RedisScript{
	Name: "certs_budget_spend",
	Source: `
if redis.call('ZSCORE', KEYS[1], '` + CertsBudgetMarker + `') == false then
  return -1
end
local now = tonumber(ARGV[1])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '(0', '(' .. tostring(now - tonumber(ARGV[2])))
if redis.call('ZSCORE', KEYS[1], ARGV[4]) ~= false then
  return 1
end
if tonumber(ARGV[3]) <= redis.call('ZCARD', KEYS[1]) - 1 then
  return 0
end
redis.call('ZADD', KEYS[1], now, ARGV[4])
redis.call('PEXPIRE', KEYS[1], ARGV[5])
return 1
`,
}

// KEYS[1] the budget key. ARGV: the key's ttl in ms, then score and member pairs. Writes the marker and
// the entries unless the key exists, and answers whether it wrote.
var CertsBudgetSeedScript = &sidecar.RedisScript{
	Name: "certs_budget_seed",
	Source: `
if redis.call('EXISTS', KEYS[1]) == 1 then
  return 0
end
redis.call('ZADD', KEYS[1], 0, '` + CertsBudgetMarker + `')
for index = 2, #ARGV, 2 do
  redis.call('ZADD', KEYS[1], ARGV[index], ARGV[index + 1])
end
redis.call('PEXPIRE', KEYS[1], ARGV[1])
return 1
`,
}

// The budget of each CA under one root.
type CertsBudget struct {
	redis    sidecar.Redis
	store    CertsStore
	settings *CertsSettings
}

func NewCertsBudget(redis sidecar.Redis, store CertsStore, settings *CertsSettings) *CertsBudget {
	return &CertsBudget{redis: redis, store: store, settings: settings}
}

// {tcb_<ca>_<registered_domain>}: one key, so one slot, per CA and root.
func certsBudgetKey(ca CertsCa, rootDomain string) string {
	return fmt.Sprintf("{tcb_%s_%s}", ca, rootDomain)
}

// The member an order spends under: its cert_id.
func certsBudgetMember(certId sidecar.Id) string {
	return certId.String()
}

// Spends one unit of ca's budget for certId at now. True when it fit under the cap or certId had spent
// already; false when the window is full. A CA with no budget always fits. A key with no marker is
// rebuilt from the rows, then spent from.
func (self *CertsBudget) Spend(ctx context.Context, ca CertsCa, certId sidecar.Id, now time.Time) (bool, error) {
	caSettings := self.settings.Cas[ca]
	if caSettings == nil {
		return false, fmt.Errorf("CA %s has no settings", ca)
	}
	if caSettings.BudgetCap == 0 {
		return true, nil
	}
	key := certsBudgetKey(ca, self.settings.RootDomain)
	args := []string{
		strconv.FormatInt(now.UnixMilli(), 10),
		strconv.FormatInt(caSettings.BudgetWindow.Milliseconds(), 10),
		strconv.Itoa(caSettings.BudgetCap),
		certsBudgetMember(certId),
		strconv.FormatInt(self.settings.BudgetTtl.Milliseconds(), 10),
	}
	// a rebuild, then one more spend, and no further: a key lost twice in one call is an error
	for range 2 {
		reply, err := self.redis.RunScript(ctx, CertsBudgetSpendScript, []string{key}, args)
		if err != nil {
			return false, err
		}
		if reply.Kind != sidecar.RedisReplyInteger {
			return false, errCertsBudgetReply
		}
		switch reply.Integer {
		case certsBudgetSpent:
			return true, nil
		case certsBudgetFull:
			return false, nil
		case certsBudgetUnseeded:
			if err := self.Rebuild(ctx, ca, now); err != nil {
				return false, err
			}
		default:
			return false, errCertsBudgetReply
		}
	}
	return false, fmt.Errorf("the budget key of CA %s was lost again during its rebuild", ca)
}

// The entries a rebuild of ca's key writes at now, as score and member pairs: every new-set order in
// the window, an order under way scored now and an issued one its not_before.
func (self *CertsBudget) rebuildEntries(ctx context.Context, ca CertsCa, now time.Time) ([]string, error) {
	window := self.settings.Cas[ca].BudgetWindow
	rows, err := self.store.ListNewSetOrders(ctx, ca, now.Add(-window))
	if err != nil {
		return nil, err
	}
	entries := []string{}
	for _, row := range rows {
		var scoreTime time.Time
		switch {
		case row.State == sidecar.TlsCertStateOrdering || row.State == sidecar.TlsCertStateWaitingDns:
			scoreTime = now
		case row.Serial != "" && !row.NotBefore.IsZero():
			scoreTime = row.NotBefore
		default:
			// no certificate came of it
			continue
		}
		if scoreTime.Before(now.Add(-window)) {
			continue
		}
		entries = append(entries, strconv.FormatInt(scoreTime.UnixMilli(), 10), certsBudgetMember(row.CertId))
	}
	return entries, nil
}

// Rebuilds ca's key from the rows at now, unless a key is there already, which the first rebuild or a
// spend after it wrote.
func (self *CertsBudget) Rebuild(ctx context.Context, ca CertsCa, now time.Time) error {
	if self.settings.Cas[ca] == nil {
		return fmt.Errorf("CA %s has no settings", ca)
	}
	entries, err := self.rebuildEntries(ctx, ca, now)
	if err != nil {
		return err
	}
	args := append([]string{strconv.FormatInt(self.settings.BudgetTtl.Milliseconds(), 10)}, entries...)
	_, err = self.redis.RunScript(ctx, CertsBudgetSeedScript, []string{certsBudgetKey(ca, self.settings.RootDomain)}, args)
	return err
}
