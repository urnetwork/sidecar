// §18.7's step 0 on a client's slot (D-SDK-16, WK5): {scp_<C>}tok and {scp_<C>}tokrev, the projection of
// its sidecar_push_token row at the newest revision applied, which WakeTokenApplyScript alone writes, with
// no ttl. api applies each change it commits, the push sender each vendor rejection it tombstones, and
// taskworker's pass each row changed since its last run and each slot whose master changed (steps 5 and
// 6), all through this one script on the client's slot, so no command spans two slots (WK1).
//
// The writer's order is server's (model.SetPushToken): read t0, the TIME of the master serving the slot,
// by WakeTokenTimeScript before the transaction; commit; then apply. The script refuses an apply over its
// window past t0 as expired, one older than tokrev as stale, and writes nothing for one equal to it, so a
// projection moves only up its row's revisions, and an apply begun before a master took the slot has
// expired by the time taskworker reconciles that slot. Revisions stay below 2^53, so unlike §6.8's
// versions the script compares them as Lua numbers, exactly.
//
// tok holds <platform>\n<token> (plan-SDK-small-readings #13), which only the sender parses. Neither
// value is ever logged (I-13).

package pushservice

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// The largest revision a row may reach: 2^53 - 1, so a Lua number holds it exactly. A row starts at its
// insert's time in milliseconds, near 2^40, and §19.10's raise adds 2^32 a restore.
const WakeTokenMaxRevision = int64(9007199254740991)

var (
	// A row the apply cannot carry: a revision out of range, a platform that is not apns or fcm, a token
	// the route would not take, or a tombstone that names a platform.
	ErrWakeTokenInvalid = errors.New("wake token invalid")
	// What a script answered that is not the shape the script returns.
	errWakeTokenReply = errors.New("wake token script reply malformed")
)

// {scp_<C>}tokrev.
func WakeTokenRevisionKey(clientId connect.Id) string {
	return "{scp_" + clientId.String() + "}tokrev"
}

// One sidecar_push_token row as the apply carries it. A tombstone has neither platform nor token.
type WakeTokenRow struct {
	ClientId connect.Id
	// 1 to WakeTokenMaxRevision.
	Revision int64
	// sidecar.PushTokenPlatformApns or sidecar.PushTokenPlatformFcm; empty for a tombstone.
	Platform string
	// Empty for a tombstone.
	Token string
}

// Whether the row is a tombstone: a token removed by an empty POST, a vendor rejection or its client's
// removal.
func (self *WakeTokenRow) Tombstone() bool {
	return self.Token == ""
}

// Whether the row can be applied.
func (self *WakeTokenRow) validate() error {
	if self.Revision < 1 || WakeTokenMaxRevision < self.Revision {
		return fmt.Errorf("%w: a revision out of range", ErrWakeTokenInvalid)
	}
	if self.Tombstone() {
		if self.Platform != "" {
			return fmt.Errorf("%w: a tombstone with a platform", ErrWakeTokenInvalid)
		}
		return nil
	}
	if !sidecar.ValidPushToken(self.Platform, self.Token) {
		return fmt.Errorf("%w: a platform or token the route does not take", ErrWakeTokenInvalid)
	}
	return nil
}

// What tok holds for a token: <platform>\n<token>.
func WakeTokenValue(platform string, token string) []byte {
	return []byte(platform + "\n" + token)
}

// The platform and token tok holds, and false for a value that is not <platform>\n<token> with a platform
// and token the route takes: the sender drops such an entry, as it drops one with no tok.
func ParseWakeTokenValue(value []byte) (platform string, token string, ok bool) {
	platform, token, found := strings.Cut(string(value), "\n")
	if !found || token == "" || !sidecar.ValidPushToken(platform, token) {
		return "", "", false
	}
	return platform, token, true
}

// The master's TIME, read inside a script so that it is the clock of the master serving the client's
// slot: a plain TIME through the cluster router reaches any node. KEYS: tokrev, which the script names
// only to route to that master and never reads. Returns TIME's {seconds, microseconds}.
var WakeTokenTimeScript = &sidecar.RedisScript{
	Name: "pushservice.wake_token_time",
	Source: `
return redis.call('TIME')
`,
}

// Applies one row's revision to the client's projection. KEYS: tok, tokrev, both of {scp_<C>}. ARGV:
// t0 and the window, both in milliseconds, the row's revision, and tok's value, empty for a tombstone.
//
// In order: refuse arguments that are not decimals below 2^53; answer expired when the master's TIME is
// over the window past t0; answer stale when tokrev holds a higher revision and current when it holds this
// one, writing nothing; else SET tokrev, then SET tok, or DEL it for a tombstone, and answer applied. A
// stored tokrev that is not a revision is overwritten, as an absent one is. Neither key gets a ttl, so
// volatile-ttl never evicts them.
var WakeTokenApplyScript = &sidecar.RedisScript{
	Name: "pushservice.wake_token_apply",
	Source: `
local tok = KEYS[1]
local tokrev = KEYS[2]
local t0 = ARGV[1]
local window = ARGV[2]
local rev = ARGV[3]
local value = ARGV[4]

-- 1 to 16 digits, the first not 0, at most 2^53 - 1: exact as a Lua number
local function revision(text)
  if #text == 0 or #text > 16 or string.find(text, '^[1-9][0-9]*$') == nil then
    return false
  end
  return #text < 16 or text <= '9007199254740991'
end

if not revision(t0) or not revision(window) or not revision(rev) then
  return redis.error_reply('ERR wake token apply arguments malformed')
end
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
if now - tonumber(t0) > tonumber(window) then
  return 'expired'
end
local stored = redis.call('GET', tokrev)
if stored and revision(stored) then
  if tonumber(stored) > tonumber(rev) then
    return 'stale'
  end
  if tonumber(stored) == tonumber(rev) then
    return 'current'
  end
end
redis.call('SET', tokrev, rev)
if value == '' then
  redis.call('DEL', tok)
else
  redis.call('SET', tok, value)
end
return 'applied'
`,
}

// What one WakeTokenApplyScript run did.
type WakeTokenApplyResult string

const (
	// tokrev holds the row's revision and tok its token, or no tok for a tombstone.
	WakeTokenApplied WakeTokenApplyResult = "applied"
	// tokrev held the row's revision already: nothing was written.
	WakeTokenCurrent WakeTokenApplyResult = "current"
	// tokrev held a higher revision: nothing was written, so an older change never replaces a newer one.
	WakeTokenStale WakeTokenApplyResult = "stale"
	// The master's TIME was over the window past t0: nothing was written. The writer rereads t0 and its
	// row and applies again.
	WakeTokenExpired WakeTokenApplyResult = "expired"
)

// The milliseconds since the epoch of the TIME of the master serving clientId's slot: the t0 a writer
// reads before its transaction.
func ReadWakeTokenTime(ctx context.Context, redis HintRedis, clientId connect.Id) (int64, error) {
	reply, err := redis.RunScript(ctx, WakeTokenTimeScript, []string{WakeTokenRevisionKey(clientId)}, nil)
	if err != nil {
		return 0, err
	}
	return parseWakeTokenTime(reply)
}

// TIME's {seconds, microseconds}, as bulk strings or integers, in milliseconds.
func parseWakeTokenTime(reply *sidecar.RedisReply) (int64, error) {
	if reply == nil || reply.Kind != sidecar.RedisReplyArray || len(reply.Replies) != 2 {
		return 0, errWakeTokenReply
	}
	parts := [2]int64{}
	for index, part := range reply.Replies {
		switch part.Kind {
		case sidecar.RedisReplyBulk:
			value, err := strconv.ParseInt(string(part.Bulk), 10, 64)
			if err != nil {
				return 0, errWakeTokenReply
			}
			parts[index] = value
		case sidecar.RedisReplyInteger:
			parts[index] = part.Integer
		default:
			return 0, errWakeTokenReply
		}
	}
	seconds, microseconds := parts[0], parts[1]
	if seconds <= 0 || microseconds < 0 || 1000000 <= microseconds || WakeTokenMaxRevision/1000 < seconds {
		return 0, errWakeTokenReply
	}
	return seconds*1000 + microseconds/1000, nil
}

// Runs WakeTokenApplyScript for row on its client's slot, with the t0 its writer read and its window,
// which must be a positive whole number of milliseconds. A row that cannot be applied is
// ErrWakeTokenInvalid, and nothing is sent. An error means Redis did not answer, so the caller does not
// know whether the row landed: it rereads t0 and its row and applies again, which is safe, since the
// script orders every apply by revision.
func ApplyWakeToken(ctx context.Context, redis HintRedis, row *WakeTokenRow, t0Ms int64, window time.Duration) (WakeTokenApplyResult, error) {
	if row == nil {
		return "", fmt.Errorf("%w: no row", ErrWakeTokenInvalid)
	}
	if err := row.validate(); err != nil {
		return "", err
	}
	windowMs := window.Milliseconds()
	if t0Ms < 1 || WakeTokenMaxRevision < t0Ms || windowMs < 1 || time.Duration(windowMs)*time.Millisecond != window {
		return "", fmt.Errorf("%w: t0 or the window out of range", ErrWakeTokenInvalid)
	}
	value := ""
	if !row.Tombstone() {
		value = string(WakeTokenValue(row.Platform, row.Token))
	}
	reply, err := redis.RunScript(
		ctx,
		WakeTokenApplyScript,
		[]string{HintTokenKey(row.ClientId), WakeTokenRevisionKey(row.ClientId)},
		[]string{
			strconv.FormatInt(t0Ms, 10),
			strconv.FormatInt(windowMs, 10),
			strconv.FormatInt(row.Revision, 10),
			value,
		},
	)
	if err != nil {
		return "", err
	}
	if reply == nil || reply.Kind != sidecar.RedisReplyBulk {
		return "", errWakeTokenReply
	}
	switch result := WakeTokenApplyResult(reply.Bulk); result {
	case WakeTokenApplied, WakeTokenCurrent, WakeTokenStale, WakeTokenExpired:
		return result, nil
	}
	return "", errWakeTokenReply
}
