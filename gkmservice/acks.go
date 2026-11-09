// §10.6's acks (gkm-10): POST /gkm/groups/<id>/ack writes the token's own leaf's newest applied epoch into Redis
// {gka_<group_id>}, soft state the reconciler's retention reads (KEYS-M2-16) and nothing else does.
//
// The hash holds one field per leaf, its sidecar_id in 32 hex characters, valued "<epoch>:<time_ms>", and since, the
// family's creation time in ms, which a write sets only when it is absent and never moves, so retention can tell a
// family younger than 30 days, one Redis lost, and delete nothing from it (§10.6's retention row). Each write renews
// the key's 31 days. A leaf's ack is written at most once per AckInterval (daily): one inside it answers 200 and
// writes nothing, so a leaf's newest epoch reaches retention at most a day late, which only delays a deletion.
//
// gkm does not check the epoch against the group's: a leaf that acks past what it applied hurts only itself, since
// retention deletes an epoch only once every recent ack has passed it, and never the newest (§10.6).

package gkmservice

import (
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The field of {gka_<group_id>} that holds the family's creation time: no sidecar's field, which is 32 hex characters.
const gkmAckSinceField = "since"

// A leaf's ack value: "<epoch>:<time_ms>".
func gkmAckValue(epoch uint64, at time.Time) []byte {
	return []byte(strconv.FormatUint(epoch, 10) + ":" + strconv.FormatInt(at.UnixMilli(), 10))
}

// A leaf's ack value read back: its epoch and time, or false for a value out of form, which retention reads as no
// ack and so deletes nothing on its account.
func parseGkmAckValue(value []byte) (epoch uint64, at time.Time, ok bool) {
	epochText, timeText, found := strings.Cut(string(value), ":")
	if !found {
		return 0, time.Time{}, false
	}
	epoch, err := strconv.ParseUint(epochText, 10, 64)
	if err != nil {
		return 0, time.Time{}, false
	}
	timeMs, err := strconv.ParseInt(timeText, 10, 64)
	if err != nil || timeMs <= 0 {
		return 0, time.Time{}, false
	}
	return epoch, time.UnixMilli(timeMs), true
}

// since's value read back, or false.
func parseGkmAckSince(value []byte) (time.Time, bool) {
	timeMs, err := strconv.ParseInt(string(value), 10, 64)
	if err != nil || timeMs <= 0 {
		return time.Time{}, false
	}
	return time.UnixMilli(timeMs), true
}

// POST /gkm/groups/<id>/ack: a GkmAckRequest, the token's own leaf's newest applied epoch.
func (self *GkmEngine) serveAck(request *GkmRequest) {
	ackRequest := &protocol.GkmAckRequest{}
	if !request.ReadMessage(ackRequest, self.settings.RequestBodyMaxByteCount) {
		return
	}
	redis := self.host.Redis
	if redis == nil {
		request.Unavailable()
		return
	}
	groupId := *request.GroupId
	key := GkmAckRedisKey(groupId)
	field := sidecar.EvsKeyId(request.SidecarId)
	now := request.Now()
	held, found, err := redis.HashGet(request.Ctx, key, field)
	if err != nil {
		request.Unavailable()
		return
	}
	if found {
		if _, at, ok := parseGkmAckValue(held); ok && now.Before(at.Add(self.settings.AckInterval)) && !at.After(now) {
			// written within the day: the next day's ack carries what this one would
			request.Reply(nil)
			return
		}
	}
	fieldValues := map[string][]byte{field: gkmAckValue(ackRequest.GetEpoch(), now)}
	if _, sinceFound, err := redis.HashGet(request.Ctx, key, gkmAckSinceField); err != nil {
		request.Unavailable()
		return
	} else if !sinceFound {
		fieldValues[gkmAckSinceField] = []byte(strconv.FormatInt(now.UnixMilli(), 10))
	}
	barrierKey := gkmBarrierGroupKey(groupId)
	testHookBarrier(BarrierAckWriteBefore, barrierKey)
	err = redis.HashSet(request.Ctx, key, fieldValues)
	if err == nil {
		_, err = redis.Expire(request.Ctx, key, self.settings.AckTtl)
	}
	testHookBarrier(BarrierAckWriteAfter, barrierKey)
	if err != nil {
		request.Unavailable()
		return
	}
	request.Reply(nil)
}
