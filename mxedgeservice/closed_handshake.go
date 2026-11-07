// The fleet's closed-handshake memory (§15.4; §2.8 mx-1): when a handshake closes, Redis remembers the
// sender's /24 or /48 for an hour, so that sender's plaintext retry gets 451, a retry, and not 530,
// which a Postfix falling back from TLS would take as final. It reaches a sibling sending address and
// another lb host's retry alike, since every block shares the keys.
//
// A key is {mxc_<HMAC_k(prefix)>} under a daily k, and holds no address. k is HMAC-SHA-256 of the fleet's
// secret and the UTC day, as a big-endian 32-bit count of days since the epoch (reading 5). An entry
// written at 23:50 is under yesterday's k by 00:10, so a read tries today's and then yesterday's, and
// the 1 h holds across 00:00 UTC. The two keys hash to different slots, so they are two calls, never
// one GetMany, which production's cluster would refuse. Each carries its own hash in the tag, spreading
// the family over the cluster. Every process must derive these alike, so testing pins them to vectors.
//
// Keys are soft state. A lost one costs a sender a 530 it should not have had, and an unanswered read
// costs nothing: it reads as recent, so a sender is told to retry and never told no for good.
//
// Safe for concurrent use.

package mxedgeservice

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"time"

	"github.com/urnetwork/sidecar"
)

const (
	// What a key holds: its existence is the whole of the memory.
	mxClosedHandshakeValue = "1"
	// The shortest fleet secret taken: SHA-256's output, the most an HMAC key adds.
	mxClosedHandshakeSecretMinByteCount = 32
	// A UTC day, which has no leap second in Unix time.
	mxSecondsPerDay = 24 * 60 * 60
)

var errMxNoClosedHandshakeSecret = errors.New("no closed-handshake secret")

// The memory, as this process reaches it.
type mxClosedHandshakes struct {
	redis  sidecar.Redis
	secret []byte
	ttl    time.Duration
	clock  MxEdgeClock
}

// A secret too short to use leaves Available false: Record refuses and Recent answers true, so the
// engine stays not ready and a sender is still only told to retry.
func newMxClosedHandshakes(redis sidecar.Redis, secret []byte, ttl time.Duration, clock MxEdgeClock) *mxClosedHandshakes {
	self := &mxClosedHandshakes{
		redis:  redis,
		secret: secret,
		ttl:    ttl,
		clock:  clock,
	}
	if self.Available() {
		testHookSecret("K_mxc", secret)
	}
	return self
}

// Whether keys can be computed.
func (self *mxClosedHandshakes) Available() bool {
	return mxClosedHandshakeSecretMinByteCount <= len(self.secret)
}

// The key for aggregate on day, under that day's k.
func (self *mxClosedHandshakes) key(aggregate netip.Prefix, day time.Time) string {
	dayMac := hmac.New(sha256.New, self.secret)
	dayMac.Write(binary.BigEndian.AppendUint32(nil, uint32(day.Unix()/mxSecondsPerDay)))
	dayKey := dayMac.Sum(nil)
	testHookSecret("K_mxc_day", dayKey)

	// a prefix never fails to marshal, and its bytes tell the two families apart by length
	prefixBytes, _ := aggregate.MarshalBinary()
	prefixMac := hmac.New(sha256.New, dayKey)
	prefixMac.Write(prefixBytes)
	return "{mxc_" + hex.EncodeToString(prefixMac.Sum(nil)) + "}"
}

// Remembers a closed handshake from sender's /24 or /48. A failure leaves nothing to do but count it:
// the sender's retry then finds no memory, the outcome a lost key has.
func (self *mxClosedHandshakes) Record(ctx context.Context, sender netip.Addr) error {
	if !self.Available() {
		return errMxNoClosedHandshakeSecret
	}
	_, aggregate := mxSenderPrefixes(sender)
	key := self.key(aggregate, self.clock.Now())
	testHookBarrier("mxedge.closed_handshake_write.before", "")
	err := self.redis.Set(ctx, key, []byte(mxClosedHandshakeValue), self.ttl)
	testHookBarrier("mxedge.closed_handshake_write.after", "")
	return err
}

// Whether sender's /24 or /48 closed a handshake within the ttl, as far as an answer says, and whether
// Redis answered at all. Anything but a clean miss on both keys reads as recent.
func (self *mxClosedHandshakes) Recent(ctx context.Context, sender netip.Addr) (recent bool, answered bool) {
	if !self.Available() {
		return true, false
	}
	_, aggregate := mxSenderPrefixes(sender)
	now := self.clock.Now()
	testHookBarrier("mxedge.closed_handshake_read.before", "")
	defer testHookBarrier("mxedge.closed_handshake_read.after", "")
	for _, day := range []time.Time{now, now.Add(-24 * time.Hour)} {
		_, found, err := self.redis.Get(ctx, self.key(aggregate, day))
		if err != nil {
			return true, false
		}
		if found {
			return true, true
		}
	}
	return false, true
}
