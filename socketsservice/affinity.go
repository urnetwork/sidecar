// §9.7's affinity (SOCK-M6-01; R-SOCK-2, D-SOCK-5): a Find that carries an affinity key, tlsedge's keyed hash of a
// visitor's /24 or /48, reaches the same listener of a group each time while that listener can take it, so one
// visitor's connections share what the listener keeps for it. It is the listener's to opt in to (§9.5's affinity):
// only listeners registered with it take part. Among them, after step 1's filter (PickSocketListeners), rendezvous
// hashing orders the group by a score of the key and each listener, highest first, and the first that is not full is
// the primary, the next such the backup: consistent hashing with bounded loads (Mirrokni, Thorup and Zadimoghaddam,
// https://arxiv.org/abs/1608.01350), whose bins hold at most ⌈c × (m + 1) / n⌉ with the ball being placed counted,
// at §9.7's c = 1.25 over the mean est of the listeners that opted in. A listener is full once its est reaches that,
// so no listener goes above 1.25 × the mean with this Find on it (a reading of "skips listeners above 1.25 × mean
// est": the paper's capacity, which at low loads spreads a key, as bounded loads must). A listener joining or leaving
// moves only the keys it ranks first for. With no listener that opted in, P2C stands.
//
// The score is SHA-1 over the key and the listener's client id in lowercase hex, which the Redis store's pick script
// computes with redis.sha1hex, the one hash a script has: a spread, not a secret, since the key arrives already keyed
// and neither the key nor a score is ever stored or logged (sock-2: the key lives for the request). The bound is
// integer arithmetic a Lua double holds exactly: a listener is full when est × 100 × n reaches percent × (the sum of
// est + 1), n being how many listeners opted in. Weight plays no part here: §9.7 bounds the branch by est alone (a
// reading).
//
// A keyed Find reads its whole group, since a sample would move a key's listener with each draw, so §9.7's 64-listener
// sample applies only to a Find with no key and a keyed Find's cost grows with its group (SOCK.md reading 15).
// BenchmarkPickSocketAffinity measures the branch at scale.

package socketsservice

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"slices"

	"github.com/urnetwork/connect"
)

// The rendezvous score of listenerClientId for affinityKey, compared as bytes, the higher first.
func SocketAffinityScore(affinityKey []byte, listenerClientId connect.Id) [sha1.Size]byte {
	input := make([]byte, 0, len(affinityKey)+2*len(listenerClientId))
	input = append(input, affinityKey...)
	input = hex.AppendEncode(input, listenerClientId[:])
	return sha1.Sum(input)
}

// One listener the branch ranks.
type socketAffinityRanked struct {
	candidate *SocketCandidate
	est       int
	score     [sha1.Size]byte
}

// The affinity branch over pickable, step 1's candidates: the primary and backup in rendezvous order among those that
// opted in, each that is full skipped; nil when none opted in, and then P2C picks. At least one listener is never
// full, since the least loaded is at or below the mean and the percent at least 100.
func pickSocketAffinity(pickable []*SocketCandidate, request *SocketPickRequest, settings *SocketSchedulerSettings) *SocketPickResult {
	ranked := []*socketAffinityRanked{}
	estSum := int64(0)
	for _, candidate := range pickable {
		if !candidate.Affinity {
			continue
		}
		est := SocketEstimate(candidate, request.NowMillis, settings)
		ranked = append(ranked, &socketAffinityRanked{
			candidate: candidate,
			est:       est,
			score:     SocketAffinityScore(request.AffinityKey, candidate.ListenerClientId),
		})
		estSum += int64(est)
	}
	if len(ranked) == 0 {
		return nil
	}
	slices.SortFunc(ranked, func(a *socketAffinityRanked, b *socketAffinityRanked) int {
		if order := bytes.Compare(b.score[:], a.score[:]); order != 0 {
			return order
		}
		return a.candidate.ListenerClientId.Cmp(b.candidate.ListenerClientId)
	})
	rankedCount := int64(len(ranked))
	capacity := int64(settings.AffinityLoadPercent) * (estSum + 1)
	result := &SocketPickResult{Outcome: SocketPickFound}
	for _, listener := range ranked {
		if capacity <= int64(listener.est)*100*rankedCount {
			continue
		}
		if result.Primary == nil {
			result.Primary = listener.candidate
			continue
		}
		result.Backup = listener.candidate
		break
	}
	return result
}
