// §6.8's topic registry, on every leg: the names a hint and a reset carry, and how each topic's version
// moves, which the push state machine (push_state.go) and pushservice's hint script both read, so the
// two sides never disagree on a topic. Owners name the topic their hints carry from here.
//
// The registry, as plan-PROTO-sync-routes-durable-versions and plan-CORE-core-hint-body #3 settled it:
//
//	core            §5    api's clock in µs, raised past the stored value
//	team            §7    the authorization log position n: durable
//	sock            §9    sockets' clock in ms, per client
//	mail            §15   the writer's clock in ms, per client, raised past the stored value
//	tls             §13   as mail
//	dns             §12   the zone serial, which a restore raises above every serial issued: durable
//	gkm             §10   gkm's clock in µs, raised past the stored value
//	gkm:<group_id>  §10   epoch x 2^24 + generation: durable
//	evs:<repo_id>   §11   the repo's push sequence, a clock created at its master's TIME
//
// Only topics that gate access are durable, and a lower or conflicting durable version alarms (I-16).
// A clock version's fall is a gap: the client refetches, checks what it gets against its pins and
// adopts it. A raised clock is one the hint script lifts to the stored value plus one when the writer's
// clock is not above it, so skew between writers never makes a hint stale.

package sidecar

import (
	"errors"
	"strings"
)

// §6.8's topics with a fixed name.
const (
	PushTopicCore = "core"
	PushTopicTeam = "team"
	PushTopicSock = "sock"
	PushTopicMail = "mail"
	PushTopicTls  = "tls"
	PushTopicDns  = "dns"
	// gkm's per-client topic: pending, wrap-pending, welcome and key-packages-low work (§10).
	PushTopicGkm = "gkm"
)

// The families' prefixes: gkm:<group_id> and evs:<repo_id>, each id in its UUID form.
const (
	PushTopicGkmGroupPrefix = "gkm:"
	PushTopicEvsPrefix      = "evs:"
)

// The bits of a gkm:<group_id> version that hold the generation: epoch x 2^24 + generation (§6.8).
const gkmGroupGenerationBitCount = 24

var (
	// A generation past 2^24, or an epoch that would carry the version past uint64.
	ErrGkmGroupVersion = errors.New("gkm group version out of range")
)

// gkm:<group_id>, one MLS group's epoch and generation (§10).
func PushTopicGkmGroup(groupId Id) string {
	return PushTopicGkmGroupPrefix + groupId.String()
}

// evs:<repo_id>, one repo's push sequence (§11.10).
func PushTopicEvs(repoId Id) string {
	return PushTopicEvsPrefix + repoId.String()
}

// The version of gkm:<group_id> at an epoch and generation: epoch x 2^24 + generation, so a rotation
// without a commit raises it too (§6.8). A generation from 2^24 on, or an epoch from 2^40 on, is out of
// range, since the sum would no longer order the pairs.
func GkmGroupVersion(epoch uint64, generation uint64) (uint64, error) {
	if 1<<gkmGroupGenerationBitCount <= generation || 1<<(64-gkmGroupGenerationBitCount) <= epoch {
		return 0, ErrGkmGroupVersion
	}
	return epoch<<gkmGroupGenerationBitCount | generation, nil
}

// How a topic's version moves.
type PushTopicClass int

const (
	// Not in §6.8's registry: nothing a client applies.
	PushTopicUnknown PushTopicClass = iota
	// Never falls: a lower or conflicting one alarms (I-16).
	PushTopicDurable
	// A clock: a fall is a gap, never an alarm.
	PushTopicClock
)

// The class of topic, PushTopicUnknown for a name §6.8 does not hold or a family member whose id does
// not parse.
func PushTopicClassOf(topic string) PushTopicClass {
	switch topic {
	case PushTopicTeam, PushTopicDns:
		return PushTopicDurable
	case PushTopicCore, PushTopicSock, PushTopicMail, PushTopicTls, PushTopicGkm:
		return PushTopicClock
	}
	if idText, found := strings.CutPrefix(topic, PushTopicGkmGroupPrefix); found {
		if pushTopicIdValid(idText) {
			return PushTopicDurable
		}
		return PushTopicUnknown
	}
	if idText, found := strings.CutPrefix(topic, PushTopicEvsPrefix); found {
		if pushTopicIdValid(idText) {
			return PushTopicClock
		}
	}
	return PushTopicUnknown
}

// Whether a family member's id is an id in its one string form, so one group or repo has one topic.
func pushTopicIdValid(idText string) bool {
	id, err := ParseId(idText)
	return err == nil && id.String() == idText
}

// Whether the hint script raises topic's version past the stored value when the writer's is not above
// it: the clocks of core, mail, tls and gkm, as gkm's was first (§6.8).
func PushTopicRaisesClock(topic string) bool {
	switch topic {
	case PushTopicCore, PushTopicMail, PushTopicTls, PushTopicGkm:
		return true
	}
	return false
}
