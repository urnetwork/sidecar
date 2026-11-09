package sidecar

import (
	"errors"
	"testing"
)

func TestPushTopicClasses(t *testing.T) {
	groupId := NewId()
	repoId := NewId()
	for _, c := range []struct {
		topic   string
		class   PushTopicClass
		raising bool
	}{
		{topic: PushTopicCore, class: PushTopicClock, raising: true},
		{topic: PushTopicTeam, class: PushTopicDurable},
		{topic: PushTopicSock, class: PushTopicClock},
		{topic: PushTopicMail, class: PushTopicClock, raising: true},
		{topic: PushTopicTls, class: PushTopicClock, raising: true},
		{topic: PushTopicDns, class: PushTopicDurable},
		{topic: PushTopicGkm, class: PushTopicClock, raising: true},
		{topic: PushTopicGkmGroup(groupId), class: PushTopicDurable},
		{topic: PushTopicEvs(repoId), class: PushTopicClock},
		{topic: "", class: PushTopicUnknown},
		{topic: "sockets", class: PushTopicUnknown},
		{topic: "evs:", class: PushTopicUnknown},
		{topic: "evs:r", class: PushTopicUnknown},
		// one repo has one topic: the 32-character form is refused
		{topic: "evs:" + repoId.String()[0:8] + repoId.String()[9:13] + repoId.String()[14:18] + repoId.String()[19:23] + repoId.String()[24:], class: PushTopicUnknown},
		{topic: "gkm:" + groupId.String() + "x", class: PushTopicUnknown},
		{topic: "CORE", class: PushTopicUnknown},
	} {
		if got := PushTopicClassOf(c.topic); got != c.class {
			t.Errorf("%q: class %d, want %d", c.topic, got, c.class)
		}
		if got := PushTopicRaisesClock(c.topic); got != c.raising {
			t.Errorf("%q: raises %t", c.topic, got)
		}
	}
}

func TestGkmGroupVersion(t *testing.T) {
	for _, c := range []struct {
		epoch      uint64
		generation uint64
		version    uint64
	}{
		{epoch: 0, generation: 1, version: 1},
		{epoch: 1, generation: 0, version: 1 << 24},
		{epoch: 3, generation: 5, version: 3<<24 + 5},
		{epoch: 1<<40 - 1, generation: 1<<24 - 1, version: 1<<64 - 1},
	} {
		version, err := GkmGroupVersion(c.epoch, c.generation)
		if err != nil || version != c.version {
			t.Errorf("(%d, %d): %d, %v", c.epoch, c.generation, version, err)
		}
	}
	// a rotation without a commit raises it, and a commit raises it past every generation before it
	before, _ := GkmGroupVersion(7, 1<<24-1)
	after, _ := GkmGroupVersion(8, 0)
	if after <= before {
		t.Errorf("%d then %d", before, after)
	}
	for _, c := range [][2]uint64{{0, 1 << 24}, {1 << 40, 0}} {
		if _, err := GkmGroupVersion(c[0], c[1]); !errors.Is(err, ErrGkmGroupVersion) {
			t.Errorf("(%d, %d): %v", c[0], c[1], err)
		}
	}
}
