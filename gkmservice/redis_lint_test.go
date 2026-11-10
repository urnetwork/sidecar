package gkmservice

// §22.4's CROSSSLOT lint on gkm's one Redis family, {gka_<group_id>} (KEYS-M2-17): every call gkm makes names keys
// under one hash tag, which the static lint reads from this package's source, so a multi-key call across two groups,
// or a key outside its tag, fails here as it would on 3 masters. The runtime half, every script and multi-key call
// T3's engines made run against the 3-master cluster (sidecart3.RunCrossslot), waits on QD-028's attested cluster.

import (
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest/crossslot"
)

func TestGkmRedisCallsPassTheCrossslotLint(t *testing.T) {
	findings, err := crossslot.Check(".", ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		t.Errorf("CROSSSLOT: %s", finding)
	}
	// the family's key is all one tag, so every key of one group shares a slot and two groups' never need to
	key := GkmAckRedisKey(testId("group-g"))
	if !strings.HasPrefix(key, "{gka_") || !strings.HasSuffix(key, "}") || !sidecar.RedisKeysShareTag([]string{key, GkmAckRedisKey(testId("group-g"))}) {
		t.Fatalf("{gka_}'s key %q is not one hash tag", key)
	}
	if sidecar.RedisKeysShareTag([]string{key, GkmAckRedisKey(testId("group-h"))}) {
		t.Fatal("two groups' acks share a tag")
	}
}
