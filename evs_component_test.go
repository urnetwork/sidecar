//go:build !sidecar_http

// The evs component routes a hint on evs:<repo_id> through its generation's queue to the client, refuses a topic
// that names no repo, and drops hints between generations.

package sidecar

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A hint reaches the client in the generation's queue, in order, and nothing does without a generation.
func TestEvsComponentRoutesHintsThroughItsQueue(t *testing.T) {
	test := newEvsTestClient(t, nil, newEvsTestStore(t))
	component := NewEvsComponent(test.client)
	repoId, refId := evsTestId("repo"), evsTestId("ref")
	delta, _ := proto.Marshal(&protocol.EvsHeadChanged{RefId: refId.Bytes(), Version: 9})
	if component.ReceiveHint(PushTopicEvs(repoId), 1, delta) {
		t.Errorf("a hint with no generation was taken")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := newSidecarComponentQueue(ctx, 4, 1024*1024, &sidecarQueueCounters{}, NewNoopLogger())
	defer queue.closeAndWait()
	env := &SidecarEnv{Ctx: ctx, queue: queue}
	if err := component.Attach(env); err != nil {
		t.Fatal(err)
	}
	if component.ReceiveHint("evs:not-an-id", 1, delta) || component.ReceiveHint(PushTopicCore, 1, delta) {
		t.Errorf("a topic that names no repo was taken")
	}
	if !component.ReceiveHint(PushTopicEvs(repoId), 2, delta) {
		t.Fatalf("the hint was dropped")
	}
	done := make(chan struct{})
	if !env.Enqueue(0, func(ctx context.Context) { close(done) }) {
		t.Fatal("the marker was dropped")
	}
	<-done
	if got := test.client.hintedVersion(repoId, refId); got != 9 {
		t.Errorf("hinted %d", got)
	}
}
