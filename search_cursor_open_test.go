//go:build !ios_extension

package sidecar

import (
	"context"
	"testing"
)

// The cursor a search just opened is never the one its session's count drops, though on a clock that has not moved
// every cursor of the session was used at the same instant: past Search.SessionCursorCount an older one goes, so no
// search answers cursor_expired at its first page. The daemon's own session, which takes no rate token, opens them
// as Sidecar.Search does. Before the fix the drop sorted the session's cursors, the new one
// among them, by their last use alone, and with every use tied any of them, the new one too, could be the one dropped:
// over 300 opens on a standing clock the chance that it never was is below one in ten million, so the old code fails
// this, and the fixed code passes it on every run.
func TestASessionsNewestCursorIsNeverTheOneDropped(t *testing.T) {
	world := newTestEngineWorld(t, nil, testEngineDocument(t, "doc", 1, 1, "notes/a.md", "harbor a"))
	session := searchLocalSession
	count := world.engine.args.Settings.SessionCursorCount
	tokens := []string{}
	for index := range 300 {
		stream, token, err := world.engine.SearchIn(context.Background(), session, &SearchRequest{Text: "harbor"})
		if err != nil {
			t.Fatalf("search %d: %v", index, err)
		}
		if _, _, _, err := stream.Next(); err != nil {
			t.Fatalf("search %d's first page: %v", index, err)
		}
		tokens = append(tokens, token)
	}
	live := 0
	for _, token := range tokens {
		if _, err := world.engine.Resume(session, token); err == nil {
			live += 1
		}
	}
	if live != count {
		t.Errorf("the session holds %d live cursors, not its %d", live, count)
	}
	if _, err := world.engine.Resume(session, tokens[len(tokens)-1]); err != nil {
		t.Errorf("the newest cursor: %v", err)
	}
}
