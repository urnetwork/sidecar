//go:build !js

// FuzzMailIndexSegment (MAIL-M7-06, §22.6's segment target): any bytes as an i/ segment, and as an f/ segment, are
// read totally, never a panic or an error from the view, and within a fixed multiple of their size; the writer's
// append onto them either closes them or leaves bytes that read with exactly one more record, the bytes read kept as
// they were (checkMailIndexSegment). The seeds in testdata/fuzz/FuzzMailIndexSegment/ hold writer-made segments, a
// newer writer's field, a record cut short and a lone tag. Off the js leg, whose Worker has no file system for go
// test's corpus reader; mail_view_test.go runs the in-code seeds there.

package sidecar

import (
	"testing"
)

func FuzzMailIndexSegment(f *testing.F) {
	for _, seed := range testMailIndexSegmentSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, segment []byte) {
		checkMailIndexSegment(t, segment)
	})
}
