//go:build !js && !ios_extension

// R4's fuzz target (DESIGN-DETAILS 11.6; SEARCH-M10-44): for any input and any split of it into writes, the one-pass
// form's documents, key sets and rows equal the whole-value form's, as mail and as a file. Seeds are every conformance
// vector under 64 KiB, each split by the seed that comes with it.

package sidecar

import (
	"math/rand"
	"testing"
)

func FuzzIndexExtractStreamEqualsWhole(f *testing.F) {
	for index, seed := range testConformanceSeeds(f) {
		if len(seed) <= 64*1024 {
			f.Add(seed, int64(index), uint8(index))
		}
	}
	f.Fuzz(func(t *testing.T, content []byte, seed int64, shape uint8) {
		random := rand.New(rand.NewSource(seed))
		settings := DefaultIndexFormatSettings()
		if shape%2 == 1 {
			// small chunks, so documents and their overlaps meet every stage
			settings.ChunkByteCount = 8 + random.Intn(200)
			settings.OverlapByteCount = random.Intn(settings.ChunkByteCount)
		}
		settings.ExtractReadByteCount = 1 + random.Intn(64)
		limit := 1 + int(shape)
		cut := func(remaining int) int {
			return 1 + random.Intn(limit)
		}
		path := []byte("m/202611/00/1")
		whole, _ := testIndexWholeDocuments(t, true, path, content, settings)
		for _, difference := range testIndexStreamDifferences(t, whole, testIndexStreamMail(t, path, content, settings, cut)) {
			t.Errorf("mail: %s", difference)
		}
		filePath := []byte("notes/fuzz.md")
		wholeFile, wholeOk := testIndexWholeDocuments(t, false, filePath, content, settings)
		streamFile, streamOk := testIndexStreamFile(t, filePath, content, settings)
		if wholeOk != streamOk {
			t.Fatalf("file: text %v, whole %v", streamOk, wholeOk)
		}
		for _, difference := range testIndexStreamDifferences(t, wholeFile, streamFile) {
			t.Errorf("file: %s", difference)
		}
	})
}
