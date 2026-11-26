//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// The api refused once it gave the index: every chunk comes from the hub by its range, each redirected to the hub's
// CDN and checked against the same index, a chunk the CDN altered fetched again, and the file whole.
func TestModelDownloadFallbackRangesFromHub(t *testing.T) {
	world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	world.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		switch {
		case asked == "api index":
			world.apiRefused.Store(true)
		case strings.HasPrefix(asked, "hub chunk "):
			return testInferDownloadRedirectCdn
		case asked == "cdn chunk 3" && attempt == 1:
			return testInferDownloadAlter
		}
		return testInferDownloadServe
	})
	download := world.newDownload(t, world.directory)
	sources := map[InferModelDownloadSource]int{}
	file, err := download.Fetch(context.Background(), world.file, func(progress *InferModelDownloadProgress) {
		sources[progress.Source] += 1
	})
	if err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	if len(world.chunkCounts("api")) != 0 {
		t.Fatalf("the api, refused, served %v", world.chunkCounts("api"))
	}
	cdn := world.chunkCounts("cdn")
	hub := world.chunkCounts("hub")
	for n := 0; n <= 10; n += 1 {
		want := 1
		if n == 3 {
			want = 2
		}
		if cdn[n] != want || hub[n] != want {
			t.Errorf("chunk %d: the hub asked %d times, its CDN %d, not %d", n, hub[n], cdn[n], want)
		}
	}
	if sources[InferModelDownloadSourceHub] == 0 {
		t.Fatalf("the progress never named the hub: %v", sources)
	}
	// each request asked exactly its chunk's range
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	for _, request := range world.requests {
		if request.server == "api" {
			continue
		}
		start, end, ok := testInferParseRange(request.header.Get("Range"))
		chunk, inIndex := world.index.Chunk(int(start / 1024))
		if !ok || !inIndex || chunk.Offset != start || chunk.Offset+chunk.ByteCount-1 != end {
			t.Errorf("a request to the %s asked %q", request.server, request.header.Get("Range"))
		}
	}
}

// The hub answering a range with the whole file, a 200, is refused, the file never read, and the download stops
// with download_unavailable, no chunk of it marked done.
func TestModelDownloadFallbackRefusesWholeAnswer(t *testing.T) {
	world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	world.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		switch {
		case asked == "api index":
			world.apiRefused.Store(true)
		case strings.HasPrefix(asked, "hub chunk "):
			return testInferDownloadWhole
		}
		return testInferDownloadServe
	})
	download := world.newDownload(t, world.directory)
	if _, err := download.Fetch(context.Background(), world.file, nil); !errors.Is(err, ErrInferDownloadUnavailable) {
		t.Fatalf("a whole answer to a range answered %v", err)
	}
	if done := world.doneChunks(t, world.directory); len(done) != 0 {
		t.Fatalf("chunks %v were marked from a whole answer", done)
	}
}

// The hub answering another range than the one asked is refused, never cut to fit.
func TestModelDownloadFallbackRefusesOtherRange(t *testing.T) {
	world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	world.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		switch {
		case asked == "api index":
			world.apiRefused.Store(true)
		case strings.HasPrefix(asked, "hub chunk "):
			return testInferDownloadOtherRange
		}
		return testInferDownloadServe
	})
	download := world.newDownload(t, world.directory)
	if _, err := download.Fetch(context.Background(), world.file, nil); !errors.Is(err, ErrInferDownloadUnavailable) {
		t.Fatalf("another range answered %v", err)
	}
	if done := world.doneChunks(t, world.directory); len(done) != 0 {
		t.Fatalf("chunks %v were marked from another range", done)
	}
}

// A redirect off the hub's hosts is refused, the host never asked; one past ModelHubRedirectMaxCount likewise.
func TestModelDownloadFallbackRefusesRedirectOffHub(t *testing.T) {
	world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	world.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		switch {
		case asked == "api index":
			world.apiRefused.Store(true)
		case strings.HasPrefix(asked, "hub chunk "):
			return testInferDownloadRedirectOther
		}
		return testInferDownloadServe
	})
	download := world.newDownload(t, world.directory)
	if _, err := download.Fetch(context.Background(), world.file, nil); !errors.Is(err, ErrInferDownloadUnavailable) {
		t.Fatalf("a redirect off the hub answered %v", err)
	}
	if other := world.chunkCounts("other"); len(other) != 0 {
		t.Fatalf("the host off the hub was asked %v", other)
	}

	// the hub to its CDN and back, past a bound of one
	bounded := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	bounded.settings.ModelHubRedirectMaxCount = 0
	bounded.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		switch {
		case asked == "api index":
			bounded.apiRefused.Store(true)
		case strings.HasPrefix(asked, "hub chunk "):
			return testInferDownloadRedirectCdn
		}
		return testInferDownloadServe
	})
	download = bounded.newDownload(t, bounded.directory)
	if _, err := download.Fetch(context.Background(), bounded.file, nil); !errors.Is(err, ErrInferDownloadUnavailable) {
		t.Fatalf("a redirect past its bound answered %v", err)
	}
	if cdn := bounded.chunkCounts("cdn"); len(cdn) != 0 {
		t.Fatalf("a redirect past its bound reached the CDN: %v", cdn)
	}
}

// While the chunks come from the hub, the api is asked again before each chunk, and the chunks go back to it once it
// answers.
func TestModelDownloadFallbackReturnsToApi(t *testing.T) {
	world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	world.settings.ModelChunkFetchConcurrency = 1
	world.settings.ModelApiProbeInterval = 0
	world.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		switch asked {
		case "api chunk 1":
			world.apiRefused.Store(true)
		case "hub chunk 4":
			world.apiRefused.Store(false)
		}
		return testInferDownloadServe
	})
	download := world.newDownload(t, world.directory)
	file, err := download.Fetch(context.Background(), world.file, nil)
	if err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	api, apiOnce := testInferAskedOnce(world.chunkCounts("api"))
	hub, hubOnce := testInferAskedOnce(world.chunkCounts("hub"))
	if !slices.Equal(api, []int{0, 1, 5, 6, 7, 8, 9, 10}) || !slices.Equal(hub, []int{2, 3, 4}) || !apiOnce || !hubOnce {
		t.Fatalf("the api served %v, the hub %v", world.chunkCounts("api"), world.chunkCounts("hub"))
	}
	if world.countOf("api probe") != 1 {
		t.Fatalf("the api answered %d probes", world.countOf("api probe"))
	}
}

// ModelApiUnreachableCount 5xx answers in a row move a chunk to the hub; any answer of the api's would have started the
// count again.
func TestModelDownloadFallbackAfterUnansweredCount(t *testing.T) {
	world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	world.settings.ModelChunkFetchConcurrency = 1
	world.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		if asked == "api chunk 3" {
			return testInferDownloadUnavailable
		}
		return testInferDownloadServe
	})
	download := world.newDownload(t, world.directory)
	file, err := download.Fetch(context.Background(), world.file, nil)
	if err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	if count := world.countOf("api chunk 3"); count != world.settings.ModelApiUnreachableCount {
		t.Fatalf("the api was asked for chunk 3 %d times, not %d", count, world.settings.ModelApiUnreachableCount)
	}
	// the probe waits an hour, so the rest comes from the hub
	if hub, once := testInferAskedOnce(world.chunkCounts("hub")); !slices.Equal(hub, testInferRange(3, 10)) || !once {
		t.Fatalf("the hub served %v", world.chunkCounts("hub"))
	}
}

// With the fallback off, or a manifest url that is not https, an api that cannot be reached stops the download with
// download_unavailable and the hub is never asked; a hub that fails ModelHubFailureMaxCount times in a row stops it too.
func TestModelDownloadNoFallbackStops(t *testing.T) {
	for _, change := range []func(world *testInferDownloadWorld){
		func(world *testInferDownloadWorld) { world.settings.ModelHubFallback = false },
		func(world *testInferDownloadWorld) { world.file.Url = "http://hub.example" + testInferHubPath },
	} {
		world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
		change(world)
		world.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
			if asked == "api index" {
				world.apiRefused.Store(true)
			}
			return testInferDownloadServe
		})
		download := world.newDownload(t, world.directory)
		if _, err := download.Fetch(context.Background(), world.file, nil); !errors.Is(err, ErrInferDownloadUnavailable) {
			t.Fatalf("an api that cannot be reached, with no fallback, answered %v", err)
		}
		if hub := world.chunkCounts("hub"); len(hub) != 0 {
			t.Fatalf("the hub was asked %v", hub)
		}
	}

	failing := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	failing.settings.ModelChunkFetchConcurrency = 1
	failing.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		switch {
		case asked == "api index":
			failing.apiRefused.Store(true)
		case strings.HasPrefix(asked, "hub chunk "):
			return testInferDownloadUnavailable
		}
		return testInferDownloadServe
	})
	download := failing.newDownload(t, failing.directory)
	if _, err := download.Fetch(context.Background(), failing.file, nil); !errors.Is(err, ErrInferDownloadUnavailable) {
		t.Fatalf("a hub that fails answered %v", err)
	}
	if count := failing.countOf("hub chunk 0"); count != failing.settings.ModelHubFailureMaxCount {
		t.Fatalf("the hub was asked %d times, not %d", count, failing.settings.ModelHubFailureMaxCount)
	}
}

// A hub request may go to the manifest url's own host and to a host under a suffix, https alone; never to another
// host, to http, or with a user.
func TestModelDownloadHubHostAllowed(t *testing.T) {
	hubUrl, err := url.Parse("https://hub.example" + testInferHubPath)
	if err != nil {
		t.Fatal(err)
	}
	suffixes := []string{"cdn.example", ".hf.example."}
	for target, allowed := range map[string]bool{
		"https://hub.example/a":                  true,
		"https://HUB.example./a":                 true,
		"https://cdn.example/a":                  true,
		"https://us-1.cdn.example/a":             true,
		"https://bridge.xet.hf.example/a":        true,
		"https://hf.example:8443/a":              true,
		"https://notcdn.example/a":               false,
		"https://cdn.example.attacker.example/a": false,
		"https://other.example/a":                false,
		"http://cdn.example/a":                   false,
		"https://user@cdn.example/a":             false,
		"https:///a":                             false,
	} {
		parsed, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		if got := inferDownloadHubHostAllowed(parsed, hubUrl, suffixes); got != allowed {
			t.Errorf("%s: allowed %v, not %v", target, got, allowed)
		}
	}
}

// A Content-Range is the range asked only when its start, end and total are, the total unknown allowed.
func TestModelDownloadContentRangeIsExact(t *testing.T) {
	for value, want := range map[string]bool{
		"bytes 1024-2047/10540":  true,
		"bytes 1024-2047/*":      true,
		"bytes 1024-2046/10540":  false,
		"bytes 1023-2047/10540":  false,
		"bytes 1024-2047/10541":  false,
		"bytes 01024-2047/10540": false,
		"bytes 1024-2047":        false,
		"bytes=1024-2047/10540":  false,
		"bytes -1024-2047/10540": false,
		"":                       false,
		"bytes 1024-2047/1e4":    false,
	} {
		if got := inferDownloadContentRangeIs(value, 1024, 2047, 10540); got != want {
			t.Errorf("%q: %v, not %v", value, got, want)
		}
	}
}

// An api that answers its probe and fails every chunk, with a hub that fails too, stops the download: the chunk moved
// to the hub stays there, the api asked again only before a chunk's first request, until the hub has failed
// ModelHubFailureMaxCount times in a row.
func TestModelDownloadFallbackStopsWhenBothFail(t *testing.T) {
	world := newTestInferDownloadWorld(t, 4*1024+10, 1024)
	world.settings.ModelChunkFetchConcurrency = 1
	world.settings.ModelApiProbeInterval = 0
	world.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		if strings.HasPrefix(asked, "api chunk ") || strings.HasPrefix(asked, "hub chunk ") {
			return testInferDownloadUnavailable
		}
		return testInferDownloadServe
	})
	download := world.newDownload(t, world.directory)
	if _, err := download.Fetch(context.Background(), world.file, nil); !errors.Is(err, ErrInferDownloadUnavailable) {
		t.Fatalf("an api and a hub that both fail answered %v", err)
	}
	hubFailureMaxCount := world.settings.ModelHubFailureMaxCount
	if count := world.countOf("hub chunk 0"); count != hubFailureMaxCount {
		t.Fatalf("the hub was asked %d times, not %d", count, hubFailureMaxCount)
	}
	if count := world.countOf("api chunk 0"); count != world.settings.ModelApiUnreachableCount {
		t.Fatalf("the api was asked %d times, not %d", count, world.settings.ModelApiUnreachableCount)
	}
}
