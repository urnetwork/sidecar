package sidecartest

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand/v2"
	"mime/quotedprintable"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"
	"unicode/utf16"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

// Deterministic filler, so a property run repeats.
func privacyFiller(seed uint64, byteCount int) []byte {
	random := rand.New(rand.NewChaCha8([32]byte{byte(seed), byte(seed >> 8)}))
	filler := make([]byte, byteCount)
	for index := range filler {
		// printable, so a text form is as embedded as in a log line
		filler[index] = byte(0x20 + random.IntN(0x5f))
	}
	return filler
}

func utf16Bytes(text string, bigEndian bool) []byte {
	out := []byte{}
	for _, unit := range utf16.Encode([]rune(text)) {
		if bigEndian {
			out = append(out, byte(unit>>8), byte(unit))
		} else {
			out = append(out, byte(unit), byte(unit>>8))
		}
	}
	return out
}

func wantFound(t *testing.T, findings []*PrivacyFinding, label string, form string, what string) {
	t.Helper()
	for _, finding := range findings {
		if finding.Needle == label && (form == "" || finding.Form == form) {
			return
		}
	}
	t.Errorf("%s: %s as %s not found in %v", what, label, form, findings)
}

// The self-test §22.7 asks of the scan, as a property: every form a canary's bytes or text can take,
// embedded at every offset of a log line, is found, and each finding says the form and where.
func TestScanFindsEveryFormOfACanaryAtEveryOffset(t *testing.T) {
	encodings := []struct {
		form   string
		encode func(body []byte, text string) []byte
	}{
		{form: "raw", encode: func(body []byte, text string) []byte { return body }},
		{form: "raw", encode: func(body []byte, text string) []byte { return []byte(text) }},
		{form: "raw", encode: func(body []byte, text string) []byte { return []byte(strings.ToUpper(text)) }},
		{form: "hex", encode: func(body []byte, text string) []byte { return []byte(hex.EncodeToString(body)) }},
		{form: "hex", encode: func(body []byte, text string) []byte { return []byte(strings.ToUpper(hex.EncodeToString(body))) }},
		{form: "hex", encode: func(body []byte, text string) []byte { return []byte(hex.EncodeToString([]byte(text))) }},
		{form: "base64", encode: func(body []byte, text string) []byte { return []byte(base64.StdEncoding.EncodeToString(body)) }},
		{form: "base64", encode: func(body []byte, text string) []byte { return []byte(base64.RawStdEncoding.EncodeToString(body)) }},
		{form: "base64", encode: func(body []byte, text string) []byte {
			return []byte(base64.StdEncoding.EncodeToString(append([]byte("x"), body...)))
		}},
		{form: "base64", encode: func(body []byte, text string) []byte {
			return []byte(base64.StdEncoding.EncodeToString(append([]byte("xy"), body...)))
		}},
		{form: "base64", encode: func(body []byte, text string) []byte { return []byte(base64.StdEncoding.EncodeToString([]byte(text))) }},
		{form: "base64url", encode: func(body []byte, text string) []byte { return []byte(base64.RawURLEncoding.EncodeToString(body)) }},
		{form: "base64url", encode: func(body []byte, text string) []byte {
			return []byte(base64.URLEncoding.EncodeToString(append([]byte("xy"), body...)))
		}},
		{form: "base32", encode: func(body []byte, text string) []byte { return []byte(base32.StdEncoding.EncodeToString(body)) }},
		{form: "base32", encode: func(body []byte, text string) []byte {
			return []byte(strings.ToLower(base32.StdEncoding.EncodeToString(append([]byte("x"), body...))))
		}},
		{form: "base32", encode: func(body []byte, text string) []byte {
			return []byte(base32.StdEncoding.EncodeToString(append([]byte("xy"), body...)))
		}},
		{form: "base32", encode: func(body []byte, text string) []byte {
			return []byte(base32.StdEncoding.EncodeToString(append([]byte("xyz"), body...)))
		}},
		{form: "base32", encode: func(body []byte, text string) []byte {
			return []byte(base32.StdEncoding.EncodeToString(append([]byte("wxyz"), body...)))
		}},
		{form: "base32hex", encode: func(body []byte, text string) []byte {
			return []byte(base32.HexEncoding.EncodeToString(append([]byte("wx"), body...)))
		}},
		{form: "percent", encode: func(body []byte, text string) []byte { return []byte(url.QueryEscape(string(body))) }},
		{form: "percent", encode: func(body []byte, text string) []byte { return []byte(url.PathEscape(string(body))) }},
		{form: "utf-16le", encode: func(body []byte, text string) []byte { return utf16Bytes(text, false) }},
		{form: "utf-16be", encode: func(body []byte, text string) []byte { return utf16Bytes(text, true) }},
	}
	capture := NewPrivacyCapture()
	text := capture.CanaryText("field")
	body, err := canaryTextEncoding.DecodeString(text)
	if err != nil || len(body) != canaryByteCount || len(text) != 52 {
		t.Fatalf("canary text %q: %v", text, err)
	}
	for index, encoding := range encodings {
		leaked := encoding.encode(body, text)
		for offset := 0; offset < 9; offset += 1 {
			filler := privacyFiller(uint64(index*16+offset), 40)
			line := append(append(bytes.Clone(filler[:offset]), leaked...), filler[offset:]...)
			found := NewPrivacyCapture()
			found.needles = capture.needles
			found.Add(PrivacyClassLog, "log", line)
			// two forms can be the same bytes, base64 and base64url where neither's own characters
			// fall, so a finding names one of them: what holds is that the needle is found in the span
			// it was planted in
			inSpan := false
			for _, finding := range found.Scan() {
				inSpan = inSpan || (finding.Needle == "field" && int64(offset) <= finding.Offset && finding.Offset < int64(offset+len(leaked)))
			}
			if !inSpan {
				t.Errorf("encoding %d (%s) at offset %d: not found in %q", index, encoding.form, offset, line)
			}
		}
	}
	// where a form is its own bytes alone, the finding names it
	for _, encoding := range encodings {
		if encoding.form != "hex" && encoding.form != "utf-16le" && encoding.form != "utf-16be" {
			continue
		}
		found := NewPrivacyCapture()
		found.needles = capture.needles
		found.Add(PrivacyClassLog, "log", encoding.encode(body, text))
		wantFound(t, found.Scan(), "field", encoding.form, encoding.form)
	}
	// a raw finding says where it was
	found := NewPrivacyCapture()
	found.needles = capture.needles
	found.Add(PrivacyClassRedis, "redis {x}y", append([]byte("0123456789"), text...))
	findings := found.Scan()
	if len(findings) != 1 || findings[0].Offset != 10 || findings[0].NeedleKind != "canary text" || findings[0].Class != PrivacyClassRedis {
		t.Errorf("%v", findings)
	}
}

// A stream read a byte at a time puts a chunk boundary inside the needle at every place it can fall.
func TestScanFindsANeedleAcrossAChunkBoundary(t *testing.T) {
	capture := NewPrivacyCapture()
	body := capture.Canary("contents")
	text := capture.CanaryText("path")
	haystack := append(append(append(privacyFiller(1, 100), body...), privacyFiller(2, 77)...), base64.StdEncoding.EncodeToString([]byte(text))...)
	haystack = append(haystack, privacyFiller(3, 3)...)
	for _, open := range []func() (io.ReadCloser, error){
		func() (io.ReadCloser, error) {
			return io.NopCloser(iotest.OneByteReader(bytes.NewReader(haystack))), nil
		},
		func() (io.ReadCloser, error) { return io.NopCloser(iotest.HalfReader(bytes.NewReader(haystack))), nil },
		func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(haystack)), nil },
	} {
		capture.items = nil
		capture.AddItem(&PrivacyItem{Class: PrivacyClassObject, Name: "object seg/a", Open: open})
		findings := capture.Scan()
		wantFound(t, findings, "contents", "raw", "stream")
		wantFound(t, findings, "path", "base64", "stream")
		for _, finding := range findings {
			if finding.Needle == "contents" && finding.Offset != 100 {
				t.Errorf("found at %d", finding.Offset)
			}
		}
	}
	// a stream past the view bound still scans whole, raw
	matcher := newPrivacyMatcher(capture.needles, nil)
	matcher.decode.MaxViewByteCount = 64
	hits := 0
	head, err := matcher.scanStream(iotest.OneByteReader(bytes.NewReader(haystack)), 64, func(pattern *privacyPattern, offset int64) { hits += 1 })
	if err != nil || head != nil || hits != 2 {
		t.Errorf("head %d bytes, %d hits, %v", len(head), hits, err)
	}
}

// Compressed and escaped, and nested: every view a body opens is scanned, and opened again.
func TestScanOpensEveryCompressionAndEscape(t *testing.T) {
	capture := NewPrivacyCapture()
	text := capture.CanaryText("subject")
	gzipped := func(body []byte) []byte {
		var out bytes.Buffer
		writer := gzip.NewWriter(&out)
		writer.Write(body)
		writer.Close()
		return out.Bytes()
	}
	zlibbed := func(body []byte) []byte {
		var out bytes.Buffer
		writer := zlib.NewWriter(&out)
		writer.Write(body)
		writer.Close()
		return out.Bytes()
	}
	deflated := func(body []byte) []byte {
		var out bytes.Buffer
		writer, _ := flate.NewWriter(&out, flate.BestCompression)
		writer.Write(body)
		writer.Close()
		return out.Bytes()
	}
	brotlied := func(body []byte) []byte {
		var out bytes.Buffer
		writer := brotli.NewWriter(&out)
		writer.Write(body)
		writer.Close()
		return out.Bytes()
	}
	zstded := func(body []byte) []byte {
		encoder, err := zstd.NewWriter(nil)
		if err != nil {
			t.Fatal(err)
		}
		defer encoder.Close()
		return encoder.EncodeAll(body, nil)
	}
	quoted := func(body []byte) []byte {
		var out bytes.Buffer
		writer := quotedprintable.NewWriter(&out)
		writer.Binary = true
		writer.Write(body)
		writer.Close()
		return out.Bytes()
	}
	line := func(leak []byte) []byte {
		return append(append([]byte("From: someone@example.test\r\nSubject: "), leak...), []byte("\r\n\r\nbody text")...)
	}
	base64Text := []byte(base64.StdEncoding.EncodeToString([]byte(text)))
	// a soft break inside the value: a line long enough that the writer breaks within the canary
	softBroken := quoted(append(bytes.Repeat([]byte("q"), 60), []byte(text+" é")...))
	if !bytes.Contains(softBroken, []byte("=\r\n")) {
		t.Fatalf("no soft break in %q", softBroken)
	}
	for _, planted := range []struct {
		body []byte
		view string
		form string
	}{
		{body: gzipped(line(base64Text)), view: "gzip", form: "base64"},
		{body: zlibbed(line([]byte(text))), view: "zlib", form: "raw"},
		{body: deflated(line([]byte(text))), view: "deflate", form: "raw"},
		{body: brotlied(line([]byte(text))), view: "brotli", form: "raw"},
		{body: zstded(line([]byte(text))), view: "zstd", form: "raw"},
		{body: softBroken, view: "quoted-printable", form: "raw"},
		{body: []byte("q=" + url.QueryEscape(text+"/"+text)), view: "", form: "raw"},
		{body: gzipped(softBroken), view: "gzip > quoted-printable", form: "raw"},
		{body: zstded(gzipped(line(base64Text))), view: "zstd > gzip", form: "base64"},
	} {
		found := NewPrivacyCapture()
		found.needles = capture.needles
		found.Add(PrivacyClassLog, "log", planted.body)
		findings := found.Scan()
		ok := false
		for _, finding := range findings {
			ok = ok || (finding.View == planted.view && finding.Form == planted.form)
		}
		if !ok {
			t.Errorf("%s as %s: %v", planted.view, planted.form, findings)
		}
	}
}

// 256 MiB of random bytes, streamed, hold no canary, key or value: the forms are long enough that
// nothing turns up by chance.
func TestScanFindsNothingInRandomBytes(t *testing.T) {
	if testing.Short() {
		t.Skip("256 MiB")
	}
	capture := NewPrivacyCapture()
	capture.Canary("contents")
	capture.CanaryText("path")
	capture.CanaryText("query")
	capture.AddSecret("K_test", []byte("synthetic-key-bytes-of-a-test"))
	capture.Forbid("address", []byte("198.51.100.23"))
	random := rand.NewChaCha8([32]byte{0x5c})
	const byteCount = 256 * 1024 * 1024
	capture.AddItem(&PrivacyItem{Class: PrivacyClassObject, Name: "object seg/random", Open: func() (io.ReadCloser, error) {
		return io.NopCloser(io.LimitReader(random, byteCount)), nil
	}})
	if findings := capture.Scan(); len(findings) != 0 {
		t.Errorf("%v", findings)
	}
}

// A declared value passes only in the class of the row that declares it, and only while §2.8's list
// holds that row live.
func TestDeclaredValuesPassOnlyWithTheirRow(t *testing.T) {
	capture := NewPrivacyCapture()
	serverName := capture.CanaryText("sni")
	capture.Add(PrivacyClassHandler, "tlsedge hello", []byte(serverName))
	capture.Add(PrivacyClassLog, "log", []byte(serverName))
	if err := capture.Declare("tls-1", "sni", PrivacyClassHandler); err != nil {
		t.Fatal(err)
	}
	findings := capture.Scan()
	if len(findings) != 1 || findings[0].Class != PrivacyClassLog {
		t.Errorf("%v", findings)
	}
	for _, planted := range []struct {
		rowId string
		class PrivacyClass
		want  string
	}{
		{rowId: "tls-999", class: PrivacyClassLog, want: "no such row"},
		{rowId: "api-12", class: PrivacyClassLog, want: "withdrawn"},
		{rowId: "tls-1", class: "CC9/elsewhere", want: "no capture class"},
	} {
		if err := capture.Declare(planted.rowId, "sni", planted.class); err == nil || !strings.Contains(err.Error(), planted.want) {
			t.Errorf("%s: %v", planted.rowId, err)
		}
	}
	// the failed declarations declared nothing
	if findings := capture.Scan(); len(findings) != 1 {
		t.Errorf("%v", findings)
	}
}

// A secret too short to look for is a finding, never dropped, and so is a forbidden value too short.
func TestAShortSecretIsRefusedLoudly(t *testing.T) {
	capture := NewPrivacyCapture()
	capture.AddSecret("nonce", []byte("fifteen bytes!!"))
	capture.Forbid("port", []byte("5671"))
	capture.AddSecret("K_ok", []byte("sixteen bytes!!!"))
	findings := capture.Scan()
	if len(findings) != 2 {
		t.Fatalf("%v", findings)
	}
	for index, want := range []string{"nonce", "port"} {
		if findings[index].NeedleKind != "refused" || findings[index].Needle != want || !strings.Contains(findings[index].String(), "under") {
			t.Errorf("%v", findings[index])
		}
	}
}

// A forbidden value under 16 bytes is looked for raw, upper or lower case, and not encoded.
func TestAShortForbiddenValueIsLookedForRaw(t *testing.T) {
	capture := NewPrivacyCapture()
	capture.Forbid("address", []byte("2001:DB8:1"))
	capture.Add(PrivacyClassLog, "log", []byte("dial 2001:db8:1::25 refused"))
	capture.Add(PrivacyClassLog, "log", []byte(base64.StdEncoding.EncodeToString([]byte("2001:db8:1"))))
	findings := capture.Scan()
	if len(findings) != 1 || findings[0].Form != "raw" || findings[0].Offset != 5 {
		t.Errorf("%v", findings)
	}
}

// mx-4's listener input is §2.8's one exception: its class is never read, and the same bytes anywhere
// else are a finding.
func TestMx4InputIsNeverScanned(t *testing.T) {
	capture := NewPrivacyCapture()
	body := capture.CanaryText("report body")
	capture.Add(PrivacyClassMx4Input, "rpt listener", []byte(body))
	if findings := capture.Scan(); len(findings) != 0 {
		t.Errorf("%v", findings)
	}
	capture.Add(PrivacyClassHandler, "mxedge", []byte(body))
	if findings := capture.Scan(); len(findings) != 1 || findings[0].Class != PrivacyClassHandler {
		t.Errorf("%v", findings)
	}
}

func TestScanFindsAHookedKey(t *testing.T) {
	capture := NewPrivacyCapture()
	key := []byte("synthetic-key-bytes-for-this-test")
	capture.AddSecret("K_test", key)
	capture.Add("CC4", "log", []byte(base64.StdEncoding.EncodeToString(key)))
	findings := capture.Scan()
	if len(findings) == 0 || findings[0].Needle != "K_test" || findings[0].NeedleKind != "secret" {
		t.Errorf("findings %v", findings)
	}
}

func TestScanFindsNothingWhereNothingLeaked(t *testing.T) {
	capture := NewPrivacyCapture()
	capture.Canary("field")
	capture.CanaryText("name")
	capture.Add(PrivacyClassLog, "log", []byte("an ordinary log line"))
	if findings := capture.Scan(); len(findings) != 0 {
		t.Errorf("findings %v", findings)
	}
}

func TestAFindingNamesWhereItWas(t *testing.T) {
	capture := NewPrivacyCapture()
	text := capture.CanaryText("commit message")
	capture.Add(PrivacyClassRedis, "redis {x}y", []byte(text))
	findings := capture.Scan()
	if len(findings) == 0 {
		t.Fatal("no finding")
	}
	line := findings[0].String()
	for _, want := range []string{"commit message", "CC3/redis", "redis {x}y", "at 0", "as raw"} {
		if !strings.Contains(line, want) {
			t.Errorf("%q lacks %q", line, want)
		}
	}
}

// Every class the fakes hold is in the scan, so a leak through a store fails the run.
func TestScanReadsEveryFakeStore(t *testing.T) {
	net := newTestNet(t)
	ctx := t.Context()
	leaks := []func(canary string){
		func(canary string) { net.Fakes().Redis.Set(ctx, "{a}"+canary, []byte("value"), 0) },
		func(canary string) { net.Fakes().Redis.Set(ctx, "{a}k", []byte(canary), 0) },
		func(canary string) { net.Fakes().Redis.HashSet(ctx, "{a}h", map[string][]byte{"f": []byte(canary)}) },
		func(canary string) {
			net.Fakes().Redis.StreamAdd(ctx, "{a}s", 0, map[string][]byte{"f": []byte(canary)})
		},
		func(canary string) {
			cluster, _ := net.Fakes().Blobs.FirstCluster()
			cluster.PutIfNoneMatch(ctx, "head/a/_", []byte(canary), nil)
		},
		func(canary string) {
			cluster, _ := net.Fakes().Blobs.SegmentCluster()
			cluster.PutIfNoneMatch(ctx, "seg/"+canary+"/_", []byte("sealed"), nil)
		},
		func(canary string) {
			cluster, _ := net.Fakes().Blobs.FirstCluster()
			cluster.PutIfNoneMatch(ctx, "idx/a.e", []byte("x"), &sidecar.BlobPutOptions{Metadata: map[string]string{"state": canary}})
		},
		func(canary string) {
			net.Fakes().Metrics.Counter("urnetwork_evs_total", "help", "code").Add(1, canary)
		},
		func(canary string) {
			net.Fakes().Push.Hint(ctx, []connect.Id{connect.NewId()}, &sidecar.ClientHint{Topic: "core", Body: []byte(canary)})
		},
		func(canary string) {
			net.Fakes().Quota.ReportUsage(ctx, &sidecar.UsageBatch{
				BatchId:  connect.NewId(),
				Producer: "evs",
				Events:   []*sidecar.UsageEvent{{NetworkId: connect.NewId(), Meter: canary}},
			})
		},
		func(canary string) {
			net.Fakes().Tasks.Schedule(ctx, &sidecar.TaskRequest{Name: "job", OnceKey: "once", Args: []byte(canary)})
		},
		func(canary string) {
			net.Fakes().Tasks.Schedule(ctx, &sidecar.TaskRequest{Name: "job", OnceKey: canary})
		},
	}
	for index, leak := range leaks {
		// a kind of its own, since an earlier leak stays in the store
		kind := fmt.Sprintf("leak-%d", index)
		leak(net.Capture().CanaryText(kind))
		found := false
		for _, finding := range net.Capture().Scan() {
			found = found || finding.Needle == kind
		}
		if !found {
			t.Errorf("leak %d: not found", index)
		}
	}
}

func benchmarkPrivacyScan(b *testing.B, byteCount int) {
	capture := NewPrivacyCapture()
	for index := range 8 {
		capture.CanaryText(fmt.Sprintf("field %d", index))
	}
	capture.AddSecret("K_test", []byte("synthetic-key-bytes-of-a-bench"))
	matcher := newPrivacyMatcher(capture.needles, nil)
	random := rand.New(rand.NewChaCha8([32]byte{0xbe}))
	body := make([]byte, byteCount)
	for index := range body {
		body[index] = byte(random.Uint32())
	}
	b.SetBytes(int64(byteCount))
	b.ResetTimer()
	for range b.N {
		matcher.scanRange(body, 0, len(body), func(pattern *privacyPattern, offset int) {
			b.Fatal("a hit in random bytes")
		})
	}
}

// The scan's cost per byte, which the three sizes hold equal: linear in bytes with the patterns fixed.
func BenchmarkPrivacyScan1MiB(b *testing.B) {
	benchmarkPrivacyScan(b, 1024*1024)
}

func BenchmarkPrivacyScan16MiB(b *testing.B) {
	benchmarkPrivacyScan(b, 16*1024*1024)
}

func BenchmarkPrivacyScan64MiB(b *testing.B) {
	benchmarkPrivacyScan(b, 64*1024*1024)
}

// A stream is opened where it starts: gzip, zstd and zlib's usual headers anywhere in a body, a zlib,
// deflate or brotli stream at the body's start or after a NUL, the fakes' field separator. A deflate or
// brotli stream inside text is not opened, which the self-test's Embeds names.
func TestScanOpensAStreamWhereItStarts(t *testing.T) {
	capture := NewPrivacyCapture()
	text := capture.CanaryText("value")
	// compressible, so no stored copy of the text is found by luck
	payload := []byte(strings.Repeat(text, 3))
	compressed := func(write func(out *bytes.Buffer)) []byte {
		var out bytes.Buffer
		write(&out)
		return out.Bytes()
	}
	gzipped := compressed(func(out *bytes.Buffer) {
		writer := gzip.NewWriter(out)
		writer.Write(payload)
		writer.Close()
	})
	zlibbed := compressed(func(out *bytes.Buffer) {
		writer := zlib.NewWriter(out)
		writer.Write(payload)
		writer.Close()
	})
	deflated := compressed(func(out *bytes.Buffer) {
		writer, _ := flate.NewWriter(out, flate.BestCompression)
		writer.Write(payload)
		writer.Close()
	})
	brotlied := compressed(func(out *bytes.Buffer) {
		writer := brotli.NewWriter(out)
		writer.Write(payload)
		writer.Close()
	})
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	zstded := encoder.EncodeAll(payload, nil)
	encoder.Close()
	if bytes.Contains(gzipped, []byte(text)) || bytes.Contains(deflated, []byte(text[:16])) {
		t.Fatal("the stream holds the text as it is")
	}
	inText := func(stream []byte) []byte {
		return append(append([]byte("level=info msg=push body="), stream...), []byte(" done")...)
	}
	afterNul := func(stream []byte) []byte {
		return append([]byte("{evs}key\x00"), stream...)
	}
	for _, planted := range []struct {
		name  string
		body  []byte
		view  string
		found bool
	}{
		{name: "gzip in text", body: inText(gzipped), view: "gzip", found: true},
		{name: "zstd in text", body: inText(zstded), view: "zstd", found: true},
		{name: "zlib in text", body: inText(zlibbed), view: "zlib", found: true},
		{name: "deflate after a NUL", body: afterNul(deflated), view: "deflate", found: true},
		{name: "brotli after a NUL", body: afterNul(brotlied), view: "brotli", found: true},
		{name: "deflate in text", body: inText(deflated), found: false},
		{name: "brotli in text", body: inText(brotlied), found: false},
	} {
		found := NewPrivacyCapture()
		found.needles = capture.needles
		found.Add(PrivacyClassLog, "log", planted.body)
		findings := found.Scan()
		opened := false
		for _, finding := range findings {
			opened = opened || finding.View == planted.view
		}
		if planted.found && !opened {
			t.Errorf("%s: %v", planted.name, findings)
		}
		if !planted.found && len(findings) != 0 {
			t.Errorf("%s was opened, so the self-test's Embeds is out of date: %v", planted.name, findings)
		}
	}
}
