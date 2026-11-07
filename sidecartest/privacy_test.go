package sidecartest

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"mime/quotedprintable"
	"net/url"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

type contextForTest = context.Context

// The self-test §22.7 asks of the scan: each form a leak can take, planted, is found.
func TestScanFindsEveryEncodingOfACanary(t *testing.T) {
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
		writer, _ := flate.NewWriter(&out, flate.DefaultCompression)
		writer.Write(body)
		writer.Close()
		return out.Bytes()
	}
	quoted := func(body []byte) []byte {
		var out bytes.Buffer
		writer := quotedprintable.NewWriter(&out)
		writer.Binary = true
		writer.Write(body)
		writer.Close()
		return out.Bytes()
	}
	utf16Bytes := func(text string) []byte {
		out := []byte{}
		for _, unit := range utf16.Encode([]rune(text)) {
			out = append(out, byte(unit), byte(unit>>8))
		}
		return out
	}
	forms := []struct {
		name string
		make func(body []byte, text string) []byte
	}{
		{name: "raw bytes", make: func(body []byte, text string) []byte { return body }},
		{name: "raw text", make: func(body []byte, text string) []byte { return []byte(text) }},
		{name: "hex of the bytes", make: func(body []byte, text string) []byte { return []byte(strings.ToUpper(hex.EncodeToString(body))) }},
		{name: "base64", make: func(body []byte, text string) []byte { return []byte(base64.StdEncoding.EncodeToString(body)) }},
		{name: "base64 shifted one byte", make: func(body []byte, text string) []byte {
			return []byte(base64.StdEncoding.EncodeToString(append([]byte("x"), body...)))
		}},
		{name: "base64 shifted two bytes", make: func(body []byte, text string) []byte {
			return []byte(base64.StdEncoding.EncodeToString(append([]byte("xy"), body...)))
		}},
		{name: "base64url", make: func(body []byte, text string) []byte { return []byte(base64.RawURLEncoding.EncodeToString(body)) }},
		{name: "base32", make: func(body []byte, text string) []byte { return []byte(base32.StdEncoding.EncodeToString(body)) }},
		{name: "base32 shifted", make: func(body []byte, text string) []byte {
			return []byte(base32.StdEncoding.EncodeToString(append([]byte("xyz"), body...)))
		}},
		{name: "quoted-printable with soft breaks", make: func(body []byte, text string) []byte { return quoted(body) }},
		{name: "percent", make: func(body []byte, text string) []byte { return []byte(url.QueryEscape(string(body))) }},
		{name: "utf-16 text", make: func(body []byte, text string) []byte { return utf16Bytes(text) }},
		{name: "gzip", make: func(body []byte, text string) []byte { return gzipped(body) }},
		{name: "zlib", make: func(body []byte, text string) []byte { return zlibbed(body) }},
		{name: "deflate", make: func(body []byte, text string) []byte { return deflated(body) }},
	}
	for _, form := range forms {
		capture := NewPrivacyCapture()
		text := capture.Canary("field")
		body, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		leaked := append([]byte("prefix "), form.make(body, text)...)
		leaked = append(leaked, []byte(" suffix")...)
		if strings.HasPrefix(form.name, "gzip") || form.name == "zlib" || form.name == "deflate" {
			leaked = form.make(body, text)
		}
		capture.AddItem(&PrivacyItem{Class: "CC4", Name: "log", Body: leaked})
		if hits := capture.Scan(); len(hits) == 0 {
			t.Errorf("%s: not found", form.name)
		}
	}
}

func TestScanFindsAHookedKey(t *testing.T) {
	capture := NewPrivacyCapture()
	key := []byte("synthetic-key-bytes-for-this-test")
	capture.AddSecret("K_test", key)
	capture.AddItem(&PrivacyItem{Class: "CC4", Name: "log", Body: []byte(base64.StdEncoding.EncodeToString(key))})
	hits := capture.Scan()
	if len(hits) == 0 || hits[0].Needle != "K_test" {
		t.Errorf("hits %v", hits)
	}
}

func TestScanFindsNothingWhereNothingLeaked(t *testing.T) {
	capture := NewPrivacyCapture()
	capture.Canary("field")
	capture.AddItem(&PrivacyItem{Class: "CC4", Name: "log", Body: []byte("an ordinary log line")})
	if hits := capture.Scan(); len(hits) != 0 {
		t.Errorf("hits %v", hits)
	}
}

func TestAHitNamesWhereItWas(t *testing.T) {
	capture := NewPrivacyCapture()
	text := capture.Canary("commit message")
	capture.AddItem(&PrivacyItem{Class: "CC3", Name: "redis {x}y", Body: []byte(text)})
	hits := capture.Scan()
	if len(hits) == 0 {
		t.Fatal("no hit")
	}
	line := hits[0].String()
	for _, want := range []string{"commit message", "CC3", "redis {x}y"} {
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
	}
	for index, leak := range leaks {
		// a label of its own, since an earlier leak stays in the store
		label := fmt.Sprintf("leak-%d", index)
		leak(net.Capture().Canary(label))
		found := false
		for _, hit := range net.Capture().Scan() {
			found = found || strings.HasPrefix(hit.Needle, label)
		}
		if !found {
			t.Errorf("leak %d: not found", index)
		}
	}
}
