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
	"mime/quotedprintable"
	"net/url"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// The forms a leak takes, written here apart from the scanner's own list, so the self-test does not
// share what it tests.
func leakEncodings(t testing.TB) []struct {
	name   string
	encode func(body []byte, text string) []byte
} {
	// the text three times over, so the stream compresses and holds no stored copy of it to find by luck
	compress := func(newWriter func(out *bytes.Buffer) io.WriteCloser) func(body []byte, text string) []byte {
		return func(body []byte, text string) []byte {
			var out bytes.Buffer
			writer := newWriter(&out)
			writer.Write([]byte(strings.Repeat(text, 3)))
			writer.Close()
			return out.Bytes()
		}
	}
	shifted := func(encode func([]byte) string, shift int) func(body []byte, text string) []byte {
		return func(body []byte, text string) []byte {
			return []byte(encode(append(bytes.Repeat([]byte("s"), shift), body...)))
		}
	}
	return []struct {
		name   string
		encode func(body []byte, text string) []byte
	}{
		{name: "raw text", encode: func(body []byte, text string) []byte { return []byte(text) }},
		{name: "raw bytes", encode: func(body []byte, text string) []byte { return body }},
		{name: "hex", encode: func(body []byte, text string) []byte { return []byte(hex.EncodeToString(body)) }},
		{name: "upper-case hex", encode: func(body []byte, text string) []byte { return []byte(strings.ToUpper(hex.EncodeToString(body))) }},
		{name: "base64", encode: shifted(base64.StdEncoding.EncodeToString, 0)},
		{name: "base64 shifted 1", encode: shifted(base64.StdEncoding.EncodeToString, 1)},
		{name: "base64 shifted 2", encode: shifted(base64.StdEncoding.EncodeToString, 2)},
		{name: "base64url", encode: shifted(base64.RawURLEncoding.EncodeToString, 0)},
		{name: "base32", encode: shifted(base32.StdEncoding.EncodeToString, 0)},
		{name: "base32 shifted 1", encode: shifted(base32.StdEncoding.EncodeToString, 1)},
		{name: "base32 shifted 2", encode: shifted(base32.StdEncoding.EncodeToString, 2)},
		{name: "base32 shifted 3", encode: shifted(base32.StdEncoding.EncodeToString, 3)},
		{name: "lower-case base32 shifted 4", encode: func(body []byte, text string) []byte {
			return bytes.ToLower(shifted(base32.StdEncoding.EncodeToString, 4)(body, text))
		}},
		{name: "base32hex", encode: shifted(base32.HexEncoding.EncodeToString, 0)},
		{name: "percent", encode: func(body []byte, text string) []byte { return []byte(url.QueryEscape(string(body))) }},
		{name: "quoted-printable", encode: func(body []byte, text string) []byte {
			var out bytes.Buffer
			writer := quotedprintable.NewWriter(&out)
			writer.Binary = true
			writer.Write(append(bytes.Repeat([]byte("q"), 70), body...))
			writer.Close()
			return out.Bytes()
		}},
		{name: "utf-16le", encode: func(body []byte, text string) []byte { return utf16Bytes(text, false) }},
		{name: "utf-16be", encode: func(body []byte, text string) []byte { return utf16Bytes(text, true) }},
		{name: "gzip", encode: compress(func(out *bytes.Buffer) io.WriteCloser { return gzip.NewWriter(out) })},
		{name: "zlib", encode: compress(func(out *bytes.Buffer) io.WriteCloser { return zlib.NewWriter(out) })},
		{name: "deflate", encode: compress(func(out *bytes.Buffer) io.WriteCloser {
			writer, _ := flate.NewWriter(out, flate.BestSpeed)
			return writer
		})},
		{name: "brotli", encode: compress(func(out *bytes.Buffer) io.WriteCloser { return brotli.NewWriter(out) })},
		{name: "zstd", encode: func(body []byte, text string) []byte {
			encoder, err := zstd.NewWriter(nil)
			if err != nil {
				t.Fatal(err)
			}
			defer encoder.Close()
			return encoder.EncodeAll([]byte(strings.Repeat(text, 3)), nil)
		}},
		{name: "gzip of base64", encode: func(body []byte, text string) []byte {
			var out bytes.Buffer
			writer := gzip.NewWriter(&out)
			writer.Write([]byte(base64.StdEncoding.EncodeToString([]byte(text))))
			writer.Close()
			return out.Bytes()
		}},
	}
}

// What a class without a leak, or a leak without a class, is.
func leakClassErrors(classes []PrivacyClass, leaks map[PrivacyClass]*Leak) []error {
	errs := []error{}
	for _, class := range classes {
		if leaks[class] == nil {
			errs = append(errs, fmt.Errorf("%s has no leak: a capture class arrives with the leak that holds it", class))
		}
	}
	for class := range leaks {
		if !privacyClassKnown(classes, class) {
			errs = append(errs, fmt.Errorf("a leak for %s, which no capture registered", class))
		}
	}
	return errs
}

func privacyClassKnown(classes []PrivacyClass, class PrivacyClass) bool {
	for _, known := range classes {
		if known == class {
			return true
		}
	}
	return false
}

// §22.7's self-test: every class catches its leak, in every form a leak can take; mx-4's listener input
// alone is never counted, which its leak shows too.
func TestEveryClassCatchesItsLeak(t *testing.T) {
	if !LeaksLinked {
		t.Skip("the leaks link only under sidecar_leaktest, which test.sh's leak leg builds")
	}
	leaks := LeakClasses()
	for _, err := range leakClassErrors(PrivacyClasses(), leaks) {
		t.Error(err)
	}
	encodings := leakEncodings(t)
	skipped := []string{}
	ran := 0
	defer func() {
		t.Logf("%d leaks run; not leaked, as no scan opens a stream with no magic inside text: %s", ran, strings.Join(skipped, ", "))
		// every class but a text path's binary forms, and the skips above
		if ran < len(leaks)*len(encodings)/2 {
			t.Errorf("only %d leaks ran", ran)
		}
	}()
	for _, class := range PrivacyClasses() {
		leak := leaks[class]
		if leak == nil {
			continue
		}
		for _, encoding := range encodings {
			func() {
				// one open at a time: under sidecar_testhooks a Net holds the process's hooks
				net := NewNet(t.Context(), nil)
				defer net.Close()
				text := net.Capture().CanaryText("leak")
				body, err := canaryTextEncoding.DecodeString(text)
				if err != nil {
					t.Fatal(err)
				}
				value := encoding.encode(body, text)
				if !leak.Binary && !isPrintableText(bytes.ReplaceAll(bytes.ReplaceAll(value, []byte("\r"), nil), []byte("\n"), nil)) {
					return
				}
				if leak.Embeds && (encoding.name == "deflate" || encoding.name == "brotli") {
					skipped = append(skipped, fmt.Sprintf("%s as %s", class, encoding.name))
					return
				}
				ran += 1
				leak.Put(t, net, value)
				caught := false
				for _, finding := range net.Capture().Scan() {
					caught = caught || (finding.Needle == "leak" && finding.Class == class)
				}
				switch {
				case class == PrivacyClassMx4Input && caught:
					t.Errorf("mx-4's input was counted, as %s", encoding.name)
				case class != PrivacyClassMx4Input && !caught:
					t.Errorf("%s did not catch its leak as %s", class, encoding.name)
				}
			}()
		}
	}
}

// The check above fails a class that arrives with no leak, and a leak for no class.
func TestAClassWithNoLeakFails(t *testing.T) {
	registry := &privacyClassRegistry{}
	if err := registry.register("CC4/toy-edge-record"); err != nil {
		t.Fatal(err)
	}
	leaks := map[PrivacyClass]*Leak{}
	for _, class := range privacyBuiltInClasses {
		leaks[class] = &Leak{Class: class}
	}
	errs := leakClassErrors(registry.classes(), leaks)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "CC4/toy-edge-record has no leak") {
		t.Errorf("%v", errs)
	}
	leaks["CC4/toy-edge-record"] = &Leak{Class: "CC4/toy-edge-record"}
	leaks["CC4/nothing-captures"] = &Leak{Class: "CC4/nothing-captures"}
	errs = leakClassErrors(registry.classes(), leaks)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "no capture registered") {
		t.Errorf("%v", errs)
	}
}

// An untagged build links no leak and registers none; a tagged one links a leak for every class.
func TestAnUntaggedBuildLinksNoLeak(t *testing.T) {
	if LeaksLinked {
		if len(LeakClasses()) < len(privacyBuiltInClasses) {
			t.Errorf("%d leaks linked", len(LeakClasses()))
		}
		return
	}
	if len(LeakClasses()) != 0 {
		t.Errorf("an untagged build links %d leaks", len(LeakClasses()))
	}
	defer func() {
		if recover() == nil {
			t.Error("an untagged build registered a leak")
		}
	}()
	RegisterLeak(&Leak{Class: PrivacyClassLog})
}

// Each form the scanner knows is what catches its own leak: with it gone, that leak passes, which is
// how the self-test above fails a scanner that loses a form. The needles are fixed, so the forms differ
// where they must: these bytes are "+" in base64 and "-" in base64url.
func TestRemovingAFormFromTheScannerFailsTheSelfTest(t *testing.T) {
	body := bytes.Repeat([]byte{0xfb, 0xef, 0xbe}, 11)[:32]
	text := []byte("synthetic text canary 0123456789 abcdefghij")
	for _, form := range []struct {
		name   string
		needle []byte
		leak   []byte
	}{
		{name: "raw", needle: body, leak: body},
		{name: "hex", needle: body, leak: []byte(hex.EncodeToString(body))},
		{name: "base64", needle: body, leak: []byte(base64.StdEncoding.EncodeToString(body))},
		{name: "base64url", needle: body, leak: []byte(base64.URLEncoding.EncodeToString(body))},
		{name: "base32", needle: body, leak: []byte(base32.StdEncoding.EncodeToString(body))},
		{name: "base32hex", needle: body, leak: []byte(base32.HexEncoding.EncodeToString(body))},
		{name: "utf-16le", needle: text, leak: utf16Bytes(string(text), false)},
		{name: "utf-16be", needle: text, leak: utf16Bytes(string(text), true)},
	} {
		caught := func(withoutForms []string) bool {
			capture := NewPrivacyCapture()
			capture.withoutForms = withoutForms
			capture.addNeedle(&privacyNeedle{label: "leak", kind: privacyNeedleCanary, body: form.needle})
			capture.Logger("evs1").Infof("[evs]push %s", form.leak)
			return len(capture.Scan()) != 0
		}
		if !caught(nil) {
			t.Errorf("%s: the whole scanner missed its leak", form.name)
		}
		if caught([]string{form.name}) {
			t.Errorf("%s: its leak was caught with the form gone, so the self-test would not notice it gone", form.name)
		}
	}
}
