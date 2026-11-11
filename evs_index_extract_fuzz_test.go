//go:build !js

// §22.6's targets for extractor 1: extraction is total and bounded on any message or file, and no byte of an
// attachment reaches a field however the message around it is built. Seeds sit in testdata/fuzz/, and every
// conformance vector of testdata/index/conformance/ is a seed besides (DESIGN-DETAILS 11.6); both run in every go test.

package sidecar

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// What a message's fields may hold at most: decoding only shrinks bytes, a charset at most triples them and an
// entity barely grows, so four times the message, plus a field's padding.
func testExtractBound(content []byte) int {
	return 4*len(content) + 1024
}

// Seeds: the vectors' messages and files, and messages near malformed.
func testExtractSeeds() map[string][]byte {
	seeds := map[string][]byte{}
	for _, c := range testExtractCases() {
		seeds[c.name] = c.content
	}
	seeds["no-header-end"] = []byte("From: a@example.com\r\nSubject: =?UTF-8?B?broken")
	seeds["unclosed-multipart"] = testMessage("Content-Type: multipart/mixed; boundary=x", "--x\nContent-Type: text/html\n\n<p>open <script>")
	seeds["encoded-word-run"] = testMessage("Subject: "+strings.Repeat("=?", 200), "")
	seeds["bad-base64"] = testMessage("Content-Type: text/plain\nContent-Transfer-Encoding: base64", "SGVsbG8!!!d29ybGQ=")
	seeds["bad-continuation"] = testMessage("Content-Type: text/plain; name*0*=UTF-8''%E2; name*1*=%ZZ", "x")
	return seeds
}

func TestExtractSeedFilesAreCurrent(t *testing.T) {
	for name, content := range testExtractSeeds() {
		testCheckCorpusFile(t, "FuzzIndexExtractMail", name, fmt.Sprintf("[]byte(%q)", content))
		testCheckCorpusFile(t, "FuzzIndexExtractFile", name, fmt.Sprintf("[]byte(%q)", content))
	}
	testCheckCorpusFile(t, "FuzzIndexExtractAttachment", "pdf", fmt.Sprintf("string(%q)", "see the sheet"), fmt.Sprintf("[]byte(%q)", "%PDF-1.4 data"), fmt.Sprintf("string(%q)", "q3.pdf"), "uint8(0)")
	testCheckCorpusFile(t, "FuzzIndexExtractAttachment", "text-attachment", fmt.Sprintf("string(%q)", "<p>hello</p>"), fmt.Sprintf("[]byte(%q)", "plain words"), fmt.Sprintf("string(%q)", "=?UTF-8?Q?n=C3=A9.txt?="), "uint8(5)")
}

// Every conformance vector's input, mail and files.
func testConformanceSeeds(f *testing.F) [][]byte {
	seeds := [][]byte{}
	for _, path := range []string{testConformanceMailPath, testConformanceFilePath} {
		for _, vector := range testConformanceVectors(f, path, indexExtractorId) {
			_, input := vector.pathAndInput(f)
			seeds = append(seeds, input)
		}
	}
	return seeds
}

func FuzzIndexExtractMail(f *testing.F) {
	for _, seed := range testConformanceSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		documents := indexExtractMail([]byte("m/202611/00/1"), content, DefaultIndexFormatSettings())
		if len(documents) == 0 {
			t.Fatal("a message gave no document")
		}
		bound := testExtractBound(content)
		for chunk, document := range documents {
			if document.Chunk != uint32(chunk) || document.Kind != IndexDocMail {
				t.Fatalf("chunk %d numbered %d", chunk, document.Chunk)
			}
			for number, field := range document.Fields {
				if bound < len(field) {
					t.Fatalf("field %d holds %d B of a %d B message", number, len(field), len(content))
				}
			}
			if DefaultIndexFormatSettings().ChunkByteCount+DefaultIndexFormatSettings().OverlapByteCount < len(document.Fields[indexFieldBody]) {
				t.Fatalf("a chunk of %d B", len(document.Fields[indexFieldBody]))
			}
			if err := document.check(); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func FuzzIndexExtractFile(f *testing.F) {
	for _, seed := range testConformanceSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		documents, ok := indexExtractFile([]byte("notes/f.txt"), content, DefaultIndexFormatSettings())
		if !ok {
			return
		}
		bound := testExtractBound(content)
		for chunk, document := range documents {
			if document.Chunk != uint32(chunk) || DefaultIndexFormatSettings().TitleMaxByteCount < len(document.Fields[indexFieldTitle]) {
				t.Fatalf("chunk %d numbered %d, titled %d B", chunk, document.Chunk, len(document.Fields[indexFieldTitle]))
			}
			if bound < len(document.Fields[indexFieldBody]) || DefaultIndexFormatSettings().ChunkByteCount+DefaultIndexFormatSettings().OverlapByteCount < len(document.Fields[indexFieldBody]) {
				t.Fatalf("a chunk of %d B", len(document.Fields[indexFieldBody]))
			}
		}
	})
}

// A message holding a text part and an attachment carrying a canary, built in one of several shapes: the canary must
// reach no field. The same message without the canary is extracted first, so a canary the text or name spelled, or a
// name that opened a part of its own, is the input's and not a leak.
func FuzzIndexExtractAttachment(f *testing.F) {
	for index, seed := range testConformanceSeeds(f) {
		f.Add("see the sheet", seed, "seed.bin", uint8(index))
	}
	f.Fuzz(func(t *testing.T, text string, attachment []byte, name string, shape uint8) {
		// A line break in the name, or the boundary anywhere, lays out other parts than these two, which is the
		// input's choice and no leak.
		if strings.ContainsAny(name, "\r\n") || strings.Contains(text+string(attachment), "zz-boundary-zz") {
			t.Skip()
		}
		canary := []byte("zqcanary" + fmt.Sprintf("%08x", len(attachment)*7919+int(shape)))
		mediaTypes := []string{"application/octet-stream", "text/plain", "text/html", "message/rfc822", "image/png", "application/pdf"}
		mediaType := mediaTypes[int(shape)%len(mediaTypes)]
		disposition := "attachment; filename=\"" + strings.ReplaceAll(name, "\"", "") + "\""
		if shape&0x10 != 0 && mediaType != "text/plain" && mediaType != "text/html" {
			// An inline part that is no text gives only its name too.
			disposition = "inline"
		}
		build := func(payload []byte) []byte {
			encoding := "base64"
			body := base64.StdEncoding.EncodeToString(payload)
			if shape&0x08 != 0 {
				encoding = "8bit"
				body = string(payload)
			}
			return testMessage(
				"From: a@example.com\nContent-Type: multipart/mixed; boundary=\"zz-boundary-zz\"",
				"--zz-boundary-zz\nContent-Type: text/plain\n\n"+text+"\n--zz-boundary-zz\nContent-Type: "+mediaType+"\nContent-Disposition: "+disposition+"\nContent-Transfer-Encoding: "+encoding+"\n\n"+body+"\n--zz-boundary-zz--\n")
		}
		holdsCanary := func(message []byte) bool {
			for _, document := range indexExtractMail([]byte("m/202611/00/1"), message, DefaultIndexFormatSettings()) {
				for _, field := range document.Fields {
					if bytes.Contains(bytes.ToLower(field), canary) {
						return true
					}
				}
			}
			return false
		}
		if holdsCanary(build(attachment)) {
			t.Skip()
		}
		payload := append(append(append([]byte{}, attachment...), ' '), canary...)
		if holdsCanary(build(append(payload, ' '))) {
			t.Fatal("a field holds the attachment's canary")
		}
	})
}
