// The views a body opens (§22.7's "decompressed"): gzip, zlib, deflate, brotli and zstd, and
// quoted-printable and percent escapes decoded, each scanned in turn and opened again, to a fixed depth
// and size, so a canary inside the gzip of a quoted-printable part is found. A view is kept only when
// it decodes cleanly, or, for a format whose header says what it is, when it decoded something before
// it stopped; a headerless format that fails says nothing, since deflate and brotli read random bytes
// as some output before they fail. Bounds hold a decompression bomb to them.

package sidecartest

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/hex"
	"io"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

type privacyDecodeSettings struct {
	// Views within views: a gzip of a quoted-printable part is depth 2.
	MaxDepth int
	// The largest body a view opens and the largest view it keeps: a body past it is scanned as it is,
	// and a view past it is cut there.
	MaxViewByteCount int
}

func defaultPrivacyDecodeSettings() *privacyDecodeSettings {
	return &privacyDecodeSettings{
		MaxDepth:         3,
		MaxViewByteCount: 64 * 1024 * 1024,
	}
}

type privacyView struct {
	name string
	body []byte
}

var zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

// Reads what reader decodes, to the bound. ok when it decoded cleanly, or, if partial is allowed, when
// it decoded something at all.
func readPrivacyView(reader io.Reader, settings *privacyDecodeSettings, partial bool) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(reader, int64(settings.MaxViewByteCount)))
	if len(body) == 0 {
		return nil, false
	}
	if err != nil && !partial {
		return nil, false
	}
	return body, true
}

// The views body opens, one level down.
func openPrivacyViews(body []byte, settings *privacyDecodeSettings) []*privacyView {
	if len(body) < 2 || settings.MaxViewByteCount < len(body) {
		return nil
	}
	views := []*privacyView{}
	add := func(name string, view []byte, ok bool) {
		if ok && !bytes.Equal(view, body) {
			views = append(views, &privacyView{name: name, body: view})
		}
	}
	if body[0] == 0x1f && body[1] == 0x8b {
		if reader, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
			view, ok := readPrivacyView(reader, settings, true)
			add("gzip", view, ok)
		}
	}
	// zlib's header: deflate with a window, and a check over its two bytes
	if body[0]&0x0f == 8 && (uint16(body[0])<<8|uint16(body[1]))%31 == 0 {
		if reader, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			view, ok := readPrivacyView(reader, settings, true)
			add("zlib", view, ok)
		}
	}
	if bytes.HasPrefix(body, zstdMagic) {
		if decoder, err := zstd.NewReader(bytes.NewReader(body), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(uint64(settings.MaxViewByteCount))); err == nil {
			view, ok := readPrivacyView(decoder, settings, true)
			add("zstd", view, ok)
			decoder.Close()
		}
	}
	view, ok := readPrivacyView(flate.NewReader(bytes.NewReader(body)), settings, false)
	add("deflate", view, ok)
	view, ok = readPrivacyView(brotli.NewReader(bytes.NewReader(body)), settings, false)
	add("brotli", view, ok)
	if view, ok := decodeQuotedPrintable(body); ok {
		add("quoted-printable", view, true)
	}
	if view, ok := decodePercent(body); ok {
		add("percent", view, true)
	}
	return views
}

// body with quoted-printable's soft breaks taken out and its =XX escapes decoded, leniently: what is
// no escape stays as it is, so a value is found whatever its writer escaped and wherever a soft break
// fell inside it. ok only when something was decoded.
func decodeQuotedPrintable(body []byte) ([]byte, bool) {
	if bytes.IndexByte(body, '=') < 0 {
		return nil, false
	}
	decoded := make([]byte, 0, len(body))
	changed := false
	for index := 0; index < len(body); index += 1 {
		b := body[index]
		if b != '=' {
			decoded = append(decoded, b)
			continue
		}
		rest := body[index+1:]
		switch {
		case bytes.HasPrefix(rest, []byte("\r\n")):
			index += 2
			changed = true
		case bytes.HasPrefix(rest, []byte("\n")):
			index += 1
			changed = true
		case 2 <= len(rest) && isHexDigit(rest[0]) && isHexDigit(rest[1]):
			value, _ := hex.DecodeString(string(rest[:2]))
			decoded = append(decoded, value[0])
			index += 2
			changed = true
		default:
			decoded = append(decoded, b)
		}
	}
	return decoded, changed
}

// body with its %XX escapes decoded, leniently, and nothing else changed. ok only when something was
// decoded.
func decodePercent(body []byte) ([]byte, bool) {
	if bytes.IndexByte(body, '%') < 0 {
		return nil, false
	}
	decoded := make([]byte, 0, len(body))
	changed := false
	for index := 0; index < len(body); index += 1 {
		b := body[index]
		if b == '%' && index+2 < len(body) && isHexDigit(body[index+1]) && isHexDigit(body[index+2]) {
			value, _ := hex.DecodeString(string(body[index+1 : index+3]))
			decoded = append(decoded, value[0])
			index += 2
			changed = true
			continue
		}
		decoded = append(decoded, b)
	}
	return decoded, changed
}

func isHexDigit(b byte) bool {
	return ('0' <= b && b <= '9') || ('a' <= b && b <= 'f') || ('A' <= b && b <= 'F')
}
