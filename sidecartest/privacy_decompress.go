// The views a body opens (§22.7's "decompressed"): gzip, zlib, deflate, brotli and zstd, and
// quoted-printable and percent escapes decoded, each scanned in turn and opened again, to a fixed depth
// and size, so a canary inside the gzip of a quoted-printable part is found. A view is kept only when
// it decodes cleanly, or, for a format whose header says what it is, when it decoded something before
// it stopped; a headerless format that fails says nothing, since deflate and brotli read random bytes
// as some output before they fail. Bounds hold a decompression bomb to them.
//
// Where a stream may start: gzip and zstd wherever their magic appears, and zlib wherever one of the
// four headers a 32 KiB window gives appears; any zlib header, deflate and brotli, which carry no magic,
// at the body's start and after each NUL, the separator the fakes put between an item's fields (a
// Redis key and its value, a task's key and arguments). A deflate or brotli stream inside text, a log
// line's or a JSON document's, is not opened: §22.7's self-test leaks those forms only through paths
// that hand a value over whole (leak_enabled.go's Embeds).

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

var (
	zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}
	// gzip's two magic bytes and its one compression method, deflate
	gzipMagic = []byte{0x1f, 0x8b, 0x08}
	// zlib's headers for a 32 KiB window, at each of its four levels
	zlibMagics = [][]byte{{0x78, 0x01}, {0x78, 0x5e}, {0x78, 0x9c}, {0x78, 0xda}}
)

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

// How many starts of one format a body's views are opened at, so a body full of a magic's bytes costs a
// bounded number of decodes.
const privacyViewStartCount = 16

// Where a stream of a format may start in body: every index of magic, or, with no magic, the start and
// each byte after a NUL.
func privacyViewStarts(body []byte, magic []byte) []int {
	starts := []int{}
	if magic != nil {
		for offset := 0; len(starts) < privacyViewStartCount; {
			index := bytes.Index(body[offset:], magic)
			if index < 0 {
				break
			}
			starts = append(starts, offset+index)
			offset += index + 1
		}
		return starts
	}
	starts = append(starts, 0)
	for offset := 0; len(starts) < privacyViewStartCount; {
		index := bytes.IndexByte(body[offset:], 0)
		if index < 0 || len(body) <= offset+index+1 {
			break
		}
		starts = append(starts, offset+index+1)
		offset += index + 1
	}
	return starts
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
	for _, start := range privacyViewStarts(body, gzipMagic) {
		if reader, err := gzip.NewReader(bytes.NewReader(body[start:])); err == nil {
			// one member: a second gzip after it is its own start
			reader.Multistream(false)
			view, ok := readPrivacyView(reader, settings, true)
			add("gzip", view, ok)
		}
	}
	zlibStarts := map[int]bool{}
	for _, magic := range zlibMagics {
		for _, start := range privacyViewStarts(body, magic) {
			zlibStarts[start] = true
		}
	}
	for _, start := range privacyViewStarts(body, nil) {
		field := body[start:]
		// zlib's header: deflate with a window, and a check over its two bytes
		if 2 <= len(field) && field[0]&0x0f == 8 && (uint16(field[0])<<8|uint16(field[1]))%31 == 0 {
			zlibStarts[start] = true
		}
	}
	for start := range zlibStarts {
		if reader, err := zlib.NewReader(bytes.NewReader(body[start:])); err == nil {
			view, ok := readPrivacyView(reader, settings, true)
			add("zlib", view, ok)
		}
	}
	for _, start := range privacyViewStarts(body, zstdMagic) {
		if decoder, err := zstd.NewReader(bytes.NewReader(body[start:]), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(uint64(settings.MaxViewByteCount))); err == nil {
			view, ok := readPrivacyView(decoder, settings, true)
			add("zstd", view, ok)
			decoder.Close()
		}
	}
	for _, start := range privacyViewStarts(body, nil) {
		field := body[start:]
		view, ok := readPrivacyView(flate.NewReader(bytes.NewReader(field)), settings, false)
		add("deflate", view, ok)
		view, ok = readPrivacyView(brotli.NewReader(bytes.NewReader(field)), settings, false)
		add("brotli", view, ok)
	}
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
