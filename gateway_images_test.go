//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

package sidecar

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
)

// GW-M12-03's images (DESIGN-COMPUTE §8.5): an image past the input size is re-encoded to fit, the same bytes every
// time; one within it passes untouched; the format is the bytes', whatever the data URL says; WebP decodes; and an
// image that declares a vast size, or that no decoder reads, is refused before it is decoded.

// A synthetic picture of width by height: a gradient, so a downscale averages distinct pixels.
func testGatewayPicture(width int, height int) *image.NRGBA {
	picture := image.NewNRGBA(image.Rect(0, 0, width, height))
	for y := range height {
		for x := range width {
			picture.SetNRGBA(x, y, color.NRGBA{R: uint8(x * 7), G: uint8(y * 13), B: uint8((x + y) * 3), A: 255})
		}
	}
	return picture
}

// The picture encoded in format.
func testGatewayEncoded(t *testing.T, format string, picture image.Image) []byte {
	t.Helper()
	buffer := &bytes.Buffer{}
	var err error
	switch format {
	case gatewayImageFormatPng:
		err = png.Encode(buffer, picture)
	case gatewayImageFormatJpeg:
		err = jpeg.Encode(buffer, picture, &jpeg.Options{Quality: 90})
	case gatewayImageFormatGif:
		err = gif.Encode(buffer, picture, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// A lossless WebP of a 1x1 opaque picture, built by hand: RIFF, VP8L, its 14-bit dimensions and a literal pixel.
var testGatewayWebp1x1 = []byte{
	'R', 'I', 'F', 'F', 0x1a, 0x00, 0x00, 0x00, 'W', 'E', 'B', 'P',
	'V', 'P', '8', 'L', 0x0d, 0x00, 0x00, 0x00,
	0x2f, 0x00, 0x00, 0x00, 0x10, 0x07, 0x10, 0x11, 0x11, 0x88, 0x88, 0xfe, 0x07, 0x00,
}

// Two encodes of the same image give the same bytes, smaller than the input and within both bounds; a JPEG stays a
// JPEG and every other format becomes a PNG.
func TestImageReencodeDeterministic(t *testing.T) {
	settings := DefaultGatewaySettings()
	settings.ImageMaxEdgePixelCount, settings.ImageMaxPixelCount = 64, 64*48
	for _, format := range []string{gatewayImageFormatPng, gatewayImageFormatJpeg, gatewayImageFormatGif} {
		data := testGatewayEncoded(t, format, testGatewayPicture(300, 200))
		mediaType, first, err := gatewayReencodeImage(settings, data)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		_, second, err := gatewayReencodeImage(settings, data)
		if err != nil || !bytes.Equal(first, second) {
			t.Fatalf("%s: two encodes differ", format)
		}
		config, decodedFormat, err := image.DecodeConfig(bytes.NewReader(first))
		if err != nil {
			t.Fatal(err)
		}
		wantFormat := "png"
		if format == gatewayImageFormatJpeg {
			wantFormat = "jpeg"
		}
		if decodedFormat != wantFormat || mediaType != "image/"+wantFormat {
			t.Errorf("%s re-encoded as %s (%s)", format, decodedFormat, mediaType)
		}
		if 64 < config.Width || 64 < config.Height || 64*48 < config.Width*config.Height || config.Width != 64 || config.Height != 42 {
			t.Errorf("%s re-encoded to %dx%d", format, config.Width, config.Height)
		}
	}
}

// An image within both bounds is sent as it came, byte for byte, its media type its bytes' whatever the URL said.
func TestImageWithinSizeUntouched(t *testing.T) {
	settings := DefaultGatewaySettings()
	data := testGatewayEncoded(t, gatewayImageFormatPng, testGatewayPicture(40, 30))
	mediaType, same, err := gatewayReencodeImage(settings, data)
	if err != nil || !bytes.Equal(same, data) || mediaType != gatewayMediaTypePng {
		t.Errorf("%s %v", mediaType, err)
	}
	url := gatewayDataUrl("image/jpeg", data)
	changed, routed, refusal := gatewayRoutedImageUrl(settings, url, "input[0].content")
	if refusal != nil || changed || routed != url {
		t.Errorf("an image that fits was changed: %v %v", changed, refusal)
	}
}

// The pixel bound holds the proportions with integers alone; the edge bound the long side.
func TestImageTargetSize(t *testing.T) {
	settings := DefaultGatewaySettings()
	for _, each := range []struct {
		width, height, wantWidth, wantHeight int
	}{
		{width: 3840, height: 2160, wantWidth: 1456, wantHeight: 819},
		{width: 1000, height: 3000, wantWidth: 522, wantHeight: 1568},
		{width: 1092, height: 1092, wantWidth: 1092, wantHeight: 1092},
		{width: 1568, height: 10, wantWidth: 1568, wantHeight: 10},
	} {
		width, height, _ := gatewayImageTargetSize(settings, each.width, each.height)
		if width != each.wantWidth || height != each.wantHeight || settings.ImageMaxPixelCount < width*height ||
			settings.ImageMaxEdgePixelCount < max(width, height) {
			t.Errorf("%dx%d to %dx%d, want %dx%d", each.width, each.height, width, height, each.wantWidth, each.wantHeight)
		}
	}
}

// One chunk of a WebP file: its fourcc and its data.
type testGatewayWebpChunk struct {
	fourcc string
	data   []byte
}

// A WebP file of chunks: RIFF, its size, WEBP, then each chunk's fourcc, size and data, padded to an even length as RIFF
// asks.
func testGatewayWebpFile(chunks ...testGatewayWebpChunk) []byte {
	body := []byte("WEBP")
	for _, chunk := range chunks {
		body = append(body, chunk.fourcc...)
		body = binary.LittleEndian.AppendUint32(body, uint32(len(chunk.data)))
		body = append(body, chunk.data...)
		if len(chunk.data)%2 == 1 {
			body = append(body, 0)
		}
	}
	file := []byte("RIFF")
	file = binary.LittleEndian.AppendUint32(file, uint32(len(body)))
	return append(file, body...)
}

// A VP8X chunk's data for a width by height canvas with no alpha: flags, three reserved bytes, then the width and the
// height less one in 24 bits each, little-endian.
func testGatewayVp8xCanvas(width int, height int) []byte {
	canvas := []byte{0, 0, 0, 0}
	canvas = append(canvas, byte(width-1), byte((width-1)>>8), byte((width-1)>>16))
	return append(canvas, byte(height-1), byte((height-1)>>8), byte((height-1)>>16))
}

// A lossy key frame of width by height whose first partition, of firstPartitionByteCount bytes, and token partition, of
// tokenByteCount, are zero bytes alone. A boolean decoder reads only 0 bits from zeros, whatever their probability, so
// the frame takes no segmentation, no loop filter, one token partition and no probability update, and each 4x4 block is
// predicted from its edges with no coefficient: a gray of luma 128 or 129 and neutral chroma.
func testGatewayVp8Gray(width int, height int, firstPartitionByteCount int, tokenByteCount int) []byte {
	// the frame tag: a key frame (bit 0 clear), version 0, shown (bit 4), then the first partition's size in 19 bits;
	// the start code; then the width and the height in 14 bits each, unscaled, little-endian
	tag := uint32(1<<4) | uint32(firstPartitionByteCount)<<5
	frame := []byte{byte(tag), byte(tag >> 8), byte(tag >> 16), 0x9d, 0x01, 0x2a}
	frame = binary.LittleEndian.AppendUint16(frame, uint16(width))
	frame = binary.LittleEndian.AppendUint16(frame, uint16(height))
	return append(frame, make([]byte, firstPartitionByteCount+tokenByteCount)...)
}

// A VP8L bitstream being written: its bytes, each filled from its least significant bit as the format reads them, and
// the bits written so far.
type testGatewayVp8lBits struct {
	data     []byte
	bitCount int
}

// The low width bits of value, least significant first.
func (self *testGatewayVp8lBits) write(value uint32, width int) {
	for i := range width {
		if self.bitCount%8 == 0 {
			self.data = append(self.data, 0)
		}
		self.data[len(self.data)-1] |= byte(value>>i&1) << (self.bitCount % 8)
		self.bitCount++
	}
}

// The header: the signature byte, the width and the height less one in 14 bits each, no alpha hint and version 0.
func (self *testGatewayVp8lBits) writeHeader(width int, height int) {
	self.write(0x2f, 8)
	self.write(uint32(width-1), 14)
	self.write(uint32(height-1), 14)
	self.write(0, 1)
	self.write(0, 3)
}

// A simple prefix code of one 8-bit symbol, which takes no bits to read, or of two, the first read from a 0 bit and the
// second from a 1.
func (self *testGatewayVp8lBits) writeSimpleCode(symbols ...uint32) {
	self.write(1, 1)
	self.write(uint32(len(symbols)-1), 1)
	self.write(1, 1)
	for _, symbol := range symbols {
		self.write(symbol, 8)
	}
}

// A lossless bitstream of width by height in halves: green 0x20 left of column splitX and 0xe0 from it, red 0x40 above
// row splitY and 0xc0 from it, blue 0x80, opaque. No transform and no color cache; green and red each a simple code of
// their two values, so each pixel takes two bits, green's then red's.
func testGatewayVp8lHalves(width int, height int, splitX int, splitY int) []byte {
	bits := &testGatewayVp8lBits{}
	bits.writeHeader(width, height)
	// no transform, no color cache, and one prefix code group for the whole image
	bits.write(0, 1)
	bits.write(0, 1)
	bits.write(0, 1)
	// green, red, blue, alpha and the backward reference distance, which no pixel uses
	bits.writeSimpleCode(0x20, 0xe0)
	bits.writeSimpleCode(0x40, 0xc0)
	bits.writeSimpleCode(0x80)
	bits.writeSimpleCode(0xff)
	bits.writeSimpleCode(0)
	for y := range height {
		for x := range width {
			greenBit, redBit := uint32(0), uint32(0)
			if splitX <= x {
				greenBit = 1
			}
			if splitY <= y {
				redBit = 1
			}
			bits.write(greenBit, 1)
			bits.write(redBit, 1)
		}
	}
	return bits.data
}

// A lossless bitstream of width by height whose entropy image names prefix code group in every tile, and which holds
// no group at all: GO-2026-6222's shape, a few bytes that name group 65535.
func testGatewayVp8lNamingGroup(width int, height int, group uint32) []byte {
	bits := &testGatewayVp8lBits{}
	bits.writeHeader(width, height)
	// no transform and no color cache, then an entropy image of 512-pixel tiles (2 + 7 bits a side)
	bits.write(0, 1)
	bits.write(0, 1)
	bits.write(1, 1)
	bits.write(7, 3)
	// the entropy image: no color cache, then one-symbol codes, so each tile's pixel takes no bits and names the
	// group in its red (the high byte) and its green (the low byte)
	bits.write(0, 1)
	bits.writeSimpleCode(group & 0xff)
	bits.writeSimpleCode(group >> 8)
	bits.writeSimpleCode(0)
	bits.writeSimpleCode(0)
	bits.writeSimpleCode(0)
	return bits.data
}

// The gateway's refusal of data, which must be 400 invalid_image with message saying want.
func testGatewayImageRefused(t *testing.T, settings *GatewaySettings, name string, data []byte, want string) {
	t.Helper()
	_, _, err := gatewayReencodeImage(settings, data)
	refusal, ok := err.(*gatewayError)
	if !ok || refusal.Code != GatewayErrorCodeInvalidImage || refusal.Status != 400 || !strings.Contains(refusal.Message, want) {
		t.Errorf("%s: %v, want 400 invalid_image saying %q", name, err, want)
	}
}

// A WebP within the input size is sent as it came, byte for byte, its size read from its VP8L, VP8 or VP8X header.
func TestImageWebpWithinSizeUntouched(t *testing.T) {
	settings := DefaultGatewaySettings()
	// a key frame's tag, its start code, then 320 by 240 in 14 bits each
	lossy := testGatewayWebpFile(testGatewayWebpChunk{
		fourcc: "VP8 ",
		data:   []byte{0x10, 0x02, 0x00, 0x9d, 0x01, 0x2a, 0x40, 0x01, 0xf0, 0x00, 0, 0, 0, 0},
	})
	for _, data := range [][]byte{testGatewayWebp1x1, lossy} {
		mediaType, same, err := gatewayReencodeImage(settings, data)
		if err != nil || mediaType != gatewayMediaTypeWebp || !bytes.Equal(same, data) {
			t.Errorf("a WebP within the size: %s %v", mediaType, err)
		}
	}
	format := gatewayImageFormatOf(lossy)
	if format == nil || format.name != gatewayImageFormatWebp {
		t.Fatal("a WebP not read as one")
	}
	if config, err := format.decodeConfig(lossy); err != nil || config.Width != 320 || config.Height != 240 {
		t.Errorf("VP8's size: %+v %v", config, err)
	}
	extended := testGatewayWebpFile(testGatewayWebpChunk{fourcc: "VP8X", data: testGatewayVp8xCanvas(4000, 3000)})
	if config, err := format.decodeConfig(extended); err != nil || config.Width != 4000 || config.Height != 3000 {
		t.Errorf("VP8X's size: %+v %v", config, err)
	}
}

// An oversized WebP, lossless or the same frame after a VP8X canvas, decodes through golang.org/x/image and comes back
// a PNG within both bounds, each pixel the average of the box it covers, the same bytes every time and from either.
func TestImageWebpReencoded(t *testing.T) {
	settings := DefaultGatewaySettings()
	settings.ImageMaxEdgePixelCount, settings.ImageMaxPixelCount = 32, 32*24
	// 320 by 240 to 32 by 24: boxes of 10 by 10, green's split through the middle of column 16's, red's on a box edge
	lossless := testGatewayVp8lHalves(320, 240, 165, 120)
	encodings := [][]byte{}
	for _, data := range [][]byte{
		testGatewayWebpFile(testGatewayWebpChunk{fourcc: "VP8L", data: lossless}),
		testGatewayWebpFile(
			testGatewayWebpChunk{fourcc: "VP8X", data: testGatewayVp8xCanvas(320, 240)},
			testGatewayWebpChunk{fourcc: "VP8L", data: lossless},
		),
	} {
		mediaType, encoded, err := gatewayReencodeImage(settings, data)
		if err != nil || mediaType != gatewayMediaTypePng {
			t.Fatalf("an oversized WebP: %s %v", mediaType, err)
		}
		if _, again, err := gatewayReencodeImage(settings, data); err != nil || !bytes.Equal(again, encoded) {
			t.Fatalf("two encodes of a WebP differ: %v", err)
		}
		picture, err := png.Decode(bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		if bounds := picture.Bounds(); bounds.Dx() != 32 || bounds.Dy() != 24 {
			t.Fatalf("re-encoded to %dx%d", bounds.Dx(), bounds.Dy())
		}
		for y := range 24 {
			for x := range 32 {
				want := color.RGBA{R: 0x40, G: 0x20, B: 0x80, A: 0xff}
				if x == 16 {
					// five columns of each green
					want.G = 0x80
				} else if 16 < x {
					want.G = 0xe0
				}
				if 12 <= y {
					want.R = 0xc0
				}
				if got := color.RGBAModel.Convert(picture.At(x, y)).(color.RGBA); got != want {
					t.Fatalf("pixel %d,%d: %v, want %v", x, y, got, want)
				}
			}
		}
		encodings = append(encodings, encoded)
	}
	if !bytes.Equal(encodings[0], encodings[1]) {
		t.Error("one frame re-encoded differently with and without its canvas")
	}
}

// An oversized lossy WebP, alone or after a VP8X canvas with its alpha in an ALPH chunk, decodes through
// golang.org/x/image and comes back a PNG within both bounds, the same bytes every time: the gray its frame decodes to,
// opaque alone and at its alpha with one, within a step of rounding through premultiplied alpha.
func TestImageWebpLossyReencoded(t *testing.T) {
	settings := DefaultGatewaySettings()
	settings.ImageMaxEdgePixelCount, settings.ImageMaxPixelCount = 32, 32*24
	frame := testGatewayVp8Gray(320, 240, 1024, 1024)
	// the canvas's alpha flag (bit 4), then the alpha unfiltered and uncompressed (a zero header byte), 0x80 everywhere
	canvas := testGatewayVp8xCanvas(320, 240)
	canvas[0] = 1 << 4
	alpha := append([]byte{0}, bytes.Repeat([]byte{0x80}, 320*240)...)
	for _, each := range []struct {
		name   string
		chunks []testGatewayWebpChunk
		alpha  uint8
	}{
		{name: "a lossy frame", chunks: []testGatewayWebpChunk{{fourcc: "VP8 ", data: frame}}, alpha: 0xff},
		{
			name: "a lossy frame with its alpha",
			chunks: []testGatewayWebpChunk{
				{fourcc: "VP8X", data: canvas},
				{fourcc: "ALPH", data: alpha},
				{fourcc: "VP8 ", data: frame},
			},
			alpha: 0x80,
		},
	} {
		data := testGatewayWebpFile(each.chunks...)
		mediaType, encoded, err := gatewayReencodeImage(settings, data)
		if err != nil || mediaType != gatewayMediaTypePng {
			t.Fatalf("%s: %s %v", each.name, mediaType, err)
		}
		if _, again, err := gatewayReencodeImage(settings, data); err != nil || !bytes.Equal(again, encoded) {
			t.Fatalf("%s: two encodes differ: %v", each.name, err)
		}
		picture, err := png.Decode(bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		if bounds := picture.Bounds(); bounds.Dx() != 32 || bounds.Dy() != 24 {
			t.Fatalf("%s: re-encoded to %dx%d", each.name, bounds.Dx(), bounds.Dy())
		}
		gray := func(value uint8) bool { return 127 <= value && value <= 129 }
		for y := range 24 {
			for x := range 32 {
				got := color.NRGBAModel.Convert(picture.At(x, y)).(color.NRGBA)
				if got.A != each.alpha || !gray(got.R) || got.G != got.R || got.B != got.R {
					t.Fatalf("%s: pixel %d,%d: %v, want a gray at alpha %#x", each.name, x, y, got, each.alpha)
				}
			}
		}
	}
}

// An oversized WebP that does not decode is refused 400 invalid_image: a canvas with no frame, a lossless bitstream or a
// lossy partition cut short, a frame that differs from its canvas, and a canvas whose alpha is missing or cut short; one
// whose header does not read, or that declares more pixels than ImageDecodePixelCount, is refused unread.
func TestImageWebpMalformedRefused(t *testing.T) {
	settings := DefaultGatewaySettings()
	settings.ImageMaxEdgePixelCount, settings.ImageMaxPixelCount = 32, 32*24
	lossless := testGatewayVp8lHalves(320, 240, 165, 120)
	lossy := testGatewayVp8Gray(320, 240, 1024, 1024)
	// a canvas naming its alpha (bit 4), and a lossy frame whose start code is gone
	alphaCanvas := testGatewayVp8xCanvas(320, 240)
	alphaCanvas[0] = 1 << 4
	noStartCode := testGatewayVp8Gray(320, 240, 1024, 1024)
	noStartCode[3] = 0
	for _, each := range []struct {
		name   string
		chunks []testGatewayWebpChunk
		want   string
	}{
		{
			name:   "a canvas with no frame",
			chunks: []testGatewayWebpChunk{{fourcc: "VP8X", data: testGatewayVp8xCanvas(320, 240)}},
			want:   "does not decode",
		},
		{
			name:   "a bitstream cut short",
			chunks: []testGatewayWebpChunk{{fourcc: "VP8L", data: lossless[:len(lossless)/2]}},
			want:   "does not decode",
		},
		{
			name: "a frame larger than its canvas",
			chunks: []testGatewayWebpChunk{
				{fourcc: "VP8X", data: testGatewayVp8xCanvas(64, 48)},
				{fourcc: "VP8L", data: lossless},
			},
			want: "does not decode",
		},
		{
			name: "a frame smaller than its canvas",
			chunks: []testGatewayWebpChunk{
				{fourcc: "VP8X", data: testGatewayVp8xCanvas(640, 480)},
				{fourcc: "VP8L", data: lossless},
			},
			want: "does not decode",
		},
		{
			name:   "a lossy first partition cut short",
			chunks: []testGatewayWebpChunk{{fourcc: "VP8 ", data: lossy[:110]}},
			want:   "does not decode",
		},
		{
			name:   "a lossy frame with no token partition",
			chunks: []testGatewayWebpChunk{{fourcc: "VP8 ", data: testGatewayVp8Gray(320, 240, 1024, 0)}},
			want:   "does not decode",
		},
		{
			name: "a lossy frame larger than its canvas",
			chunks: []testGatewayWebpChunk{
				{fourcc: "VP8X", data: testGatewayVp8xCanvas(64, 48)},
				{fourcc: "VP8 ", data: lossy},
			},
			want: "does not decode",
		},
		{
			name: "a canvas naming alpha with none before its frame",
			chunks: []testGatewayWebpChunk{
				{fourcc: "VP8X", data: alphaCanvas},
				{fourcc: "VP8 ", data: lossy},
			},
			want: "does not decode",
		},
		{
			name: "alpha cut short",
			chunks: []testGatewayWebpChunk{
				{fourcc: "VP8X", data: alphaCanvas},
				{fourcc: "ALPH", data: make([]byte, 101)},
				{fourcc: "VP8 ", data: lossy},
			},
			want: "does not decode",
		},
		{
			name:   "a lossy frame without its start code",
			chunks: []testGatewayWebpChunk{{fourcc: "VP8 ", data: noStartCode}},
			want:   "does not read",
		},
		{
			name:   "alpha with no canvas",
			chunks: []testGatewayWebpChunk{{fourcc: "ALPH", data: make([]byte, 10)}},
			want:   "does not read",
		},
		{
			name:   "a canvas past the pixels the gateway reads",
			chunks: []testGatewayWebpChunk{{fourcc: "VP8X", data: testGatewayVp8xCanvas(10000, 10000)}},
			want:   "past the",
		},
		{
			name:   "a lossless header past the pixels the gateway reads",
			chunks: []testGatewayWebpChunk{{fourcc: "VP8L", data: testGatewayVp8lNamingGroup(16384, 16384, 0)}},
			want:   "past the",
		},
	} {
		testGatewayImageRefused(t, settings, each.name, testGatewayWebpFile(each.chunks...), each.want)
	}
}

// GO-2026-6222: golang.org/x/image before v0.45.0 allocated every prefix code group up to the highest a VP8L image's
// entropy image named, about 170 MiB for group 65535 from a file of a few bytes. The decoder the gateway links refuses
// a group past libwebp's 2600 before it allocates any, and the gateway answers 400.
func TestImageWebpManyPrefixCodeGroupsRefused(t *testing.T) {
	settings := DefaultGatewaySettings()
	data := testGatewayWebpFile(testGatewayWebpChunk{fourcc: "VP8L", data: testGatewayVp8lNamingGroup(2000, 2000, 65535)})
	if len(data) > 64 {
		t.Fatalf("the image takes %d bytes", len(data))
	}
	format := gatewayImageFormatOf(data)
	if format == nil || format.name != gatewayImageFormatWebp {
		t.Fatal("a WebP not read as one")
	}
	if _, err := format.decode(data); err == nil || !strings.Contains(err.Error(), "too many Huffman trees") {
		t.Fatalf("the linked decoder on an image naming group 65535: %v, want GO-2026-6222's refusal", err)
	}
	testGatewayImageRefused(t, settings, "an image naming group 65535", data, "does not decode")
}

// An image that declares more pixels than ImageDecodePixelCount is refused unread; bytes no decoder reads, a data URL
// that is not base64, and a URL the gateway would have to fetch are refused 400 invalid_image.
func TestImageRefusals(t *testing.T) {
	settings := DefaultGatewaySettings()
	// a PNG header declaring 40000x40000, its IHDR's CRC whole, and no pixels
	header := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR")
	header = binary.BigEndian.AppendUint32(header, 40000)
	header = binary.BigEndian.AppendUint32(header, 40000)
	header = append(header, 8, 6, 0, 0, 0)
	header = binary.BigEndian.AppendUint32(header, crc32.ChecksumIEEE(header[12:]))
	if _, _, err := gatewayReencodeImage(settings, header); err == nil || !strings.Contains(err.Error(), "past the") {
		t.Errorf("a vast declared size: %v", err)
	}
	if _, _, err := gatewayReencodeImage(settings, []byte("not an image")); err == nil {
		t.Error("bytes no decoder reads")
	}
	for _, url := range []string{"https://images.example/x.png", "data:image/png,rawbytes", "data:image/png;base64,***"} {
		_, _, refusal := gatewayRoutedImageUrl(settings, url, "input[1].content")
		if refusal == nil || refusal.Code != GatewayErrorCodeInvalidImage || refusal.Status != 400 {
			t.Errorf("%s: %+v", url, refusal)
		}
	}
	_, data, ok := gatewayParseDataUrl("data:image/png;base64," + base64.RawStdEncoding.EncodeToString([]byte("abc")))
	if !ok || string(data) != "abc" {
		t.Error("unpadded base64")
	}
}

// A request's oversized screenshot is re-encoded in the routed body the call records and the model receives.
func TestImageReencodedInTheRoutedBody(t *testing.T) {
	settings := DefaultGatewaySettings()
	settings.ImageMaxEdgePixelCount, settings.ImageMaxPixelCount = 32, 32*32
	data := testGatewayEncoded(t, gatewayImageFormatPng, testGatewayPicture(320, 100))
	body := `{"model":"chutes-kimi-k3-tee-high","input":[{"role":"user","content":[{"type":"input_text","text":"look"},` +
		`{"type":"input_image","image_url":"` + gatewayDataUrl("image/png", data) + `"}]}]}`
	routed, refusal := gatewayRouteResponses(settings, []byte(body), nil)
	if refusal != nil {
		t.Fatal(refusal)
	}
	request, _, refusal := gatewayTranslateResponses(routed)
	if refusal != nil {
		t.Fatal(refusal)
	}
	image := request.Messages[0].Parts[1]
	config, err := png.DecodeConfig(bytes.NewReader(image.Data))
	if err != nil || config.Width != 32 || config.Height != 10 {
		t.Errorf("the routed image: %dx%d %v", config.Width, config.Height, err)
	}
	again, _ := gatewayRouteResponses(settings, []byte(body), nil)
	if !bytes.Equal(routed, again) {
		t.Error("two routes of the same body differ")
	}
}
