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

// A WebP header of chunk fourcc with data: RIFF, its size, WEBP, the chunk and its size.
func testGatewayWebpHeader(fourcc string, data []byte) []byte {
	header := []byte("RIFF")
	header = binary.LittleEndian.AppendUint32(header, uint32(4+8+len(data)))
	header = append(header, "WEBP"...)
	header = append(header, fourcc...)
	header = binary.LittleEndian.AppendUint32(header, uint32(len(data)))
	return append(header, data...)
}

// A WebP's size is read from its own header, VP8L's, VP8's and VP8X's, with no decoder linked: one within the input
// size is sent as it came, and one past it is refused 400 until a decoder past GO-2026-6222 is linked.
func TestImageWebpReadByItsHeader(t *testing.T) {
	settings := DefaultGatewaySettings()
	mediaType, same, err := gatewayReencodeImage(settings, testGatewayWebp1x1)
	if err != nil || mediaType != gatewayMediaTypeWebp || !bytes.Equal(same, testGatewayWebp1x1) {
		t.Fatalf("a WebP within the size: %s %v", mediaType, err)
	}
	lossy := testGatewayWebpHeader("VP8 ", []byte{0x10, 0x02, 0x00, 0x9d, 0x01, 0x2a, 0x40, 0x01, 0xf0, 0x00, 0, 0, 0, 0})
	config, err := gatewayWebpConfig(lossy)
	if err != nil || config.Width != 320 || config.Height != 240 {
		t.Errorf("VP8's size: %+v %v", config, err)
	}
	if _, same, err := gatewayReencodeImage(settings, lossy); err != nil || !bytes.Equal(same, lossy) {
		t.Errorf("a lossy WebP within the size: %v", err)
	}
	// a canvas of 4000x3000, past the input size
	extended := testGatewayWebpHeader("VP8X", []byte{0, 0, 0, 0, 0x9f, 0x0f, 0x00, 0xb7, 0x0b, 0x00})
	if config, err := gatewayWebpConfig(extended); err != nil || config.Width != 4000 || config.Height != 3000 {
		t.Errorf("VP8X's size: %+v %v", config, err)
	}
	_, _, err = gatewayReencodeImage(settings, extended)
	refusal, ok := err.(*gatewayError)
	if !ok || refusal.Code != GatewayErrorCodeInvalidImage || refusal.Status != 400 || !strings.Contains(refusal.Message, "PNG or JPEG") {
		t.Errorf("an oversized WebP: %v", err)
	}
	if _, err := gatewayWebpConfig(testGatewayWebpHeader("ALPH", make([]byte, 10))); err == nil {
		t.Error("a WebP of an unknown first chunk was read")
	}
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
