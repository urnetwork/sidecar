//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The gateway's images (DESIGN-COMPUTE §8.5's images; GW-M12-03): Codex and Claude Code resend a session's screenshots
// at every turn, so an image past the input size (GatewaySettings' ImageMaxEdgePixelCount and ImageMaxPixelCount, which
// stand for every model's, the catalog carrying none per model) is re-encoded to fit before the call is recorded or
// sent, and the session entries record what was sent and dedupe it across turns (§24.8).
//
//	read      the image's own bytes say its format, whatever its data URL claims: PNG, JPEG and GIF through the
//	          standard library, WebP through golang.org/x/image's decoder; its header's size is read first, and one
//	          past ImageDecodePixelCount is refused unread, so a small file that declares a vast image takes nothing
//	fits      an image within both bounds is sent as it came, byte for byte
//	shrink    otherwise the largest size within both bounds that keeps its proportions, counted in integers alone, and
//	          each output pixel the average of the whole source pixels its box covers, in premultiplied 16-bit
//	          channels summed in integers, so the same image re-encodes to the same bytes on every device
//	write     a JPEG as a JPEG at ImageJpegQuality, every other format as a PNG; both encoders are deterministic
//
// A data URL that is not base64, an image no decoder reads, and one too large are refused 400, invalid_image. Package-
// level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"strings"

	"golang.org/x/image/webp"
)

// The formats an image is read in and written as: identifiers.
const (
	gatewayImageFormatPng  = "png"
	gatewayImageFormatJpeg = "jpeg"
	gatewayImageFormatGif  = "gif"
	gatewayImageFormatWebp = "webp"

	gatewayMediaTypePng  = "image/png"
	gatewayMediaTypeJpeg = "image/jpeg"
	gatewayMediaTypeGif  = "image/gif"
	gatewayMediaTypeWebp = "image/webp"

	gatewayDataUrlPrefix = "data:"
	gatewayDataUrlBase64 = ";base64"
)

// One image format the gateway reads: how its header and its pixels decode, and its media type.
type gatewayImageFormat struct {
	name         string
	mediaType    string
	magic        func(data []byte) bool
	decodeConfig func(data []byte) (image.Config, error)
	decode       func(data []byte) (image.Image, error)
}

// The formats, read by their own magic bytes rather than image's registry, so what the gateway takes does not depend
// on what else the binary links.
var gatewayImageFormats = []*gatewayImageFormat{
	{
		name:      gatewayImageFormatPng,
		mediaType: gatewayMediaTypePng,
		magic:     func(data []byte) bool { return bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) },
		decodeConfig: func(data []byte) (image.Config, error) {
			return png.DecodeConfig(bytes.NewReader(data))
		},
		decode: func(data []byte) (image.Image, error) { return png.Decode(bytes.NewReader(data)) },
	},
	{
		name:      gatewayImageFormatJpeg,
		mediaType: gatewayMediaTypeJpeg,
		magic:     func(data []byte) bool { return bytes.HasPrefix(data, []byte("\xff\xd8\xff")) },
		decodeConfig: func(data []byte) (image.Config, error) {
			return jpeg.DecodeConfig(bytes.NewReader(data))
		},
		decode: func(data []byte) (image.Image, error) { return jpeg.Decode(bytes.NewReader(data)) },
	},
	{
		name:      gatewayImageFormatGif,
		mediaType: gatewayMediaTypeGif,
		magic: func(data []byte) bool {
			return bytes.HasPrefix(data, []byte("GIF87a")) || bytes.HasPrefix(data, []byte("GIF89a"))
		},
		decodeConfig: func(data []byte) (image.Config, error) {
			return gif.DecodeConfig(bytes.NewReader(data))
		},
		// an animation's first frame, as the APIs read one
		decode: func(data []byte) (image.Image, error) { return gif.Decode(bytes.NewReader(data)) },
	},
	{
		name:      gatewayImageFormatWebp,
		mediaType: gatewayMediaTypeWebp,
		magic: func(data []byte) bool {
			return 12 <= len(data) && string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP"
		},
		decodeConfig: func(data []byte) (image.Config, error) {
			return webp.DecodeConfig(bytes.NewReader(data))
		},
		decode: func(data []byte) (image.Image, error) { return webp.Decode(bytes.NewReader(data)) },
	},
}

// The format data is in, by its magic bytes; nil for none the gateway reads.
func gatewayImageFormatOf(data []byte) *gatewayImageFormat {
	for _, format := range gatewayImageFormats {
		if format.magic(data) {
			return format
		}
	}
	return nil
}

// A data URL's media type and bytes: base64 alone, which every harness sends images in. false for anything else.
func gatewayParseDataUrl(url string) (string, []byte, bool) {
	rest, ok := strings.CutPrefix(url, gatewayDataUrlPrefix)
	if !ok {
		return "", nil, false
	}
	header, encoded, ok := strings.Cut(rest, ",")
	if !ok {
		return "", nil, false
	}
	mediaType, isBase64 := strings.CutSuffix(header, gatewayDataUrlBase64)
	if !isBase64 {
		return "", nil, false
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// some clients drop the padding
		data, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(encoded, "="))
		if err != nil {
			return "", nil, false
		}
	}
	return mediaType, data, true
}

// A base64 data URL of data.
func gatewayDataUrl(mediaType string, data []byte) string {
	return gatewayDataUrlPrefix + mediaType + gatewayDataUrlBase64 + "," + base64.StdEncoding.EncodeToString(data)
}

// The size within both of the settings' bounds that keeps width:height, in integers alone; the size itself where it
// fits, and false then.
func gatewayImageTargetSize(settings *GatewaySettings, width int, height int) (int, int, bool) {
	maxEdge, maxPixels := settings.ImageMaxEdgePixelCount, settings.ImageMaxPixelCount
	if width <= 0 || height <= 0 {
		return width, height, false
	}
	edgeFits := maxEdge <= 0 || (width <= maxEdge && height <= maxEdge)
	pixelsFit := maxPixels <= 0 || uint64(width)*uint64(height) <= uint64(maxPixels)
	if edgeFits && pixelsFit {
		return width, height, false
	}
	targetWidth, targetHeight := width, height
	if !edgeFits {
		if height <= width {
			targetWidth, targetHeight = maxEdge, max(1, int(uint64(height)*uint64(maxEdge)/uint64(width)))
		} else {
			targetWidth, targetHeight = max(1, int(uint64(width)*uint64(maxEdge)/uint64(height))), maxEdge
		}
	}
	if 0 < maxPixels && uint64(maxPixels) < uint64(targetWidth)*uint64(targetHeight) {
		// width' = floor(sqrt(maxPixels * width / height)), then the height that keeps the proportions
		scaledWidth := int(gatewayIntegerSqrt(uint64(maxPixels) * uint64(width) / uint64(height)))
		scaledWidth = max(1, min(scaledWidth, targetWidth))
		scaledHeight := max(1, int(uint64(height)*uint64(scaledWidth)/uint64(width)))
		for 1 < scaledWidth && uint64(maxPixels) < uint64(scaledWidth)*uint64(scaledHeight) {
			scaledWidth--
			scaledHeight = max(1, int(uint64(height)*uint64(scaledWidth)/uint64(width)))
		}
		targetWidth, targetHeight = scaledWidth, scaledHeight
	}
	return targetWidth, targetHeight, true
}

// The largest integer whose square is at most value.
func gatewayIntegerSqrt(value uint64) uint64 {
	if value < 2 {
		return value
	}
	// Newton's method from above, in integers
	root := value
	next := (root + value/root) / 2
	for next < root {
		root = next
		next = (root + value/root) / 2
	}
	return root
}

// source scaled down to width by height: each output pixel the average of the whole source pixels its box covers, in
// premultiplied 16-bit channels summed in integers (see the file header's shrink row).
func gatewayImageAreaAverage(source image.Image, width int, height int) *image.RGBA {
	bounds := source.Bounds()
	sourceWidth, sourceHeight := bounds.Dx(), bounds.Dy()
	target := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := range height {
		y0 := bounds.Min.Y + y*sourceHeight/height
		y1 := bounds.Min.Y + (y+1)*sourceHeight/height
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := range width {
			x0 := bounds.Min.X + x*sourceWidth/width
			x1 := bounds.Min.X + (x+1)*sourceWidth/width
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var red, green, blue, alpha uint64
			for sourceY := y0; sourceY < y1; sourceY++ {
				for sourceX := x0; sourceX < x1; sourceX++ {
					r, g, b, a := source.At(sourceX, sourceY).RGBA()
					red, green, blue, alpha = red+uint64(r), green+uint64(g), blue+uint64(b), alpha+uint64(a)
				}
			}
			count := uint64(x1-x0) * uint64(y1-y0)
			target.SetRGBA(x, y, color.RGBA{
				R: uint8((red / count) >> 8),
				G: uint8((green / count) >> 8),
				B: uint8((blue / count) >> 8),
				A: uint8((alpha / count) >> 8),
			})
		}
	}
	return target
}

// data re-encoded to fit the settings' input size, with its media type (see the file header); data itself, with the
// media type its bytes say, where it fits. A gatewayError, invalid_image, for an image the gateway cannot read or
// that is too large.
func gatewayReencodeImage(settings *GatewaySettings, data []byte) (string, []byte, error) {
	format := gatewayImageFormatOf(data)
	if format == nil {
		return "", nil, gatewayInvalidRequest(GatewayErrorCodeInvalidImage, "", "an image that is no PNG, JPEG, GIF or WebP")
	}
	config, err := format.decodeConfig(data)
	if err != nil {
		return "", nil, gatewayInvalidRequest(GatewayErrorCodeInvalidImage, "", "a %s image whose header does not read", format.name)
	}
	targetWidth, targetHeight, shrink := gatewayImageTargetSize(settings, config.Width, config.Height)
	if !shrink {
		return format.mediaType, data, nil
	}
	if settings.ImageDecodePixelCount < 0 || uint64(settings.ImageDecodePixelCount) < uint64(config.Width)*uint64(config.Height) {
		return "", nil, gatewayInvalidRequest(GatewayErrorCodeInvalidImage, "",
			"a %dx%d image, past the %d pixels the gateway reads", config.Width, config.Height, settings.ImageDecodePixelCount)
	}
	source, err := format.decode(data)
	if err != nil {
		return "", nil, gatewayInvalidRequest(GatewayErrorCodeInvalidImage, "", "a %s image that does not decode", format.name)
	}
	target := gatewayImageAreaAverage(source, targetWidth, targetHeight)
	encoded := &bytes.Buffer{}
	if format.name == gatewayImageFormatJpeg {
		quality := min(max(settings.ImageJpegQuality, 1), 100)
		if err := jpeg.Encode(encoded, target, &jpeg.Options{Quality: quality}); err != nil {
			return "", nil, fmt.Errorf("an image did not encode: %w", err)
		}
		return gatewayMediaTypeJpeg, encoded.Bytes(), nil
	}
	if err := png.Encode(encoded, target); err != nil {
		return "", nil, fmt.Errorf("an image did not encode: %w", err)
	}
	return gatewayMediaTypePng, encoded.Bytes(), nil
}
