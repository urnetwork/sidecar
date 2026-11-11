//go:build !ios_extension

// Extractor 1's byte classes and transfer encodings (DESIGN-DETAILS 11.2.1, 11.2.5's T1 to T3 and W3;
// protocol/INDEX-FORMAT.md's Extractor 1): base64 and quoted-printable as rules of the format, byte loops that no
// library's release can change (QD-690). Each is total: damaged input has one reading, and nothing is refused but an
// encoded word's text, which W3 names.
//
// Names, labels and encodings compare under lower, which raises A-Z alone, and only the six white bytes are trimmed,
// so no header, parameter, label or tag is ever read as Unicode text. Package-level functions are safe for concurrent
// use.

package sidecar

// Whether b is white: 0x09 to 0x0D, or SP.
func indexWhite(b byte) bool {
	return b == ' ' || ('\t' <= b && b <= '\r')
}

// Whether b is blank: SP or HT.
func indexBlank(b byte) bool {
	return b == ' ' || b == '\t'
}

// Whether b is an ASCII letter.
func indexAsciiLetter(b byte) bool {
	return ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z')
}

// Whether b is an ASCII digit.
func indexAsciiDigit(b byte) bool {
	return '0' <= b && b <= '9'
}

// Whether b is an ASCII letter or digit.
func indexAsciiAlphanumeric(b byte) bool {
	return indexAsciiLetter(b) || indexAsciiDigit(b)
}

// A hex digit's value, 0-9, A-F and a-f, or -1 for any other byte.
func indexHexValue(b byte) int {
	switch {
	case '0' <= b && b <= '9':
		return int(b - '0')
	case 'A' <= b && b <= 'F':
		return int(b-'A') + 10
	case 'a' <= b && b <= 'f':
		return int(b-'a') + 10
	}
	return -1
}

// lower of 11.2.1: each byte A-Z raised by 0x20, every other byte as it is.
func indexLower(text string) string {
	for index := 0; index < len(text); index += 1 {
		if 'A' <= text[index] && text[index] <= 'Z' {
			lowered := []byte(text)
			for index := range lowered {
				if 'A' <= lowered[index] && lowered[index] <= 'Z' {
					lowered[index] += 'a' - 'A'
				}
			}
			return string(lowered)
		}
	}
	return text
}

// trim of 11.2.1: text without its leading and its trailing white bytes.
func indexTrim(text string) string {
	start, end := 0, len(text)
	for start < end && indexWhite(text[start]) {
		start += 1
	}
	for start < end && indexWhite(text[end-1]) {
		end -= 1
	}
	return text[start:end]
}

// A base64 alphabet byte's value, A-Z a-z 0-9 + /, or -1 for any other byte, '=' included.
func indexBase64Value(b byte) int {
	switch {
	case 'A' <= b && b <= 'Z':
		return int(b - 'A')
	case 'a' <= b && b <= 'z':
		return int(b-'a') + 26
	case '0' <= b && b <= '9':
		return int(b-'0') + 52
	case b == '+':
		return 62
	case b == '/':
		return 63
	}
	return -1
}

// Appends what base64 values give: each 4 give 3 bytes; a last 2 give 1 and a last 3 give 2, the unused bits ignored;
// a last 1 gives none.
func indexBase64AppendValues(decoded []byte, values []byte) []byte {
	for 4 <= len(values) {
		decoded = append(decoded, values[0]<<2|values[1]>>4, values[1]<<4|values[2]>>2, values[2]<<6|values[3])
		values = values[4:]
	}
	switch len(values) {
	case 2:
		decoded = append(decoded, values[0]<<2|values[1]>>4)
	case 3:
		decoded = append(decoded, values[0]<<2|values[1]>>4, values[1]<<4|values[2]>>2)
	}
	return decoded
}

// T2, a body's base64: white bytes are skipped, and alphabet bytes are taken up to the first byte that is neither,
// '=' included, where decoding ends.
func indexBase64Body(body []byte) []byte {
	decoded := make([]byte, 0, len(body)/4*3+3)
	values := make([]byte, 0, 4)
	for _, b := range body {
		if indexWhite(b) {
			continue
		}
		value := indexBase64Value(b)
		if value < 0 {
			break
		}
		values = append(values, byte(value))
		if len(values) == 4 {
			decoded = indexBase64AppendValues(decoded, values)
			values = values[:0]
		}
	}
	return indexBase64AppendValues(decoded, values)
}

// W3, an encoded word's base64 text: every '=' at its end dropped, what is left alphabet bytes alone, not 1 more than a
// multiple of 4 long, else false. Nothing is skipped, a CR or SP included.
func indexBase64Word(text []byte) ([]byte, bool) {
	end := len(text)
	for 0 < end && text[end-1] == '=' {
		end -= 1
	}
	text = text[:end]
	if len(text)%4 == 1 {
		return nil, false
	}
	values := make([]byte, len(text))
	for index, b := range text {
		value := indexBase64Value(b)
		if value < 0 {
			return nil, false
		}
		values[index] = byte(value)
	}
	return indexBase64AppendValues(make([]byte, 0, len(text)/4*3+2), values), true
}

// T3, quoted-printable, left to right: '=' and two hex digits are that byte. Any other '=' is a soft line break, which
// gives nothing, when after it come at most LineWindowByteCount blank bytes and then LF, or CR LF, or the end of body;
// all of that is consumed. Any other '=' is itself. Every other byte is itself, control bytes included, so no line is
// too long and a line's trailing blank bytes stay.
func indexQuotedPrintable(body []byte, settings *IndexFormatSettings) []byte {
	decoded := make([]byte, 0, len(body))
	for index := 0; index < len(body); {
		b := body[index]
		if b != '=' {
			decoded = append(decoded, b)
			index += 1
			continue
		}
		if index+2 < len(body) {
			if high, low := indexHexValue(body[index+1]), indexHexValue(body[index+2]); 0 <= high && 0 <= low {
				decoded = append(decoded, byte(high<<4|low))
				index += 3
				continue
			}
		}
		end := index + 1
		for end < len(body) && end-(index+1) < settings.LineWindowByteCount && indexBlank(body[end]) {
			end += 1
		}
		switch {
		case end == len(body):
			index = end
			continue
		case body[end] == '\n':
			index = end + 1
			continue
		case body[end] == '\r' && end+1 < len(body) && body[end+1] == '\n':
			index = end + 2
			continue
		}
		decoded = append(decoded, '=')
		index += 1
	}
	return decoded
}

// T1: a body under its Content-Transfer-Encoding: lower(trim(encoding)) base64 selects T2 and quoted-printable T3;
// anything else, absent included, leaves body as it is.
func indexTransferDecode(encoding string, body []byte, settings *IndexFormatSettings) []byte {
	switch indexLower(indexTrim(encoding)) {
	case "base64":
		return indexBase64Body(body)
	case "quoted-printable":
		return indexQuotedPrintable(body, settings)
	}
	return body
}
