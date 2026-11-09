package checker

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Z3 to Z9 over plaintexts: the records' framing, the commands' literal forms, the header block, the
// end of the message, the server's records and its replies (SPEC.md 4.2, 4.3 and section 7).

const (
	flagBulk       uint32 = 1
	flagRequireTls uint32 = 2

	modeBdat uint32 = 1
	modeData uint32 = 2

	crlf = "\r\n"
)

// What an opened client record holds (SPEC.md 4.2).
type role uint8

const (
	roleEhlo role = iota + 1
	roleMail
	roleRcpt
	roleData
	roleBdat
	roleHeader
	roleBody
	roleEndMark
	roleQuit
)

// SPEC.md 4.2's local set: RFC 5321's Dot-string octets without % and !.
func localOctet(octet byte) bool {
	return 'a' <= octet && octet <= 'z' || 'A' <= octet && octet <= 'Z' || '0' <= octet && octet <= '9' ||
		strings.IndexByte("#$&'*+-/=?^_`{|}~.", octet) >= 0
}

// One to 64 octets of the local set.
func localForm(value string) bool {
	if value == "" || 64 < len(value) {
		return false
	}
	for i := range len(value) {
		if !localOctet(value[i]) {
			return false
		}
	}
	return true
}

// RFC 5321's Domain, as SPEC.md section 6 reads it: labels of letters, digits and hyphens.
func domainForm(name string) bool {
	if name == "" || 255 < len(name) {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || 63 < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			octet := label[i]
			if !('a' <= octet && octet <= 'z' || 'A' <= octet && octet <= 'Z' || '0' <= octet && octet <= '9' || octet == '-') {
				return false
			}
		}
	}
	return true
}

// SPEC.md section 6's forms, refused before any template is built.
func checkPreambleForms(preamble *Preamble) error {
	if preamble.RecipientCount == 0 {
		return errors.New("no recipient")
	}
	for name, value := range map[string]string{
		"recipient_domain": preamble.RecipientDomain, "header_from_domain": preamble.HeaderFromDomain,
		"dkim_selector": preamble.DkimSelector, "envelope_domain": preamble.EnvelopeDomain, "helo_name": preamble.HeloName,
	} {
		if !domainForm(value) {
			return fmt.Errorf("%s is not a Domain", name)
		}
	}
	left, right, found := strings.Cut(preamble.MessageId, "@")
	if !found || strings.Contains(right, "@") || !localRun(left) || !localRun(right) {
		return errors.New("message_id is not one @ between two runs of the local set")
	}
	reference, found := strings.CutPrefix(preamble.XUrRef, "1.")
	if !found || !base32Spelling(reference, 21) {
		return errors.New("x_ur_ref is not 1. and the base32 of 21 octets")
	}
	fields := strings.Split(preamble.FeedbackId, ":")
	if len(fields) != 4 || (fields[0] != "n" && fields[0] != "b") || (fields[1] != "c" && fields[1] != "p" && fields[1] != "t") ||
		!base32Spelling(fields[2], 16) || fields[3] != "urnetwork" {
		return errors.New("feedback_id is not class, tier, token and urnetwork")
	}
	return nil
}

// Whether a value is the one lowercase unpadded base32 spelling (RFC 4648 §6) of octetCount octets:
// ceil(8 n / 5) characters of a-z and 2-7, the last character's unused low bits zero.
func base32Spelling(value string, octetCount int) bool {
	bitCount := 8 * octetCount
	if len(value) != (bitCount+4)/5 {
		return false
	}
	last := 0
	for i := range len(value) {
		octet := value[i]
		switch {
		case 'a' <= octet && octet <= 'z':
			last = int(octet - 'a')
		case '2' <= octet && octet <= '7':
			last = int(octet-'2') + 26
		default:
			return false
		}
	}
	unused := 5*len(value) - bitCount
	return last&(1<<unused-1) == 0
}

// A non-empty run of the local set, of any length.
func localRun(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		if !localOctet(value[i]) {
			return false
		}
	}
	return true
}

// An opened client record's content: in 1.3, Z3 requires its final octet to be the inner type 23, with
// no padding after it, and the content is what precedes it. 1.2's outer type is E1's.
func clientContent(version uint16, plaintext []byte) ([]byte, error) {
	if version == versionTls12 {
		return plaintext, nil
	}
	if len(plaintext) == 0 || plaintext[len(plaintext)-1] != recordApplicationData {
		return nil, errors.New("not unpadded application data")
	}
	return plaintext[:len(plaintext)-1], nil
}

// The roles a part's records play (SPEC.md 4.3's table), and the check a part outside it fails. Roles
// follow from public values alone, so a part with a record count its index has no roles for is refused
// before any verification, which is the edge's refusal, E3, as for a template no plaintext of a
// record's length can fill (SPEC.md readings 23 and 28).
func partRoles(preamble *Preamble, part *Part) ([]role, string, error) {
	count := len(part.Records)
	repeat := func(r role, times int) []role {
		roles := make([]role, times)
		for i := range roles {
			roles[i] = r
		}
		return roles
	}
	switch {
	case part.Index == 1:
		if count != 1 {
			return nil, "E3", errors.New("pi1 opens one record, EHLO")
		}
		return []role{roleEhlo}, "", nil
	case part.Index == 2:
		roles := append([]role{roleMail}, repeat(roleRcpt, int(min(preamble.RecipientCount, uint32(count))))...)
		if part.Mode == modeData {
			roles = append(roles, roleData)
		}
		if uint64(count) != 1+uint64(preamble.RecipientCount)+map[bool]uint64{true: 1}[part.Mode == modeData] {
			return nil, "E3", fmt.Errorf("pi2 opens %d records for %d recipients", count, preamble.RecipientCount)
		}
		return roles, "", nil
	case part.Index == 3 && part.Mode == modeBdat:
		if count != 3 || !part.Last {
			return nil, "E3", errors.New("BDAT's pi3 opens BDAT, the header block and QUIT, and is the last")
		}
		return []role{roleBdat, roleHeader, roleQuit}, "", nil
	case part.Mode == modeData && 3 <= part.Index:
		var roles []role
		if part.Index == 3 {
			roles = append(roles, roleHeader)
		}
		ends := 0
		if part.Last {
			ends = 2
		}
		if count < len(roles)+ends || (!part.Last && count == len(roles) && part.Index != 3) || count == 0 {
			return nil, "E3", errors.New("a DATA part without its records or its end")
		}
		roles = append(roles, repeat(roleBody, count-len(roles)-ends)...)
		if part.Last {
			roles = append(roles, roleEndMark, roleQuit)
		}
		return roles, "", nil
	default:
		return nil, "E3", fmt.Errorf("no part %d in mode %d", part.Index, part.Mode)
	}
}

// Z4: a command record against its literal form (SPEC.md 4.2). The local part is the template's
// "local" run, so its length follows from the record's.
func checkCommand(r role, preamble *Preamble, content []byte) error {
	text := string(content)
	exact := func(want string) error {
		if text != want {
			return fmt.Errorf("record is not %q", strings.TrimSuffix(want, crlf))
		}
		return nil
	}
	path := func(prefix string, suffix string) error {
		local, found := strings.CutPrefix(text, prefix)
		if found {
			local, found = strings.CutSuffix(local, suffix)
		}
		if !found || !localForm(local) {
			return fmt.Errorf("record is not %q with a local part", prefix+"…"+strings.TrimSuffix(suffix, crlf))
		}
		return nil
	}
	switch r {
	case roleEhlo:
		return exact("EHLO " + preamble.HeloName + crlf)
	case roleMail:
		suffix := "@" + preamble.EnvelopeDomain + ">"
		if preamble.Flags&flagRequireTls != 0 {
			suffix += " REQUIRETLS"
		}
		return path("MAIL FROM:<", suffix+crlf)
	case roleRcpt:
		return path("RCPT TO:<", "@"+preamble.RecipientDomain+">"+crlf)
	case roleBdat:
		return exact("BDAT " + strconv.FormatUint(preamble.MessageByteCount, 10) + " LAST" + crlf)
	case roleData:
		return exact("DATA" + crlf)
	}
	return nil
}

// Whether a record of contentBytes octets can fill its role's template at all: a literal only at its
// own length, a path only with a local run of 1 to 64 octets. Header and body records take any length.
func templateFits(r role, preamble *Preamble, contentBytes int) bool {
	pathFits := func(prefix string, suffix string) bool {
		local := contentBytes - len(prefix) - len(suffix)
		return 1 <= local && local <= 64
	}
	switch r {
	case roleEhlo:
		return contentBytes == len("EHLO "+preamble.HeloName+crlf)
	case roleMail:
		suffix := "@" + preamble.EnvelopeDomain + ">" + crlf
		if preamble.Flags&flagRequireTls != 0 {
			suffix = "@" + preamble.EnvelopeDomain + "> REQUIRETLS" + crlf
		}
		return pathFits("MAIL FROM:<", suffix)
	case roleRcpt:
		return pathFits("RCPT TO:<", "@"+preamble.RecipientDomain+">"+crlf)
	case roleBdat:
		return contentBytes == len("BDAT "+strconv.FormatUint(preamble.MessageByteCount, 10)+" LAST"+crlf)
	case roleData, roleQuit:
		return contentBytes == len("DATA"+crlf)
	case roleEndMark:
		return contentBytes == len("."+crlf)
	default:
		return 0 <= contentBytes
	}
}

// Z5 over the header block, as SPEC.md section 7 states it, item by item.
func checkHeaderBlock(preamble *Preamble, block []byte) error {
	// 1: the octet class, CR only before LF, LF only after CR
	for i, octet := range block {
		switch {
		case octet == '\t' || ' ' <= octet && octet <= '~':
		case octet == '\r':
			if i+1 == len(block) || block[i+1] != '\n' {
				return errors.New("Z5.1: a bare CR")
			}
		case octet == '\n':
			if i == 0 || block[i-1] != '\r' {
				return errors.New("Z5.1: a bare LF")
			}
		default:
			return fmt.Errorf("Z5.1: octet %#x", octet)
		}
	}
	// 2: CRLF CRLF at the end and no empty line before it
	if !bytes.HasSuffix(block, []byte(crlf+crlf)) {
		return errors.New("Z5.2: no CRLF CRLF at the end")
	}
	lines := strings.Split(string(block[:len(block)-2*len(crlf)]), crlf)
	for _, line := range lines {
		if line == "" {
			return errors.New("Z5.2: an empty line before the end")
		}
	}
	// 3: no leading continuation; each field line a name of 21-7E but ':' up to ':', not starting '.'
	continuation := func(line string) bool {
		return line[0] == ' ' || line[0] == '\t'
	}
	if continuation(lines[0]) {
		return errors.New("Z5.3: the first line is a continuation")
	}
	for _, line := range lines {
		if continuation(line) {
			continue
		}
		name, _, found := strings.Cut(line, ":")
		if !found || name == "" || name[0] == '.' {
			return fmt.Errorf("Z5.3: %q has no field name", line)
		}
		for i := range len(name) {
			if name[i] < 0x21 || 0x7e < name[i] {
				return fmt.Errorf("Z5.3: %q has no field name", line)
			}
		}
	}
	// 4: from, message-id, x-ur-ref and feedback-id once each, uncontinued, in their literal forms
	literals := map[string]func(line string) bool{
		"from": func(line string) bool {
			rest, found := strings.CutPrefix(line, "From: ")
			if found {
				rest, found = strings.CutSuffix(rest, "@"+preamble.HeaderFromDomain+">")
			}
			if !found {
				return false
			}
			phrase, local, found := strings.Cut(rest, "<")
			if !found || !localForm(local) {
				return false
			}
			for i := range len(phrase) {
				if phrase[i] != ' ' && !localOctet(phrase[i]) {
					return false
				}
			}
			// Reading: SPEC.md writes the optional phrase as "phrase SP", so a phrase ends in SP
			return phrase == "" || phrase[len(phrase)-1] == ' '
		},
		"message-id":  func(line string) bool { return line == "Message-ID: <"+preamble.MessageId+">" },
		"x-ur-ref":    func(line string) bool { return line == "X-UR-Ref: "+preamble.XUrRef },
		"feedback-id": func(line string) bool { return line == "Feedback-ID: "+preamble.FeedbackId },
	}
	counts := map[string]int{}
	for i, line := range lines {
		if continuation(line) {
			continue
		}
		name, _, _ := strings.Cut(line, ":")
		literal, ok := literals[strings.ToLower(name)]
		if !ok {
			continue
		}
		counts[strings.ToLower(name)] += 1
		if !literal(line) {
			return fmt.Errorf("Z5.4: %q is not in its literal form", line)
		}
		if i+1 < len(lines) && continuation(lines[i+1]) {
			return fmt.Errorf("Z5.4: %s is continued", name)
		}
	}
	for name := range literals {
		if counts[name] != 1 {
			return fmt.Errorf("Z5.4: %d lines named %s", counts[name], name)
		}
	}
	// 5: exactly one line with the fixed signature's prefix, continuing with d= and s=
	const signaturePrefix = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:date:message-id:x-ur-ref:feedback-id; "
	signatures := 0
	for _, line := range lines {
		if strings.HasPrefix(line, signaturePrefix) {
			signatures += 1
			if !strings.HasPrefix(line, signaturePrefix+"d="+preamble.HeaderFromDomain+"; s="+preamble.DkimSelector+"; ") {
				return errors.New("Z5.5: the fixed signature names another d= or s=")
			}
		}
	}
	if signatures != 1 {
		return fmt.Errorf("Z5.5: %d fixed signatures", signatures)
	}
	// 6: when BULK, one line named list-unsubscribe-post, uncontinued, and it is the literal
	if preamble.Flags&flagBulk != 0 {
		posts := 0
		for i, line := range lines {
			if continuation(line) {
				continue
			}
			name, _, _ := strings.Cut(line, ":")
			if strings.ToLower(name) != "list-unsubscribe-post" {
				continue
			}
			posts += 1
			if line != "List-Unsubscribe-Post: List-Unsubscribe=One-Click" {
				return fmt.Errorf("Z5.6: %q is not in its literal form", line)
			}
			if i+1 < len(lines) && continuation(lines[i+1]) {
				return errors.New("Z5.6: List-Unsubscribe-Post is continued")
			}
		}
		if posts != 1 {
			return fmt.Errorf("Z5.6: %d List-Unsubscribe-Post lines on BULK", posts)
		}
	}
	return nil
}

// Z6 over a DATA record: whole lines ending CRLF, no bare CR or LF, and no line that is exactly ".".
func checkDataRecord(content []byte) error {
	if !bytes.HasSuffix(content, []byte(crlf)) {
		return errors.New("a DATA record not ending CRLF")
	}
	for i, octet := range content {
		if octet == '\r' && (i+1 == len(content) || content[i+1] != '\n') {
			return errors.New("a bare CR in DATA")
		}
		if octet == '\n' && (i == 0 || content[i-1] != '\r') {
			return errors.New("a bare LF in DATA")
		}
	}
	for _, line := range strings.Split(string(content[:len(content)-len(crlf)]), crlf) {
		if line == "." {
			return errors.New("a line of one dot in DATA")
		}
	}
	return nil
}

// Z7: what a server record holds. 1.3 application data joins the reply stream; a NewSessionTicket,
// inner type 22 whose first octet is 4, is skipped; anything else fails, a padded record included.
func serverContent(version uint16, plaintext []byte) ([]byte, bool, error) {
	if version == versionTls12 {
		return plaintext, true, nil
	}
	if len(plaintext) == 0 {
		return nil, false, errors.New("an empty server record")
	}
	switch plaintext[len(plaintext)-1] {
	case recordApplicationData:
		return plaintext[:len(plaintext)-1], true, nil
	case recordHandshake:
		if 1 < len(plaintext) && plaintext[0] == messageNewSessionTicket {
			return nil, false, nil
		}
		return nil, false, errors.New("a server handshake record other than a ticket")
	default:
		return nil, false, fmt.Errorf("a server record of inner type %d", plaintext[len(plaintext)-1])
	}
}

// One RFC 5321 reply: each line's code and text.
type reply struct {
	codes []string
	texts []string
}

// Z8's parse: lines of three digits, then '-' or SP with text, or CRLF directly; text without CR or
// LF; a reply is its lines through one without '-'. The stream must end at a reply's end.
func parseReplies(stream []byte) ([]*reply, error) {
	var replies []*reply
	current := &reply{}
	for 0 < len(stream) {
		end := bytes.Index(stream, []byte(crlf))
		if end < 0 {
			return nil, errors.New("a reply line without its CRLF")
		}
		line := string(stream[:end])
		stream = stream[end+len(crlf):]
		if len(line) < 3 || strings.IndexFunc(line[:3], func(r rune) bool { return r < '0' || '9' < r }) >= 0 {
			return nil, fmt.Errorf("reply line %q has no code", line)
		}
		if strings.ContainsAny(line, "\r\n") {
			return nil, errors.New("a reply line holding CR or LF")
		}
		more := 3 < len(line) && line[3] == '-'
		if 3 < len(line) && line[3] != '-' && line[3] != ' ' {
			return nil, fmt.Errorf("reply line %q", line)
		}
		current.codes = append(current.codes, line[:3])
		current.texts = append(current.texts, line[min(4, len(line)):])
		if !more {
			replies = append(replies, current)
			current = &reply{}
		}
	}
	if 0 < len(current.codes) {
		return nil, errors.New("the stream ends inside a reply")
	}
	return replies, nil
}

// Whether every line of a reply has a code that passes.
func (self *reply) coded(pass func(code string) bool) bool {
	for _, code := range self.codes {
		if !pass(code) {
			return false
		}
	}
	return true
}

// Z9: CHUNKING in the EHLO reply, the line and the CRLF before it inside one application record.
func offersChunking(records [][]byte) bool {
	for _, content := range records {
		lower := bytes.ToLower(content)
		for _, separator := range []string{"-", " "} {
			if bytes.Contains(lower, []byte(crlf+"250"+separator+"chunking"+crlf)) {
				return true
			}
		}
	}
	return false
}
