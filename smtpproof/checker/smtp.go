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

// One to LocalMaxByteCount octets of the local set.
func localForm(settings *CheckSettings, value string) bool {
	if value == "" || settings.LocalMaxByteCount < len(value) {
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
func domainForm(settings *CheckSettings, name string) bool {
	if name == "" || settings.DomainMaxByteCount < len(name) {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || settings.LabelMaxByteCount < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
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
func checkPreambleForms(settings *CheckSettings, preamble *Preamble) error {
	if preamble.RecipientCount == 0 {
		return errors.New("no recipient")
	}
	for name, value := range map[string]string{
		"recipient_domain": preamble.RecipientDomain, "header_from_domain": preamble.HeaderFromDomain,
		"dkim_selector": preamble.DkimSelector, "envelope_domain": preamble.EnvelopeDomain, "helo_name": preamble.HeloName,
	} {
		if !domainForm(settings, value) {
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

// The first application record's sequence number: 0 under 1.3, and 1 under 1.2, whose Finished took 0.
func firstApplicationSeq(version uint16) uint64 {
	if version == versionTls12 {
		return 1
	}
	return 0
}

// The role a client record plays by its position alone (DESIGN-DETAILS 3.2.5's table): EHLO at f, MAIL
// at f+1, R RCPTs, then BDAT's command or DATA, then k header records, then the body; k is 0 until the
// part that opens the header block's first record names it.
func roleAt(offset uint64, recipients uint32, mode uint32, k uint32) (role, error) {
	envelopeEnd := 2 + uint64(recipients)
	switch {
	case recipients == 0:
		return 0, errors.New("a transaction names no recipient")
	case offset == 0:
		return roleEhlo, nil
	case offset == 1:
		return roleMail, nil
	case offset < envelopeEnd:
		return roleRcpt, nil
	case offset == envelopeEnd && mode == modeBdat:
		return roleBdat, nil
	case offset == envelopeEnd && mode == modeData:
		return roleData, nil
	case offset == envelopeEnd:
		return 0, fmt.Errorf("no record of mode %d at the envelope's end", mode)
	case k == 0:
		return 0, errors.New("a message record before the header block's record count is named")
	case offset <= envelopeEnd+uint64(k):
		return roleHeader, nil
	default:
		return roleBody, nil
	}
}

// What one part opens, in its order, and the kind of part that makes it (DESIGN-DETAILS 3.2.5 step 8):
// "key", "env", "msg", "hdr" or "body". On the last part the final record is QUIT and, in DATA mode, the
// one before it the end mark, each past the header block.
func partShape(preamble *Preamble, version uint16, part *Part, seqs []uint64, k uint32) ([]role, string, error) {
	first := firstApplicationSeq(version)
	headerFirst := first + 3 + uint64(preamble.RecipientCount)
	roles := make([]role, len(seqs))
	for i, seq := range seqs {
		if seq < first {
			return nil, "", errors.New("a record before the first application record")
		}
		at, err := roleAt(seq-first, preamble.RecipientCount, part.Mode, k)
		if err != nil {
			return nil, "", err
		}
		switch {
		case part.Last && i == len(seqs)-1:
			if at != roleBody {
				return nil, "", errors.New("QUIT before the message's body")
			}
			roles[i] = roleQuit
		case part.Last && part.Mode == modeData && i == len(seqs)-2:
			if at != roleBody {
				return nil, "", errors.New("the end mark before the message's body")
			}
			roles[i] = roleEndMark
		default:
			roles[i] = at
		}
	}
	if part.Index == 1 {
		if len(roles) != 1 || roles[0] != roleEhlo {
			return nil, "", errors.New("the key part opens EHLO alone")
		}
		return roles, "key", nil
	}
	kind := ""
	headers, bodies, quit, endMark, bdat := 0, 0, false, false, false
	lastHeader := false
	for i, r := range roles {
		var this string
		switch r {
		case roleMail, roleRcpt, roleData:
			this = "env"
		case roleBdat:
			this = "msg"
			bdat = true
		case roleHeader:
			headers += 1
			this = "hdr"
			if seqs[i] == headerFirst {
				this = "msg"
			}
			lastHeader = seqs[i] == headerFirst+uint64(k)-1
		case roleBody:
			bodies += 1
			this = "body"
		case roleEndMark:
			endMark = true
			this = "body"
		case roleQuit:
			quit = true
			continue
		default:
			return nil, "", errors.New("EHLO after the key part")
		}
		if kind != "" && kind != this {
			return nil, "", errors.New("records of more than one kind in one part")
		}
		kind = this
	}
	switch {
	case kind == "" && quit:
		return nil, "", errors.New("QUIT alone")
	case kind == "":
		return roles, "env", nil
	case 1 < headers+bodies:
		return nil, "", errors.New("more than one header or body record in one part")
	case kind == "env" && quit:
		return nil, "", errors.New("QUIT in an envelope part")
	case kind == "msg" && headers != 1:
		return nil, "", errors.New("BDAT's command without the header block's first record")
	case kind == "msg" && part.Mode == modeBdat && (!bdat || roles[0] != roleBdat):
		return nil, "", errors.New("the header block's first record without BDAT's command before it")
	case kind == "body" && part.Mode != modeData:
		return nil, "", errors.New("a body record outside DATA mode")
	case kind == "body" && bodies == 0 && !endMark:
		return nil, "", errors.New("a body part with neither a body record nor the end mark")
	case part.Mode == modeBdat && (kind == "msg" || kind == "hdr") && lastHeader != quit:
		return nil, "", errors.New("BDAT's QUIT rides the header block's last record, and nothing else")
	case part.Mode == modeData && quit && !endMark:
		return nil, "", errors.New("DATA's QUIT without the end mark")
	}
	return roles, kind, nil
}

// Z4: a command record against its literal form (SPEC.md 4.2). The local part is the template's
// "local" run, so its length follows from the record's.
func checkCommand(settings *CheckSettings, r role, preamble *Preamble, content []byte) error {
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
		if !found || !localForm(settings, local) {
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
// own length, a path only with a local run of 1 to LocalMaxByteCount octets. Header and body records
// take any length.
func templateFits(settings *CheckSettings, r role, preamble *Preamble, contentBytes int) bool {
	pathFits := func(prefix string, suffix string) bool {
		local := contentBytes - len(prefix) - len(suffix)
		return 1 <= local && local <= settings.LocalMaxByteCount
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

// Z5.4's From line, without its CRLF: "From: ", a phrase of the local set and SP ending in SP or none, then
// "<", a local part, and "@" the declared domain ">".
func fromForm(settings *CheckSettings, preamble *Preamble, line string) bool {
	rest, found := strings.CutPrefix(line, "From: ")
	if found {
		rest, found = strings.CutSuffix(rest, "@"+preamble.HeaderFromDomain+">")
	}
	if !found {
		return false
	}
	phrase, local, found := strings.Cut(rest, "<")
	if !found || !localForm(settings, local) {
		return false
	}
	for i := range len(phrase) {
		if phrase[i] != ' ' && !localOctet(phrase[i]) {
			return false
		}
	}
	// Reading: SPEC.md writes the optional phrase as "phrase SP", so a phrase ends in SP
	return phrase == "" || phrase[len(phrase)-1] == ' '
}

// Z5 over the header block, as SPEC.md section 7 states it, item by item.
func checkHeaderBlock(settings *CheckSettings, preamble *Preamble, block []byte) error {
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
		"from":        func(line string) bool { return fromForm(settings, preamble, line) },
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

// The scan state between records (DESIGN-DETAILS 3.2.4): pos in bits 0 and 1 (0 in a line, 1 after CR,
// 2 after LF, 3 after a "." that began a body line), an unfinished field name in bit 2, the line's
// octets so far in bits 3 to 9, a bit from 10 for each literal the line so far begins, and in bit 16
// whether the line that just ended was a single field's.
const (
	scanPosLine = 0
	scanPosCr   = 1
	scanPosLf   = 2
	scanPosDot  = 3
	scanRunMore = 127
)

// The literals a line may begin, in the state's bit order, and whether each is a field name compared
// without case. Each is SPEC.md's.
var scanLiterals = []struct {
	text   string
	folded bool
}{
	{text: "from:", folded: true},
	{text: "message-id:", folded: true},
	{text: "x-ur-ref:", folded: true},
	{text: "feedback-id:", folded: true},
	{text: "list-unsubscribe-post:", folded: true},
	{text: "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:date:message-id:x-ur-ref:feedback-id; "},
}

// Whether line begins with a literal's first count octets: a name's letters without case, as bit 5
// forced compares them, the signature's prefix exactly.
func beginsLiteral(line []byte, literal int, count int) bool {
	text := scanLiterals[literal].text
	if len(line) < count {
		return false
	}
	for i := range count {
		octet := line[i]
		if scanLiterals[literal].folded {
			octet |= 0x20
		}
		if octet != text[i] {
			return false
		}
	}
	return true
}

// Whether a literal counts in this message: all but the one-click field, which counts on BULK alone.
func literalCounts(literal int, bulk bool) bool {
	return literal != 4 || bulk
}

// The state after the header block's first records, header, the last of which starts at recordStart:
// read from the definition over the octets themselves. first says the last record is the block's
// first, the only one a single field may end in.
func headerState(header []byte, recordStart int, first bool, bulk bool) uint32 {
	n := len(header)
	state := uint32(scanPosLine)
	switch header[n-1] {
	case '\r':
		state = scanPosCr
	case '\n':
		state = scanPosLf
	}
	if state == scanPosLf {
		// the line that ended: a single field's, in the first record only
		start := bytes.LastIndexByte(header[:n-1], '\n') + 1
		line := header[start:n]
		if first {
			for literal := range 5 {
				if literalCounts(literal, bulk) && beginsLiteral(line, literal, len(scanLiterals[literal].text)) {
					state |= 1 << 16
				}
			}
		}
		return state
	}
	start := bytes.LastIndexByte(header, '\n') + 1
	line := header[start:]
	if line[0] == ' ' || line[0] == '\t' {
		// a continuation: no name, no run
		return state
	}
	if !bytes.Contains(line, []byte(":")) {
		state |= 1 << 2
	}
	run := scanRunMore
	if recordStart <= start {
		run = min(len(line), scanRunMore)
	}
	state |= uint32(run) << 3
	for literal := range scanLiterals {
		if run < len(scanLiterals[literal].text) && beginsLiteral(line, literal, run) {
			state |= 1 << (10 + literal)
		}
	}
	return state
}

// The state after DATA's body octets so far: pos alone, the body starting at a line's start.
func bodyState(body []byte) uint32 {
	n := len(body)
	switch {
	case n == 0:
		return scanPosLf
	case body[n-1] == '\r':
		return scanPosCr
	case body[n-1] == '\n':
		return scanPosLf
	case body[n-1] == '.' && (n == 1 || body[n-2] == '\n'):
		return scanPosDot
	default:
		return scanPosLine
	}
}

// Z5's placement over the header block's records so far (DESIGN-DETAILS 3.2.4): the single fields and the
// fixed signature's prefix begin lines of the first record only, each literal whole inside it; and the
// first record holds each exactly once, in its literal form, every such line ending inside it and not
// continued there. header holds the records so far, the first firstEnd octets long.
func checkHeaderPlacement(settings *CheckSettings, preamble *Preamble, header []byte, firstEnd int) error {
	bulk := preamble.Flags&flagBulk != 0
	counts := make([]int, len(scanLiterals))
	starts := make([]int, len(scanLiterals))
	for start := 0; start < len(header); {
		end := bytes.IndexByte(header[start:], '\n')
		next := len(header)
		if 0 <= end {
			next = start + end + 1
		}
		line := header[start:next]
		if line[0] != ' ' && line[0] != '\t' {
			for literal := range scanLiterals {
				length := len(scanLiterals[literal].text)
				if !literalCounts(literal, bulk) || !beginsLiteral(line, literal, length) {
					continue
				}
				if firstEnd < start+length {
					return fmt.Errorf("Z5: %q begins a line past the header block's first record", scanLiterals[literal].text)
				}
				counts[literal] += 1
				starts[literal] = start
			}
		}
		start = next
	}
	if len(header) != firstEnd {
		return nil
	}
	// the first record alone: each once, in its literal form, whole inside it
	for literal := range scanLiterals {
		if literalCounts(literal, bulk) && counts[literal] != 1 {
			return fmt.Errorf("Z5: %d lines begin %q in the header block's first record", counts[literal], scanLiterals[literal].text)
		}
	}
	lineAt := func(literal int) ([]byte, bool) {
		start := starts[literal]
		end := bytes.Index(header[start:], []byte(crlf))
		if end < 0 {
			return nil, false
		}
		return header[start : start+end], true
	}
	forms := map[int]string{
		1: "Message-ID: <" + preamble.MessageId + ">",
		2: "X-UR-Ref: " + preamble.XUrRef,
		3: "Feedback-ID: " + preamble.FeedbackId,
	}
	if bulk {
		forms[4] = "List-Unsubscribe-Post: List-Unsubscribe=One-Click"
	}
	for literal, form := range forms {
		if line, ok := lineAt(literal); !ok || string(line) != form {
			return fmt.Errorf("Z5: %q is not whole and in its literal form inside the first record", scanLiterals[literal].text)
		}
	}
	if line, ok := lineAt(0); !ok || !fromForm(settings, preamble, string(line)) {
		return errors.New("Z5: From is not whole and in its form inside the first record")
	}
	tags := scanLiterals[5].text + "d=" + preamble.HeaderFromDomain + "; s=" + preamble.DkimSelector + "; "
	if start := starts[5]; len(header) < start+len(tags) || string(header[start:start+len(tags)]) != tags {
		return errors.New("Z5: the fixed signature's d= and s= are not inside the first record")
	}
	// a single field's line is not continued where the record shows what follows it
	for literal := range 5 {
		if !literalCounts(literal, bulk) {
			continue
		}
		line, _ := lineAt(literal)
		after := starts[literal] + len(line) + len(crlf)
		if after < len(header) && (header[after] == ' ' || header[after] == '\t') {
			return fmt.Errorf("Z5: %q is continued", scanLiterals[literal].text)
		}
	}
	return nil
}

// Z5's rules over the header records so far that a whole block's check cannot wait for: no leading
// continuation, no empty line, each line a field or a continuation whose name holds 21-7E but ':' and
// does not start with '.', CR and LF in pairs but for a CR the next record answers, and a single field's
// line not continued in a later record.
func checkHeaderSoFar(settings *CheckSettings, preamble *Preamble, header []byte, firstEnd int) error {
	for i, octet := range header {
		switch {
		case octet == '\t' || ' ' <= octet && octet <= '~':
		case octet == '\r':
			if i+1 < len(header) && header[i+1] != '\n' {
				return errors.New("Z5.1: a bare CR")
			}
		case octet == '\n':
			if i == 0 || header[i-1] != '\r' {
				return errors.New("Z5.1: a bare LF")
			}
		default:
			return fmt.Errorf("Z5.1: octet %#x", octet)
		}
	}
	if header[0] == ' ' || header[0] == '\t' {
		return errors.New("Z5.3: the first line is a continuation")
	}
	for start := 0; start < len(header); {
		end := bytes.IndexByte(header[start:], '\n')
		next := len(header)
		if 0 <= end {
			next = start + end + 1
		}
		line := header[start:next]
		start = next
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		if line[0] == '\r' {
			// the block's final empty line ends it, and the whole block's check reads that
			continue
		}
		name, _, found := bytes.Cut(line, []byte(":"))
		complete := bytes.HasSuffix(line, []byte(crlf))
		if (complete && !found) || name[0] == '.' || (found && len(name) == 0) {
			return fmt.Errorf("Z5.3: %q has no field name", line)
		}
		for _, octet := range name {
			if octet < 0x21 || 0x7e < octet {
				return fmt.Errorf("Z5.3: %q has no field name", line)
			}
		}
	}
	return checkHeaderPlacement(settings, preamble, header, firstEnd)
}

// Z6's rules over DATA's body records so far that the whole body's check cannot wait for: CR and LF in
// pairs but for a CR the next record answers, and no "." at a line's start followed by CR.
func checkBodySoFar(body []byte) error {
	for i, octet := range body {
		switch {
		case octet == '\r' && i+1 < len(body) && body[i+1] != '\n':
			return errors.New("a bare CR in DATA")
		case octet == '\n' && (i == 0 || body[i-1] != '\r'):
			return errors.New("a bare LF in DATA")
		case octet == '.' && (i == 0 || body[i-1] == '\n') && i+1 < len(body) && body[i+1] == '\r':
			return errors.New("a line of one dot in DATA")
		}
	}
	return nil
}
