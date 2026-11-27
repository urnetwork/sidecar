//go:build !ios_extension

// How an approver's device shows a version-5 action (DESIGN-COMPUTE §16.3's "Canonical text shows" column, §25.10's
// kind 26, §28.8's kind 27; D-MCP-17, IC-16, IC-20; CACL-M12-02), in the one render ur approve, the daemon's approval
// methods and the sdk's approvals all show through ApprovalRender.Text(). RenderApprovalRequestDetail hands a version-5
// action here, so versions 1 to 4 render as before, byte for byte.
//
//	fields     each field the action sets, a nested message field by field under its record.proto names
//	           (enclave.shape, send.target_agent, calendar_events[0].title), never through the scalar path, which would
//	           misread a message; every string escaped by ApprovalUntrustedText, bytes in lowercase hex, numbers in
//	           decimal, an amount in nano-USD also in dollars, and a numbered value by its name beside its number
//	sections   kind 24's whole send (its text and stdin), kind 26's whole body and kind 27's whole message each in a
//	           section of its own, line by line (ApprovalUntrustedLines), never in the 2 KiB preview
//	detail     the opened CanonicalActionDetail5 (Sidecar.OpenActionDetail5) as sealed_detail.<name>; a detail that did
//	           not open takes no approval, as version 4's does
//	auto       field 70's basis and rule numbers among the fields; SAFE-M13-11 puts the rules in words
//	meaning    a sentence built around daemon-built fields, never from an agent's text, for each kind (see
//	           approvalComputeMeaning), and kind 19's provider disclosure line, which opens its text, from CTRUST's
//	           registry (ApprovalComputeDisclosureLines)
//	withheld   what the device could not show whole or check, each a reason it takes no approval: a string past
//	           ApprovalComputeRenderSettings.TextMaxByteCount or a list past ListMaxCount, a sealed detail that did not
//	           open, kind 19's disclosure line where no registry renders it, kind 23's host that is not its URL's in
//	           punycode, kind 25's events, whose per-event cards are MAILCAL-M13-06's, kind 27's files, which only the
//	           support conversation's card shows whole, and kind 24's release, whose versions' writer, taint and text
//	           need the release's version reader
//
// A channel-4 decision's rendering is SAFE-M13-11's. The render is a value nothing changes. Package-level functions are
// safe for concurrent use. On every leg but the ios_extension legs, as record_approval_render.go is.

package sidecar

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

// The version-5 render's bounds (QD-702). The package-level render reads DefaultApprovalComputeRenderSettings(), as
// the action rules read DefaultCanonicalActionSettings(); threading each device's own instance through is the review
// phase's settings sweep (QD-706).
type ApprovalComputeRenderSettings struct {
	// The most bytes one string of a version-5 action may hold for the render to show it whole: 64 KiB, twice the
	// 32 KiB a send's stdin and a call's body may hold (§16.3, §25.10). A longer one is shown cut and takes no
	// approval, since a person approves only what they were shown whole.
	TextMaxByteCount int
	// The most entries one repeated field may hold for the render to show it whole: 256. A longer list takes no
	// approval.
	ListMaxCount int
}

// The render's defaults, the only place one is set.
func DefaultApprovalComputeRenderSettings() *ApprovalComputeRenderSettings {
	return &ApprovalComputeRenderSettings{
		TextMaxByteCount: 64 * 1024,
		ListMaxCount:     256,
	}
}

// What renders a disclosure's summary line on this device: CTRUST's registry (CTRUST-M11-01's
// ComputeDisclosureRegistry.Line), in the person's locale. An error, or no source at all, renders none, and a kind-19
// card, which the line opens (§16.3), then takes no approval. Safe for concurrent use.
type ApprovalComputeDisclosureLines interface {
	ApprovalDisclosureLine(id string) (string, error)
}

// What builds a Sidecar's disclosure lines: CTRUST's file registers one from an init function
// (registerApprovalComputeDisclosureLines). Nil until it does.
var approvalComputeDisclosureLinesSource func(sidecar *Sidecar) ApprovalComputeDisclosureLines

// Registers what gives a Sidecar's disclosure lines, from an init function in CTRUST's file. A second registration, or
// a nil one, is a build error, which panics as registerComputeComponent does.
func registerApprovalComputeDisclosureLines(source func(sidecar *Sidecar) ApprovalComputeDisclosureLines) {
	if source == nil || approvalComputeDisclosureLinesSource != nil {
		panic("approval disclosure lines registered twice or as nil")
	}
	approvalComputeDisclosureLinesSource = source
}

// This sidecar's disclosure lines, nil where no registry is registered.
func (self *Sidecar) approvalComputeDisclosureLines() ApprovalComputeDisclosureLines {
	if self == nil || approvalComputeDisclosureLinesSource == nil {
		return nil
	}
	return approvalComputeDisclosureLinesSource(self)
}

// One section of a version-5 render: a field's whole text apart from the fields.
type ApprovalComputeSection struct {
	// record.proto's path of the field it shows: send.text, send.stdin, service_call.body, support.text.
	Name string
	// What it is, in the daemon's words.
	Title string
	// Its lines, each escaped (ApprovalUntrustedLines).
	Lines []string
}

// What a version-5 render adds to ApprovalRender (CACL-M12-02).
type ApprovalComputeRender struct {
	// Kind 19's provider disclosure, by its id (enclave:<provider>) and its summary line, which opens its text; empty
	// for every other kind, and the line empty where it did not render.
	DisclosureId string
	Disclosure   string
	// The whole send, body or message, each in its own section.
	Sections []*ApprovalComputeSection
	// What the person should notice beside the action, each a sentence: a host that does not convert to punycode, a
	// value holding characters the render escaped.
	Flags []string
	// Why this device takes no approval of the action, each a sentence; empty where it showed the action whole.
	Withheld []string
}

// The inputs of a version-5 render.
type ApprovalComputeRenderArgs struct {
	// The request as Pending parsed it, its action at version 5.
	Request *StoredApprovalRequest
	// What its sealed_detail opened to on this device (Sidecar.OpenActionDetail5): nil for an action that carries none,
	// or one that did not open, which then takes no approval.
	Detail *protocol.CanonicalActionDetail5
	// Kind 19's disclosure line's source; nil renders none, and a kind-19 card takes no approval.
	Disclosures ApprovalComputeDisclosureLines
	// Nil reads DefaultApprovalComputeRenderSettings().
	Settings *ApprovalComputeRenderSettings
}

// The fields a version-5 render shows as sections, by message and field name.
var approvalComputeSectionFields = map[string]string{
	"SendFields.text":                 "the whole of what is sent",
	"SendFields.stdin":                "the whole of the command's stdin",
	"ServiceCallFields.body":          "the whole body the call sends",
	"SupportFields.text":              "the whole message",
	"CalendarEventAction.description": "the event's whole description",
}

// The fields that hold nano-USD, by message and field name.
var approvalComputeUsdFields = []string{"EnclaveFields.price_per_hour", "BudgetFields.amount", "BudgetFields.current"}

// The fields that hold unix seconds, by message and field name.
var approvalComputeSecondsFields = []string{"BundleManifest.first", "BundleManifest.last"}

// The names of the numbered values version 5's uint32 fields carry, by message and field name (§16.3, §23.9, §25.10,
// §27.9, §28.8; QD-1391's direct).
var approvalComputeValueNames = map[string]map[uint64]string{
	"CanonicalAction.egress_mode":   {1: "auto", 2: "exits", 3: "none", uint64(approvalComputeEgressModeDirect): "direct"},
	"BudgetFields.period":           {1: "day", 2: "month", 3: "run"},
	"SendFields.mode":               {1: "prompt", 2: "steer", 3: "follow_up"},
	"ContextFields.act":             {1: "continue", 2: "cross"},
	"CalendarEventAction.operation": {1: "add", 2: "change", 3: "remove"},
	"ServiceCallFields.class":       {1: "write", 2: "send"},
	"AutoFields.basis":              {1: "taint", 2: "always"},
	"CanonicalActionDetail5.role":   {1: "agents", 2: "indexer"},
	"SupportFields.kind":            {1: "bug", 2: "feature", 3: "question", 4: "praise", 5: "security", 6: "other"},
	"FileFields.type":               {1: "text", 2: "png", 3: "jpeg"},
}

// An amount of nano-USD in dollars, exactly: at least two places, more only where the amount needs them.
func approvalComputeUsd(nanoUsd uint64) string {
	fraction := strings.TrimRight(fmt.Sprintf("%09d", nanoUsd%1_000_000_000), "0")
	for len(fraction) < 2 {
		fraction += "0"
	}
	return "$" + strconv.FormatUint(nanoUsd/1_000_000_000, 10) + "." + fraction
}

// One render's working state.
type approvalComputeRenderer struct {
	settings *ApprovalComputeRenderSettings
	action   *protocol.CanonicalAction
	render   *ApprovalRender
	compute  *ApprovalComputeRender
	// the fields by path, for the meaning
	shown map[string]string
}

// Adds a reason the action takes no approval here.
func (self *approvalComputeRenderer) withhold(format string, a ...any) {
	reason := fmt.Sprintf(format, a...)
	if !slices.Contains(self.compute.Withheld, reason) {
		self.compute.Withheld = append(self.compute.Withheld, reason)
	}
}

// Adds a flag.
func (self *approvalComputeRenderer) flag(format string, a ...any) {
	flag := fmt.Sprintf(format, a...)
	if !slices.Contains(self.compute.Flags, flag) {
		self.compute.Flags = append(self.compute.Flags, flag)
	}
}

// Adds one field.
func (self *approvalComputeRenderer) field(name string, value string) {
	self.render.Fields = append(self.render.Fields, &ApprovalRenderField{Name: name, Value: value})
	self.shown[name] = value
}

// A string escaped as one line, past the bound cut and withheld, a value holding escaped characters flagged.
func (self *approvalComputeRenderer) text(name string, text string) string {
	if self.settings.TextMaxByteCount < len(text) {
		self.withhold("%s holds %d bytes, more than this device shows whole", name, len(text))
		text = text[:self.settings.TextMaxByteCount]
	}
	if ApprovalUntrustedHidden(text) {
		self.flag("%s holds characters shown escaped as \\u{...}", name)
	}
	return ApprovalUntrustedText(text)
}

// A section of its own, its text whole line by line, or cut and withheld past the bound.
func (self *approvalComputeRenderer) section(name string, title string, text string) {
	if self.settings.TextMaxByteCount < len(text) {
		self.withhold("%s holds %d bytes, more than this device shows whole", name, len(text))
		text = text[:self.settings.TextMaxByteCount]
	}
	if ApprovalUntrustedHidden(strings.ReplaceAll(text, "\n", "")) {
		self.flag("%s holds characters shown escaped as \\u{...}", name)
	}
	self.compute.Sections = append(self.compute.Sections, &ApprovalComputeSection{Name: name, Title: title, Lines: ApprovalUntrustedLines(text)})
	self.shown[name] = text
}

// One scalar value as the render shows it, by its message and field.
func (self *approvalComputeRenderer) scalar(name string, key string, field protoreflect.FieldDescriptor, value protoreflect.Value) string {
	switch field.Kind() {
	case protoreflect.StringKind:
		return self.text(name, value.String())
	case protoreflect.BytesKind:
		return hex.EncodeToString(value.Bytes())
	case protoreflect.BoolKind:
		return strconv.FormatBool(value.Bool())
	case protoreflect.Int32Kind, protoreflect.Int64Kind, protoreflect.Sint32Kind, protoreflect.Sint64Kind,
		protoreflect.Sfixed32Kind, protoreflect.Sfixed64Kind:
		text := strconv.FormatInt(value.Int(), 10)
		if slices.Contains(approvalComputeSecondsFields, key) {
			text += " (" + time.Unix(value.Int(), 0).UTC().Format(time.RFC3339) + ")"
		}
		return text
	case protoreflect.EnumKind:
		number := value.Enum()
		text := strconv.FormatInt(int64(number), 10)
		if enumValue := field.Enum().Values().ByNumber(number); enumValue != nil {
			text += " (" + strings.ToLower(string(enumValue.Name())) + ")"
		}
		return text
	}
	number := value.Uint()
	text := strconv.FormatUint(number, 10)
	if slices.Contains(approvalComputeUsdFields, key) {
		return approvalComputeUsd(number) + " (" + text + " nano-USD)"
	}
	if names, ok := approvalComputeValueNames[key]; ok {
		if name, named := names[number]; named {
			return text + " (" + name + ")"
		}
		return text + " (unnamed)"
	}
	return text
}

// One field of message, which a render shows under name: a section, a nested message field by field, a list entry by
// entry, or a scalar.
func (self *approvalComputeRenderer) value(name string, field protoreflect.FieldDescriptor, value protoreflect.Value) {
	key := string(field.ContainingMessage().Name()) + "." + string(field.Name())
	nested := field.Kind() == protoreflect.MessageKind || field.Kind() == protoreflect.GroupKind
	if field.IsMap() {
		// version 5 declares no map; a parse would have refused one
		self.withhold("%s is a map this device does not show", name)
		return
	}
	if field.IsList() {
		list := value.List()
		if self.settings.ListMaxCount < list.Len() {
			self.withhold("%s holds %d entries, more than this device shows whole", name, list.Len())
			return
		}
		if !nested {
			values := make([]string, 0, list.Len())
			for i := 0; i < list.Len(); i += 1 {
				values = append(values, self.scalar(fmt.Sprintf("%s[%d]", name, i), key, field, list.Get(i)))
			}
			self.field(name, strings.Join(values, ", "))
			return
		}
		for i := 0; i < list.Len(); i += 1 {
			self.message(fmt.Sprintf("%s[%d]", name, i), list.Get(i).Message())
		}
		return
	}
	if nested {
		self.message(name, value.Message())
		return
	}
	if title, ok := approvalComputeSectionFields[key]; ok && field.Kind() == protoreflect.StringKind {
		self.section(name, title, value.String())
		return
	}
	self.field(name, self.scalar(name, key, field, value))
}

// A nested message field by field, under prefix.
func (self *approvalComputeRenderer) message(prefix string, message protoreflect.Message) {
	for _, number := range setFieldNumbers(message) {
		field := message.Descriptor().Fields().ByNumber(number)
		self.value(prefix+"."+string(field.Name()), field, message.Get(field))
	}
}

// The render of a request whose action is at version 5, as the file header says.
func RenderApprovalRequestCompute(args *ApprovalComputeRenderArgs) *ApprovalRender {
	request := args.Request
	action := request.Action.Action
	settings := args.Settings
	if settings == nil {
		settings = DefaultApprovalComputeRenderSettings()
	}
	render := approvalRenderHead(request)
	render.Compute = &ApprovalComputeRender{}
	renderer := &approvalComputeRenderer{
		settings: settings,
		action:   action,
		render:   render,
		compute:  render.Compute,
		shown:    map[string]string{},
	}
	if action.GetVersion() != canonicalActionVersionCompute {
		renderer.withhold("the action is at version %d, not version 5", action.GetVersion())
	}
	message := action.ProtoReflect()
	for _, number := range setFieldNumbers(message) {
		switch number {
		case canonicalActionFieldKind, canonicalActionFieldVersion, canonicalActionFieldScope, approvalRenderPreviewField:
			continue
		case canonicalActionFieldSealedDetail:
			render.Sealed = true
			continue
		}
		field := message.Descriptor().Fields().ByNumber(number)
		renderer.value(string(field.Name()), field, message.Get(field))
	}
	// the request's own daemon-built fields, its uses among them
	requestMessage := request.Request.ProtoReflect()
	for _, number := range append(slices.Clone(approvalRequestDetailFields), approvalRequestFieldUses) {
		field := requestMessage.Descriptor().Fields().ByNumber(number)
		if requestMessage.Has(field) {
			renderer.field(string(field.Name()), approvalRenderValue(field, requestMessage.Get(field)))
		}
	}
	if render.Sealed {
		if args.Detail == nil {
			renderer.withhold("its sealed detail did not open on this device")
		} else {
			render.Opened = true
			renderer.message(strings.TrimSuffix(approvalRenderSealedPrefix, "."), args.Detail.ProtoReflect())
		}
	}
	renderer.kindChecks(args.Disclosures)
	render.Meaning = renderer.meaning(args.Detail)
	render.Unshown = 0 < len(render.Compute.Withheld)
	return render
}

// What each kind's card needs beyond its fields: kind 19's disclosure line, kind 23's host held to its URL, and the
// kinds whose card this render does not build.
func (self *approvalComputeRenderer) kindChecks(disclosures ApprovalComputeDisclosureLines) {
	action := self.action
	switch SidecarActionKind(action.GetKind()) {
	case SidecarActionEnclaveCreate:
		provider := action.GetEnclave().GetProvider()
		self.compute.DisclosureId = "enclave:" + provider
		if disclosures == nil {
			self.withhold("the provider's disclosure line, which opens this card, does not render on this device")
			return
		}
		line, err := disclosures.ApprovalDisclosureLine(self.compute.DisclosureId)
		if err != nil || line == "" {
			self.withhold("the provider's disclosure line, which opens this card, does not render on this device")
			return
		}
		self.compute.Disclosure = self.text("disclosure", line)
	case SidecarActionFetchUnlistedUrl:
		host, converted := ApprovalUntrustedUrlHost(action.GetUrl())
		switch {
		case host == "":
			self.withhold("the URL names no host this device can read")
		case !converted:
			self.flag("the URL's host does not convert to punycode")
			self.withhold("the URL's host does not convert to punycode, so the host it reaches cannot be shown")
		case host != action.GetHost():
			self.withhold("the action's host is not its URL's host in punycode")
		default:
			self.field("url.host", host)
		}
	case SidecarActionTaintedSend:
		send := action.GetSend()
		if 0 < len(send.GetRefs()) && send.GetText() == "" && send.GetStdin() == "" {
			// a release: its versions' writer, taint and whole text are what the card shows (§16.3)
			self.withhold("a release's versions are shown with their writer, taint and whole text only where this device reads them")
		}
	case SidecarActionCalendarWrite:
		self.withhold("a calendar write's events are shown one card each, with its switch, only by the calendar's card")
	case SidecarActionSupportSend:
		if 0 < len(action.GetSupport().GetFiles()) {
			self.withhold("a message's files are shown whole only by the support conversation's card")
		}
	}
}

// A shown value or its stand-in, for a sentence.
func (self *approvalComputeRenderer) named(path string, otherwise string) string {
	if value := self.shown[path]; value != "" {
		return value
	}
	return otherwise
}

// What approving the action allows, in words around its daemon-built fields, never from an agent's text (§16.3).
func (self *approvalComputeRenderer) meaning(detail *protocol.CanonicalActionDetail5) string {
	action := self.action
	enclave := action.GetEnclave()
	enclaveName := func() string {
		if enclave.GetName() != "" {
			return "enclave " + self.named("enclave.name", "")
		}
		return "enclave " + hex.EncodeToString(enclave.GetEnclaveId())
	}
	switch SidecarActionKind(action.GetKind()) {
	case SidecarActionEgressChange:
		meaning := approvalRenderMeaning(action)
		if meaning == "" {
			meaning = "Change sidecar " + hex.EncodeToString(action.GetSubject()) + "'s egress"
		}
		return meaning + ", after it took tainted input there"
	case SidecarActionEnclaveCreate:
		name := "an enclave whose name did not open on this device"
		if detail != nil {
			name = "enclave " + self.named("sealed_detail.name", "")
		}
		meaning := fmt.Sprintf("Create %s on %s (label %s), shape %s, at %s an hour, its default egress %s", name,
			self.named("enclave.provider", "no provider"), self.named("enclave.label", "none"),
			self.named("enclave.shape", "none"), approvalComputeUsd(enclave.GetPricePerHour()),
			self.named("egress_mode", "unset"))
		if detail.GetRole() == approvalComputeDetailRoleIndexer {
			meaning += ". It will read every member's incoming mail and the mailboxes members grant it"
		}
		return meaning
	case SidecarActionEnclaveEgressDirect:
		return fmt.Sprintf("Turn off %s's default egress: its traffic leaves through the provider, and the miner sees its traffic's metadata",
			enclaveName())
	case SidecarActionComputeBudgetRaise:
		budget := action.GetBudget()
		whose := "a budget"
		switch {
		case len(budget.GetAgentId()) != 0:
			whose = "agent " + hex.EncodeToString(budget.GetAgentId()) + "'s budget"
		case len(detail.GetGrantId()) != 0:
			whose = "gateway grant " + hex.EncodeToString(detail.GetGrantId()) + "'s budget"
		case detail == nil:
			whose = "a budget whose grant did not open on this device"
		}
		period := map[uint32]string{approvalComputeBudgetPeriodDay: "a day", approvalComputeBudgetPeriodMonth: "a month",
			approvalComputeBudgetPeriodRun: "a run"}[budget.GetPeriod()]
		return fmt.Sprintf("Raise %s to %s %s, from %s", whose, approvalComputeUsd(budget.GetAmount()), period,
			approvalComputeUsd(budget.GetCurrent()))
	case SidecarActionEnclaveDelete:
		return fmt.Sprintf("Remove %s (label %s): its running incarnation is revoked and its machine destroyed with everything on it, its settings are erased and its cards retired",
			enclaveName(), self.named("enclave.label", "none"))
	case SidecarActionFetchUnlistedUrl:
		return fmt.Sprintf("Fetch %s, at host %s: the agent composed this URL, and it appeared in nothing the run may fetch from",
			self.named("url", ""), self.named("url.host", self.named("host", "")))
	case SidecarActionTaintedSend:
		return self.sendMeaning()
	case SidecarActionCalendarWrite:
		return fmt.Sprintf("Write %d events to calendar %s at %s", len(action.GetCalendarEvents()),
			self.named("calendar_name", ""), self.named("calendar_host", ""))
	case SidecarActionServiceWrite:
		call := action.GetServiceCall()
		effect := "it changes the person's own data"
		if call.GetClass() == approvalComputeServiceClassSend {
			effect = "it reaches other people"
		}
		target := "https://" + self.named("host", "") + self.named("service_call.path", "")
		if call.GetQuery() != "" {
			target += "?" + self.named("service_call.query", "")
		}
		return fmt.Sprintf("Send %s %s through connection %s to %s as %s: %s", self.named("service_call.method", ""),
			target, self.named("service_call.label", ""), self.named("service_call.service", ""),
			self.named("service_call.account", ""), effect)
	case SidecarActionSupportSend:
		meaning := "Send this message to URnetwork's support: URnetwork's support, and the subprocessors its disclosure names, will read it"
		if entry := action.GetSupport().GetEntry(); entry != "" {
			meaning += ", continuing item " + self.named("support.entry", "")
		}
		return meaning
	}
	return ""
}

// Kind 24's sentence: what is sent, by which tool, to whom, and a continuation's or crossing's counts.
func (self *approvalComputeRenderer) sendMeaning() string {
	action := self.action
	send := action.GetSend()
	var to string
	switch {
	case action.GetEnclave() != nil:
		mode := self.named("egress_mode", "an unnamed egress")
		to = fmt.Sprintf("into enclave %s (label %s, egress %s)",
			self.named("enclave.name", hex.EncodeToString(action.GetEnclave().GetEnclaveId())), self.named("enclave.label", "none"), mode)
	case len(send.GetTargetMemberId()) != 0:
		to = fmt.Sprintf("to member %s's agent %s", hex.EncodeToString(send.GetTargetMemberId()),
			self.named("send.target_agent", hex.EncodeToString(send.GetTargetAgentId())))
	default:
		to = "to sidecar " + hex.EncodeToString(action.GetSubject())
	}
	what := "a message"
	switch send.GetMode() {
	case 1:
		what = "a prompt"
	case 2:
		what = "a steer"
	case approvalComputeSendModeFollowUp:
		what = "a follow-up"
	}
	if send.GetStdin() != "" || send.GetCwd() != "" {
		what = "a command"
	}
	meaning := fmt.Sprintf("Send %s with %s %s, from a run tainted by %s", what, self.named("tool", "an unnamed tool"), to,
		self.named("taint_reasons", "no reason given"))
	if context := action.GetContext(); context != nil {
		act := "Continue"
		if context.GetAct() == approvalComputeContextActCross {
			act = "Cross with"
		}
		meaning = fmt.Sprintf("%s run %s at its node %s, %s: %d nodes, %d flagged and %d untrusted; its context holds %d mail messages, %d calendar events, %d fetched pages and %d connected services' results",
			act, hex.EncodeToString(context.GetRunId()), hex.EncodeToString(context.GetEntryId()), to, context.GetNodes(),
			context.GetFlagged(), context.GetUntrusted(), context.GetMailMessages(), context.GetCalendarEvents(),
			context.GetFetchedPages(), context.GetServiceResults())
	}
	return meaning
}
