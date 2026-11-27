// The ACL document's compute block (DESIGN-COMPUTE §16.4, §16.5; D-CACL-4, R-CCTX-23; CACL-M12-03), under the network's
// compute_policy feature (§16.6): who may run which models, the budgets the broker enforces, the enclaves' floor and
// shapes, and the switches of search, fetch, calendar, connections, support and automatic approvals, read token by
// token against its schema as acl_policy.go reads every key, an unknown or repeated key and a value of the wrong type
// refused:
//
//	assurance_floor          none, AP, A1 or A2: the lowest label remote inference may use; none, every label, by
//	                         default (CO-18, Q-CACL-3's (a))
//	providers                `*` alone, or remote inference providers' slugs, never model names
//	enclave_assurance_floor  AP, A1 or A2: AP by default (Q-PROV-2), which a network may only raise
//	budgets                  [{subjects, per, day_usd, month_usd}]: per subject, agent, member or network, an amount per
//	                         UTC day or month or both, each a positive decimal in USD read exactly into nano-USD, more
//	                         than nine places refused, never a float
//	enclave_shapes           the shapes members may create
//	search                   {enabled, modes, day_max}: §21's tool, its modes and the network's searches a UTC day
//	fetch                    {enabled, egress}: §22's tool, egress auto or exits with its exit
//	calendar                 {enabled, egress}: §23's tools, egress auto, exits with its exit, or direct
//	connect                  {enabled, services, generic, custom, egress}: §25's connections, egress as calendar's
//	support                  {egress, agents, logs}: FB section 5's feedback.egress, on, persons, auto_only or off, and
//	                         whether agents write to support and attach the support log (§28.6)
//	approvals                {auto}: the kinds among 23 to 27 the safety classifier may decide (§27.10), by name
//	disclosures              {id: statement}: the network's acknowledgments by disclosure id, each an Owner's or Admin's
//	                         signed disclosure-ack statement in base64, kept opaque for CTRUST-M12-02 to verify (§2.8)
//	history                  {member_share}: auto, or a share of the network's storage from 0.05 to 1 (§24.10,
//	                         Q-CTXH-16), which §16.4's example omits
//
// Each key narrows where §16.4 says so, and none lets an admin read a member's connection. A network with no document
// keeps the block alone in the config head's compute.hujson (ConfigHeadComputePath), a document holding the compute key
// and nothing else, which sets no reach: the network stays under the implicit document (ParseAclComputeRecord).
// What the block compiles to and when is acl_compute_block_compile.go's: a head naming it while compute_policy is off is
// refused by every reader alike.
//
// The block's bounds are format values every reader holds alike, so two readers never refuse different heads:
// AclComputeBlockSettings, read from its default as the action rules read theirs (QD-702, QD-706).
//
// On every leg, the forwarding role's and the page Worker's included, since every admitted sidecar compiles policy:
// root Id, no connect type. A refusal names a field path and never a value (I-13).

package sidecar

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

// The compute block's bounds (QD-702): format values, the protocol's, which every reader holds alike. The parse reads
// DefaultAclComputeBlockSettings(); the device's ComputePolicySettings carries the same instance's values.
type AclComputeBlockSettings struct {
	// The most budgets a block holds: 256.
	BudgetMaxCount int
	// The most subjects one budget names: 64.
	BudgetSubjectMaxCount int
	// The most one budget's amount may be, in nano-USD: $1,000,000.
	BudgetMaxNanoUsd uint64
	// The most provider slugs `providers` holds: 64, each at most 32 bytes.
	ProviderMaxCount     int
	ProviderMaxByteCount int
	// The most shapes `enclave_shapes` holds: 64, each at most 32 bytes.
	ShapeMaxCount     int
	ShapeMaxByteCount int
	// The most modes search names: 16, each at most 32 bytes.
	SearchModeMaxCount     int
	SearchModeMaxByteCount int
	// The most searches a UTC day `search.day_max` may set: 1,000,000.
	SearchDayMaxLimit uint32
	// The most services `connect.services` names: 256, each at most 64 bytes.
	ServiceMaxCount     int
	ServiceMaxByteCount int
	// The most disclosures the block holds: 64; an id at most 64 bytes; a statement at most 16 KiB of base64.
	DisclosureMaxCount              int
	DisclosureIdMaxByteCount        int
	DisclosureStatementMaxByteCount int
	// history.member_share's bounds, in millionths of the network's storage: 0.05 and 1 (§24.10, Q-CTXH-16).
	MemberShareMinPpm uint32
	MemberShareMaxPpm uint32
	// A model: glob within canonical names (§16.2): at most 128 bytes, a canonical name's bound, and at most 4 `*`,
	// which bounds what one match costs.
	ModelGlobMaxByteCount     int
	ModelGlobWildcardMaxCount int
}

// The block's defaults, the only place one is set.
func DefaultAclComputeBlockSettings() *AclComputeBlockSettings {
	return &AclComputeBlockSettings{
		BudgetMaxCount:                  256,
		BudgetSubjectMaxCount:           64,
		BudgetMaxNanoUsd:                1_000_000 * aclComputeNanoUsdPerUsd,
		ProviderMaxCount:                64,
		ProviderMaxByteCount:            32,
		ShapeMaxCount:                   64,
		ShapeMaxByteCount:               32,
		SearchModeMaxCount:              16,
		SearchModeMaxByteCount:          32,
		SearchDayMaxLimit:               1_000_000,
		ServiceMaxCount:                 256,
		ServiceMaxByteCount:             64,
		DisclosureMaxCount:              64,
		DisclosureIdMaxByteCount:        64,
		DisclosureStatementMaxByteCount: 16 * 1024,
		MemberShareMinPpm:               50_000,
		MemberShareMaxPpm:               aclComputePpmWhole,
		ModelGlobMaxByteCount:           128,
		ModelGlobWildcardMaxCount:       4,
	}
}

// Units, not limits: nano-USD in a dollar, its nine places, and the millionths of a whole share.
const (
	aclComputeNanoUsdPerUsd uint64 = 1_000_000_000
	aclComputeUsdPlaces            = 9
	aclComputePpmWhole      uint32 = 1_000_000
	aclComputePpmPlaces            = 6
)

// Every provider, every service: `*`.
const aclComputeEvery = "*"

// What a budget is per (§16.4), AclComputeBudgetRow.per's values.
type AclComputeBudgetPer uint32

const (
	// Each subject the selectors name has a budget of its own.
	AclComputeBudgetPerSubject AclComputeBudgetPer = 1
	// Each agent id under the subjects has one.
	AclComputeBudgetPerAgent AclComputeBudgetPer = 2
	// Each member, across their devices.
	AclComputeBudgetPerMember AclComputeBudgetPer = 3
	// One for the network, across the subjects.
	AclComputeBudgetPerNetwork AclComputeBudgetPer = 4
)

// The per values by name.
var aclComputeBudgetPers = map[string]AclComputeBudgetPer{
	"subject": AclComputeBudgetPerSubject, "agent": AclComputeBudgetPerAgent,
	"member": AclComputeBudgetPerMember, "network": AclComputeBudgetPerNetwork,
}

// The floors by name: the inference floor takes all four, the enclaves' AP and above.
var aclComputeAssurances = map[string]protocol.ComputeAssurance{
	"none": protocol.ComputeAssurance_COMPUTE_ASSURANCE_NONE,
	"AP":   protocol.ComputeAssurance_COMPUTE_ASSURANCE_AP,
	"A1":   protocol.ComputeAssurance_COMPUTE_ASSURANCE_A1,
	"A2":   protocol.ComputeAssurance_COMPUTE_ASSURANCE_A2,
}

// An egress a tool's traffic leaves by (§22, §23.7, §25.8).
type AclComputeEgress string

const (
	// URnetwork's network, the connect client's destination.
	AclComputeEgressAuto AclComputeEgress = "auto"
	// An exit of the network's, a tag's or a named one, the block's exit.
	AclComputeEgressExits AclComputeEgress = "exits"
	// From the device's own address: calendars and connections only (§23.7, §25.8), never a fetch (§22.4).
	AclComputeEgressDirect AclComputeEgress = "direct"
)

// The kinds automatic approvals may decide (§27.4, §27.10), by name.
var aclComputeApprovalKinds = map[string]SidecarActionKind{
	"fetch_unlisted_url": SidecarActionFetchUnlistedUrl,
	"tainted_send":       SidecarActionTaintedSend,
	"calendar_write":     SidecarActionCalendarWrite,
	"service_write":      SidecarActionServiceWrite,
	"support_send":       SidecarActionSupportSend,
}

// The kinds automatic approvals decide by default, all five (§16.5), in order.
var aclComputeApprovalKindsAll = []SidecarActionKind{
	SidecarActionFetchUnlistedUrl, SidecarActionTaintedSend, SidecarActionCalendarWrite, SidecarActionServiceWrite,
	SidecarActionSupportSend,
}

// FB section 5's feedback.egress values (§28.6).
var aclComputeSupportEgresses = []string{"on", "persons", "auto_only", "off"}

// The disclosure id families §2.8 names, ahead of their slug.
var aclComputeDisclosureFamilies = []string{"search", "inference", "enclave", "connect", "listeners", "approvals"}

// One parsed compute block. A key the block leaves out reads as its zero here, nil or 0, and §16.5's default holds
// for it (ComputePolicyView). Immutable once parsed: lists in the order written.
type AclComputeBlock struct {
	// 0 where the block leaves it out.
	AssuranceFloor protocol.ComputeAssurance
	// Nil where left out; [`*`] for every provider.
	Providers []string
	// 0 where left out: AP.
	EnclaveAssuranceFloor protocol.ComputeAssurance
	Budgets               []AclComputeBudget
	// Nil where left out: every shape the policy offers.
	EnclaveShapes []string
	// Each nil where left out.
	Search      *AclComputeSearch
	Fetch       *AclComputeRoute
	Calendar    *AclComputeRoute
	Connect     *AclComputeConnect
	Support     *AclComputeSupport
	Approvals   *AclComputeApprovals
	Disclosures []AclComputeDisclosure
	History     *AclComputeHistory
}

// One budget (§16.4).
type AclComputeBudget struct {
	Subjects []AclSelector
	Per      AclComputeBudgetPer
	// What its subjects may be charged a UTC day and a UTC month, in nano-USD; 0 for a period it does not cap.
	DayNanoUsd   uint64
	MonthNanoUsd uint64
}

// search (§21.9).
type AclComputeSearch struct {
	// Nil where left out.
	Enabled *bool
	// Nil where left out: every mode.
	Modes []string
	// 0 where left out: the broker's default cap.
	DayMax uint32
}

// fetch and calendar (§22.7, §23.7).
type AclComputeRoute struct {
	// Nil where left out.
	Enabled *bool
	// "" where left out: auto.
	Egress AclComputeEgress
	// Under exits, the exit: a tag: or sidecar: selector. Nil otherwise.
	Exit *AclSelector
}

// connect (§25.8).
type AclComputeConnect struct {
	AclComputeRoute
	// Nil where left out: every service the policy lists, as [`*`] says.
	Services []string
	// Each nil where left out: service_call offered, members' own definitions on desktops.
	Generic *bool
	Custom  *bool
}

// support (§28.6).
type AclComputeSupport struct {
	// "" where left out: on.
	Egress string
	// Each nil where left out: true.
	Agents *bool
	Logs   *bool
}

// approvals (§27.10).
type AclComputeApprovals struct {
	// The kinds the classifier may decide, in the order written; empty sends every such approval to a person.
	Auto []SidecarActionKind
}

// One acknowledgment the network holds (§2.8, CO-41).
type AclComputeDisclosure struct {
	// The disclosure's id, such as inference:engy.
	Id string
	// The signed disclosure-ack statement as the document holds it, standard base64: opaque here, CTRUST-M12-02's to
	// verify.
	Statement string
}

// history (§24.10).
type AclComputeHistory struct {
	// auto: the whole for a network of one member, 2/n for one of n (Q-CTXH-16).
	MemberShareAuto bool
	// Otherwise the share in millionths, within the settings' bounds.
	MemberSharePpm uint32
}

// Every selector the block names, budgets' subjects and egress exits, in the order written: what a writer's tables must
// hold names for.
func (self *AclComputeBlock) selectors() []AclSelector {
	if self == nil {
		return nil
	}
	selectors := []AclSelector{}
	for _, budget := range self.Budgets {
		selectors = append(selectors, budget.Subjects...)
	}
	for _, route := range []*AclComputeRoute{self.Fetch, self.Calendar, self.connectRoute()} {
		if route != nil && route.Exit != nil {
			selectors = append(selectors, *route.Exit)
		}
	}
	return selectors
}

// connect's route, nil without connect.
func (self *AclComputeBlock) connectRoute() *AclComputeRoute {
	if self == nil || self.Connect == nil {
		return nil
	}
	return &self.Connect.AclComputeRoute
}

// The block, at the document's top level.
func (self *aclPolicyReader) readComputeBlock() (*AclComputeBlock, error) {
	settings := DefaultAclComputeBlockSettings()
	block := &AclComputeBlock{}
	err := self.readFields(func(key string) func() error {
		switch key {
		case "assurance_floor":
			return func() (err error) {
				block.AssuranceFloor, err = self.readComputeAssurance(false)
				return err
			}
		case "providers":
			return func() (err error) {
				block.Providers, err = self.readComputeNames(settings.ProviderMaxCount, settings.ProviderMaxByteCount, true, aclComputeProviderSlug)
				return err
			}
		case "enclave_assurance_floor":
			return func() (err error) {
				block.EnclaveAssuranceFloor, err = self.readComputeAssurance(true)
				return err
			}
		case "budgets":
			return func() error {
				block.Budgets = []AclComputeBudget{}
				return self.readArray(func() error {
					if settings.BudgetMaxCount <= len(block.Budgets) {
						return self.refuse(aclPolicyRefusal("more budgets than a block holds"))
					}
					budget, err := self.readComputeBudget(settings)
					block.Budgets = append(block.Budgets, budget)
					return err
				})
			}
		case "enclave_shapes":
			return func() (err error) {
				block.EnclaveShapes, err = self.readComputeNames(settings.ShapeMaxCount, settings.ShapeMaxByteCount, false, aclComputeSlug)
				return err
			}
		case "search":
			return func() (err error) {
				block.Search, err = self.readComputeSearch(settings)
				return err
			}
		case "fetch":
			return func() (err error) {
				block.Fetch, err = self.readComputeRoute(false)
				return err
			}
		case "calendar":
			return func() (err error) {
				block.Calendar, err = self.readComputeRoute(true)
				return err
			}
		case "connect":
			return func() (err error) {
				block.Connect, err = self.readComputeConnect(settings)
				return err
			}
		case "support":
			return func() (err error) {
				block.Support, err = self.readComputeSupport()
				return err
			}
		case "approvals":
			return func() (err error) {
				block.Approvals, err = self.readComputeApprovals()
				return err
			}
		case "disclosures":
			return func() (err error) {
				block.Disclosures, err = self.readComputeDisclosures(settings)
				return err
			}
		case "history":
			return func() (err error) {
				block.History, err = self.readComputeHistory(settings)
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return block, nil
}

// A floor by name: none, AP, A1 or A2, the enclaves' AP or above, since a network only raises theirs (Q-PROV-2).
func (self *aclPolicyReader) readComputeAssurance(enclave bool) (protocol.ComputeAssurance, error) {
	return aclPolicyRead(self, func(text string) (protocol.ComputeAssurance, error) {
		assurance, known := aclComputeAssurances[text]
		if !known || (enclave && assurance == protocol.ComputeAssurance_COMPUTE_ASSURANCE_NONE) {
			return 0, aclPolicyRefusal("an unknown assurance floor")
		}
		return assurance, nil
	})
}

// A slug: lowercase letters and digits, with inner hyphens.
func aclComputeSlug(text string) bool {
	if text == "" || text[0] == '-' || text[len(text)-1] == '-' {
		return false
	}
	return strings.Trim(text, aclLowerAlphanumerics+"-") == ""
}

// A provider's slug: §6.3's [a-z0-9]+, the first part of a canonical name, so a model's name, which holds a hyphen,
// is never one.
func aclComputeProviderSlug(text string) bool {
	return text != "" && strings.Trim(text, aclLowerAlphanumerics) == ""
}

// A list of names, each at most maxByteCount bytes and valid, none twice, at most maxCount; where every is allowed, `*`
// alone stands for all. Never empty: a list naming nothing would read as no default.
func (self *aclPolicyReader) readComputeNames(maxCount int, maxByteCount int, every bool, valid func(text string) bool) ([]string, error) {
	names, err := aclPolicyReadList(self, func(text string) (string, error) {
		if every && text == aclComputeEvery {
			return text, nil
		}
		if maxByteCount < len(text) || !valid(text) {
			return "", aclPolicyRefusal("not a name this list takes")
		}
		return text, nil
	}, false)
	if err != nil {
		return nil, err
	}
	switch {
	case maxCount < len(names):
		return nil, self.refuse(aclPolicyRefusal("more names than the list holds"))
	case slices.Contains(names, aclComputeEvery) && len(names) != 1:
		return nil, self.refuse(aclPolicyRefusal("* beside names"))
	}
	sorted := slices.Clone(names)
	slices.Sort(sorted)
	if len(slices.Compact(sorted)) != len(names) {
		return nil, self.refuse(aclPolicyRefusal("a name given twice"))
	}
	return names, nil
}

// One budget.
func (self *aclPolicyReader) readComputeBudget(settings *AclComputeBlockSettings) (AclComputeBudget, error) {
	budget := AclComputeBudget{}
	hasPer := false
	err := self.readFields(func(key string) func() error {
		switch key {
		case "subjects":
			return func() (err error) {
				if budget.Subjects, err = self.readSelectors(aclPositionSrc); err == nil && settings.BudgetSubjectMaxCount < len(budget.Subjects) {
					err = self.refuse(aclPolicyRefusal("more subjects than a budget names"))
				}
				return err
			}
		case "per":
			return func() (err error) {
				hasPer = true
				budget.Per, err = aclPolicyRead(self, func(text string) (AclComputeBudgetPer, error) {
					per, known := aclComputeBudgetPers[text]
					if !known {
						return 0, aclPolicyRefusal("an unknown per")
					}
					return per, nil
				})
				return err
			}
		case "day_usd":
			return func() (err error) {
				budget.DayNanoUsd, err = self.readComputeUsd(settings)
				return err
			}
		case "month_usd":
			return func() (err error) {
				budget.MonthNanoUsd, err = self.readComputeUsd(settings)
				return err
			}
		}
		return nil
	})
	if err != nil {
		return AclComputeBudget{}, err
	}
	switch {
	case budget.Subjects == nil:
		return AclComputeBudget{}, self.refuse(aclPolicyRefusal("a budget with no subjects"))
	case !hasPer:
		return AclComputeBudget{}, self.refuse(aclPolicyRefusal("a budget with no per"))
	case budget.DayNanoUsd == 0 && budget.MonthNanoUsd == 0:
		return AclComputeBudget{}, self.refuse(aclPolicyRefusal("a budget with no amount"))
	}
	return budget, nil
}

// A JSON number, refusing any other type.
func (self *aclPolicyReader) readNumber() (json.Number, error) {
	token, err := self.readToken()
	if err != nil {
		return "", err
	}
	number, isNumber := token.(json.Number)
	if !isNumber {
		return "", self.refuse(aclPolicyRefusal("not a number"))
	}
	return number, nil
}

// A true or false, refusing any other type.
func (self *aclPolicyReader) readBool() (*bool, error) {
	token, err := self.readToken()
	if err != nil {
		return nil, err
	}
	value, isBool := token.(bool)
	if !isBool {
		return nil, self.refuse(aclPolicyRefusal("not true or false"))
	}
	return &value, nil
}

// A decimal of at most places places, digits and one point, as a whole count of 10^-places units, refusing a sign,
// an exponent and a value past most. One spelling of each value: JSON's own grammar already refuses leading zeros.
func aclComputeDecimal(number json.Number, places int, most uint64) (uint64, error) {
	text := string(number)
	whole, fraction, hasFraction := strings.Cut(text, ".")
	if whole == "" || strings.Trim(whole, "0123456789") != "" || (hasFraction && (fraction == "" || strings.Trim(fraction, "0123456789") != "")) {
		return 0, aclPolicyRefusal("not a plain decimal")
	}
	if places < len(fraction) {
		return 0, aclPolicyRefusal("more decimal places than its unit holds")
	}
	fraction += strings.Repeat("0", places-len(fraction))
	scale := uint64(1)
	for range places {
		scale *= 10
	}
	wholeValue, err := strconv.ParseUint(whole, 10, 64)
	if err != nil || most/scale < wholeValue {
		return 0, aclPolicyRefusal("past the most it may be")
	}
	fractionValue := uint64(0)
	if fraction != "" {
		if fractionValue, err = strconv.ParseUint(fraction, 10, 64); err != nil {
			return 0, aclPolicyRefusal("not a plain decimal")
		}
	}
	value := wholeValue*scale + fractionValue
	if most < value {
		return 0, aclPolicyRefusal("past the most it may be")
	}
	return value, nil
}

// An amount in USD, exactly, as nano-USD: positive, at most nine places and the settings' most.
func (self *aclPolicyReader) readComputeUsd(settings *AclComputeBlockSettings) (uint64, error) {
	number, err := self.readNumber()
	if err != nil {
		return 0, err
	}
	nanoUsd, err := aclComputeDecimal(number, aclComputeUsdPlaces, settings.BudgetMaxNanoUsd)
	if err != nil {
		return 0, self.refuse(err)
	}
	if nanoUsd == 0 {
		return 0, self.refuse(aclPolicyRefusal("an amount of nothing"))
	}
	return nanoUsd, nil
}

// search: {enabled, modes, day_max}.
func (self *aclPolicyReader) readComputeSearch(settings *AclComputeBlockSettings) (*AclComputeSearch, error) {
	search := &AclComputeSearch{}
	err := self.readFields(func(key string) func() error {
		switch key {
		case "enabled":
			return func() (err error) {
				search.Enabled, err = self.readBool()
				return err
			}
		case "modes":
			return func() (err error) {
				search.Modes, err = self.readComputeNames(settings.SearchModeMaxCount, settings.SearchModeMaxByteCount, false, aclComputeSlug)
				return err
			}
		case "day_max":
			return func() error {
				number, err := self.readNumber()
				if err != nil {
					return err
				}
				count, err := aclComputeDecimal(number, 0, uint64(settings.SearchDayMaxLimit))
				if err != nil || count == 0 {
					return self.refuse(aclPolicyRefusal("not a count of searches"))
				}
				search.DayMax = uint32(count)
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return search, nil
}

// An egress and its exit, read from route's own keys; direct only where the tool takes it.
func (self *aclPolicyReader) readComputeRouteField(key string, route *AclComputeRoute, direct bool) func() error {
	switch key {
	case "enabled":
		return func() (err error) {
			route.Enabled, err = self.readBool()
			return err
		}
	case "egress":
		return func() (err error) {
			route.Egress, err = aclPolicyRead(self, func(text string) (AclComputeEgress, error) {
				switch egress := AclComputeEgress(text); egress {
				case AclComputeEgressAuto, AclComputeEgressExits:
					return egress, nil
				case AclComputeEgressDirect:
					if direct {
						return egress, nil
					}
				}
				return "", aclPolicyRefusal("an egress this tool does not take")
			})
			return err
		}
	case "exit":
		return func() error {
			exit, err := aclPolicyRead(self, func(text string) (AclSelector, error) {
				selector, err := parseAclSelector(text, aclPositionVia)
				if err == nil && selector.Kind != AclSelectorTag && selector.Kind != AclSelectorSidecar {
					err = aclPolicyRefusal("an exit that is no tag: or sidecar:")
				}
				return selector, err
			})
			route.Exit = &exit
			return err
		}
	}
	return nil
}

// Refuses an exit without exits, and exits without its exit.
func (self *aclPolicyReader) checkComputeRoute(route *AclComputeRoute) error {
	if (route.Egress == AclComputeEgressExits) != (route.Exit != nil) {
		return self.refuse(aclPolicyRefusal("exits names its exit, and only exits does"))
	}
	return nil
}

// fetch or calendar: {enabled, egress, exit}, calendar's egress also direct.
func (self *aclPolicyReader) readComputeRoute(direct bool) (*AclComputeRoute, error) {
	route := &AclComputeRoute{}
	err := self.readFields(func(key string) func() error {
		return self.readComputeRouteField(key, route, direct)
	})
	if err != nil {
		return nil, err
	}
	if err := self.checkComputeRoute(route); err != nil {
		return nil, err
	}
	return route, nil
}

// connect: {enabled, services, generic, custom, egress, exit}.
func (self *aclPolicyReader) readComputeConnect(settings *AclComputeBlockSettings) (*AclComputeConnect, error) {
	connect := &AclComputeConnect{}
	err := self.readFields(func(key string) func() error {
		if read := self.readComputeRouteField(key, &connect.AclComputeRoute, true); read != nil {
			return read
		}
		switch key {
		case "services":
			return func() (err error) {
				connect.Services, err = self.readComputeNames(settings.ServiceMaxCount, settings.ServiceMaxByteCount, true, func(text string) bool {
					return text != "" && strings.Trim(text, aclLowerAlphanumerics+"-_.") == ""
				})
				return err
			}
		case "generic":
			return func() (err error) {
				connect.Generic, err = self.readBool()
				return err
			}
		case "custom":
			return func() (err error) {
				connect.Custom, err = self.readBool()
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := self.checkComputeRoute(&connect.AclComputeRoute); err != nil {
		return nil, err
	}
	return connect, nil
}

// support: {egress, agents, logs}.
func (self *aclPolicyReader) readComputeSupport() (*AclComputeSupport, error) {
	support := &AclComputeSupport{}
	err := self.readFields(func(key string) func() error {
		switch key {
		case "egress":
			return func() (err error) {
				support.Egress, err = aclPolicyRead(self, func(text string) (string, error) {
					if !slices.Contains(aclComputeSupportEgresses, text) {
						return "", aclPolicyRefusal("an unknown support egress")
					}
					return text, nil
				})
				return err
			}
		case "agents":
			return func() (err error) {
				support.Agents, err = self.readBool()
				return err
			}
		case "logs":
			return func() (err error) {
				support.Logs, err = self.readBool()
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return support, nil
}

// approvals: {auto: [kind names]}, which may be empty, each kind once.
func (self *aclPolicyReader) readComputeApprovals() (*AclComputeApprovals, error) {
	approvals := &AclComputeApprovals{}
	hasAuto := false
	err := self.readFields(func(key string) func() error {
		if key != "auto" {
			return nil
		}
		return func() error {
			hasAuto = true
			kinds, err := aclPolicyReadList(self, func(text string) (SidecarActionKind, error) {
				kind, known := aclComputeApprovalKinds[text]
				if !known {
					return 0, aclPolicyRefusal("a kind automatic approvals do not decide")
				}
				return kind, nil
			}, true)
			if err != nil {
				return err
			}
			sorted := slices.Clone(kinds)
			slices.Sort(sorted)
			if len(slices.Compact(sorted)) != len(kinds) {
				return self.refuse(aclPolicyRefusal("a kind given twice"))
			}
			approvals.Auto = kinds
			return nil
		}
	})
	if err != nil {
		return nil, err
	}
	if !hasAuto {
		return nil, self.refuse(aclPolicyRefusal("approvals with no auto"))
	}
	return approvals, nil
}

// Whether id is a disclosure id of a family §2.8 names: <family>:<slug>.
func aclComputeDisclosureId(id string, settings *AclComputeBlockSettings) bool {
	family, slug, found := strings.Cut(id, ":")
	return found && len(id) <= settings.DisclosureIdMaxByteCount && slices.Contains(aclComputeDisclosureFamilies, family) &&
		aclComputeSlug(slug)
}

// disclosures: {id: statement}, each statement standard base64 within its bound, kept as written.
func (self *aclPolicyReader) readComputeDisclosures(settings *AclComputeBlockSettings) ([]AclComputeDisclosure, error) {
	disclosures := []AclComputeDisclosure{}
	err := self.readEntries(func(key string) error {
		if !aclComputeDisclosureId(key, settings) {
			return self.refuse(aclPolicyRefusal("not a disclosure id"))
		}
		if settings.DisclosureMaxCount <= len(disclosures) {
			return self.refuse(aclPolicyRefusal("more disclosures than a block holds"))
		}
		statement, err := aclPolicyRead(self, func(text string) (string, error) {
			if text == "" || settings.DisclosureStatementMaxByteCount < len(text) {
				return "", aclPolicyRefusal("not a statement within its bound")
			}
			if _, err := base64.StdEncoding.Strict().DecodeString(text); err != nil {
				return "", aclPolicyRefusal("a statement that is not standard base64")
			}
			return text, nil
		})
		disclosures = append(disclosures, AclComputeDisclosure{Id: key, Statement: statement})
		return err
	})
	if err != nil {
		return nil, err
	}
	return disclosures, nil
}

// history: {member_share: auto, or a share from the settings' least to the whole, at most six places}.
func (self *aclPolicyReader) readComputeHistory(settings *AclComputeBlockSettings) (*AclComputeHistory, error) {
	history := &AclComputeHistory{}
	hasShare := false
	err := self.readFields(func(key string) func() error {
		if key != "member_share" {
			return nil
		}
		return func() error {
			hasShare = true
			token, err := self.readToken()
			if err != nil {
				return err
			}
			switch value := token.(type) {
			case string:
				if value != "auto" {
					return self.refuse(aclPolicyRefusal("a share that is neither auto nor a number"))
				}
				history.MemberShareAuto = true
				return nil
			case json.Number:
				ppm, err := aclComputeDecimal(value, aclComputePpmPlaces, uint64(aclComputePpmWhole))
				if err != nil || ppm < uint64(settings.MemberShareMinPpm) || uint64(settings.MemberShareMaxPpm) < ppm {
					return self.refuse(aclPolicyRefusal("a share outside its bounds"))
				}
				history.MemberSharePpm = uint32(ppm)
				return nil
			}
			return self.refuse(aclPolicyRefusal("a share that is neither auto nor a number"))
		}
	})
	if err != nil {
		return nil, err
	}
	if !hasShare {
		return nil, self.refuse(aclPolicyRefusal("history with no member_share"))
	}
	return history, nil
}

// The block-alone record's path in a config head (§16.4; Appendix D's §7.9 ACL document rows): a network with no
// document keeps its compute block here, a document holding the compute key and nothing else, which sets no reach.
const ConfigHeadComputePath = "compute.hujson"

// A block-alone record that is no record: one holding a key beside compute, or no compute.
var ErrAclComputeRecordInvalid = errors.New("invalid compute record")

// The network has a document, which holds its own compute block: a block-alone record has no place beside it, and a
// first document that names a block of its own while the network keeps one alone needs the person to reconcile them.
var ErrAclComputeRecordBesideDocument = errors.New("the network's document holds its compute block, so no block-alone record stands beside it")

// The block a network with no document keeps alone (ConfigHeadComputePath): HuJSON holding {"compute": {...}} and no
// other key, parsed as a document's block is. nil and an error wrapping ErrAclPolicyInvalid, and ErrAclComputeRecordInvalid
// for one holding anything else, for a record it refuses.
func ParseAclComputeRecord(source []byte) (*AclComputeBlock, error) {
	policy, err := ParseAclPolicy(source)
	if err != nil {
		return nil, err
	}
	if policy.Compute == nil || !aclComputeRecordAlone(source) {
		return nil, fmt.Errorf("%w: %w: it holds a key beside compute, or no compute", ErrAclPolicyInvalid, ErrAclComputeRecordInvalid)
	}
	return policy.Compute, nil
}

// Whether source's top-level object holds the compute key and no other: what a parse that filled defaults cannot tell.
func aclComputeRecordAlone(source []byte) bool {
	standard, err := aclStandardizeHujson(source)
	if err != nil {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(standard))
	decoder.UseNumber()
	keys := []string{}
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return false
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		key, _ := token.(string)
		keys = append(keys, key)
		var skipped json.RawMessage
		if err := decoder.Decode(&skipped); err != nil {
			return false
		}
	}
	return slices.Equal(keys, []string{"compute"})
}
