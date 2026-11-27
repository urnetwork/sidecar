// DESIGN-COMPUTE §16.2's resources and actions (D-CACL-1; CACL-M12-04) on CACL-M11-05's numbers, beside §8.4's:
//
//	model:<glob>          infer: run a remote model whose canonical name the glob matches, `*` inside a name and never
//	                      read as a label (R1-56), so a grant never passes the network's floor or the person's tee_only;
//	                      a local model needs no grant (CO-9)
//	compute:enclave       create, and admin: stop or delete another subject's enclave, never start one, a start being
//	                      its sponsor's (§11.4); a rule may name the shapes it allows
//	compute:buy           buy: buy credits, redeem promotion codes and set auto-renew, beside the Owner's and Billing
//	                      admin's roles (§9.10; QD-1389's word)
//	compute:search        query: run a web search (§21)
//	a subject             ssh, with users among agent, root and edit and an optional check period (§12.5), the dst
//	                      usually tag:enclave or tag:enclave-<id>
//	listener:<selector>   dial: each listed socket and map entry of the subjects *, tag:, group:, user:, sidecar: or
//	                      autogroup: name, at their overlay addresses, an ip field narrowing the ports (§26.7)
//
// A rule naming one of these names that kind of destination alone, and only its own actions: infer on model:, create
// and admin on compute:enclave, buy on compute:buy, query on compute:search, ssh on subjects, dial on listener:; and
// §16.2's actions stand on no other destination. `*` in allow stays §8.4's nine actions, so no document that wrote it,
// the frozen implicit one among them, compiles another row at a release.
//
// What rows carry: model_glob, compute_resource and listener (an atom, as atom holds one) targets, each its own kind,
// and the actions by number. What stays on the device, as ports and prefixes do: an ssh grant's users and check period
// (AclLocalSsh), a compute:enclave rule's shapes and a listener grant's ports (AclLocalRule).
//
// Every reader refuses them before their feature's base alike: listener: under listeners, the rest under
// compute_policy (§16.6's table), a head naming one while its feature is off compiling in no reader; a reader built
// before them refuses the resource or the action as unknown. The compute_policy feature's implicit rules are
// acl_compute_implicit.hujson's, which compile after the frozen implicit document once the feature is on.
//
// On every leg, as the policy's parse is: root Id, no connect type. A refusal names no value (I-13).

package sidecar

import (
	_ "embed"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// §16.2's resources, beside §8.4's kinds.
const (
	// model:<glob>
	AclResourceModel AclResourceKind = 101 + iota
	// compute:enclave, compute:buy, compute:search
	AclResourceCompute
	// listener:<selector>
	AclResourceListener
)

// §16.2's actions by name. `*` in allow does not take them (aclNameActions stays §8.4's).
var aclComputeNameActions = map[string]protocol.AclAction{
	"infer":  protocol.AclAction_ACL_ACTION_INFER,
	"create": protocol.AclAction_ACL_ACTION_CREATE,
	"buy":    protocol.AclAction_ACL_ACTION_BUY,
	"query":  protocol.AclAction_ACL_ACTION_QUERY,
	"ssh":    protocol.AclAction_ACL_ACTION_SSH,
}

// compute:<name>'s resources.
var aclComputeResourceNames = map[string]protocol.AclComputeResource{
	"enclave": protocol.AclComputeResource_ACL_COMPUTE_RESOURCE_ENCLAVE,
	"buy":     protocol.AclComputeResource_ACL_COMPUTE_RESOURCE_BUY,
	"search":  protocol.AclComputeResource_ACL_COMPUTE_RESOURCE_SEARCH,
}

// Each compute resource's own actions.
var aclComputeResourceActions = map[protocol.AclComputeResource][]protocol.AclAction{
	protocol.AclComputeResource_ACL_COMPUTE_RESOURCE_ENCLAVE: {protocol.AclAction_ACL_ACTION_CREATE, protocol.AclAction_ACL_ACTION_ADMIN},
	protocol.AclComputeResource_ACL_COMPUTE_RESOURCE_BUY:     {protocol.AclAction_ACL_ACTION_BUY},
	protocol.AclComputeResource_ACL_COMPUTE_RESOURCE_SEARCH:  {protocol.AclAction_ACL_ACTION_QUERY},
}

// An ssh grant's users (§12.5).
var aclComputeSshUsers = []string{"agent", "root", "edit"}

// The name compute:<name> writes for a resource, "" for none.
func aclComputeResourceName(resource protocol.AclComputeResource) string {
	for name, named := range aclComputeResourceNames {
		if named == resource {
			return name
		}
	}
	return ""
}

// §16.2's actions' names, for the canonical forms and grant actions (aclActionName): "" for another action.
func aclComputeActionName(action protocol.AclAction) string {
	for name, named := range aclComputeNameActions {
		if named == action {
			return name
		}
	}
	return ""
}

// Whether action is one of §16.2's, which only their own destinations take.
func aclComputeAction(action protocol.AclAction) bool {
	return aclComputeActionName(action) != ""
}

// A glob within canonical names: §6.3's characters [a-z0-9.-] and `*`, at most the settings' bytes and wildcards. A
// label is no glob's word: none, AP, A1 and A2 match nothing but a name that holds them (R1-56).
func aclComputeModelGlob(glob string, settings *AclComputeBlockSettings) bool {
	if glob == "" || settings.ModelGlobMaxByteCount < len(glob) || settings.ModelGlobWildcardMaxCount < strings.Count(glob, "*") {
		return false
	}
	return strings.Trim(glob, aclLowerAlphanumerics+".-*") == ""
}

// Whether glob matches a canonical name: `*` takes any run of characters, the others match themselves. Linear in the
// name for each star, which ModelGlobWildcardMaxCount bounds.
func AclComputeModelGlobMatch(glob string, name string) bool {
	parts := strings.Split(glob, "*")
	if len(parts) == 1 {
		return glob == name
	}
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	rest := name[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, part := range parts[1 : len(parts)-1] {
		index := strings.Index(rest, part)
		if index < 0 {
			return false
		}
		rest = rest[index+len(part):]
	}
	return len(last) <= len(rest) && strings.HasSuffix(rest, last)
}

// A compute resource's text, its scheme cut: model:<glob>, compute:<name> or listener:<selector>.
func parseAclComputeResource(scheme string, value string) (AclResource, error) {
	switch scheme {
	case "model":
		if !aclComputeModelGlob(value, DefaultAclComputeBlockSettings()) {
			return AclResource{}, aclPolicyRefusal("not a glob within canonical names")
		}
		return AclResource{Kind: AclResourceModel, Name: value}, nil
	case "compute":
		resource, known := aclComputeResourceNames[value]
		if !known {
			return AclResource{}, aclPolicyRefusal("not a compute resource")
		}
		return AclResource{Kind: AclResourceCompute, ComputeResource: resource}, nil
	case "listener":
		if value == "*" {
			return AclResource{Kind: AclResourceListener, Subject: AclSelector{Kind: AclSelectorAutogroup, Autogroup: protocol.AclAutogroup_ACL_AUTOGROUP_NETWORK}}, nil
		}
		selector, err := parseAclSelector(value, aclPositionDst)
		if err != nil {
			return AclResource{}, err
		}
		switch {
		case selector.Kind == AclSelectorAutogroup && selector.Autogroup == protocol.AclAutogroup_ACL_AUTOGROUP_INTERNET:
		case selector.Kind == AclSelectorTag, selector.Kind == AclSelectorGroup, selector.Kind == AclSelectorUser,
			selector.Kind == AclSelectorSidecar, selector.Kind == AclSelectorAutogroup:
			return AclResource{Kind: AclResourceListener, Subject: selector}, nil
		}
		return AclResource{}, aclPolicyRefusal("a listener: selector of a kind §26.7 does not name")
	}
	return AclResource{}, aclPolicyRefusal("not a resource")
}

// A compute resource's §16.2 text, "" for another kind.
func aclComputeResourceText(resource AclResource) string {
	switch resource.Kind {
	case AclResourceModel:
		return "model:" + resource.Name
	case AclResourceCompute:
		return "compute:" + aclComputeResourceName(resource.ComputeResource)
	case AclResourceListener:
		if resource.Subject.Kind == AclSelectorAutogroup && resource.Subject.Autogroup == protocol.AclAutogroup_ACL_AUTOGROUP_NETWORK {
			return "listener:*"
		}
		return "listener:" + resource.Subject.String()
	}
	return ""
}

// The feature a resource needs, 0 for one of §8.4's.
func aclComputeResourceFeature(resource AclResource) AuthFeature {
	switch resource.Kind {
	case AclResourceModel, AclResourceCompute:
		return AuthFeatureComputePolicy
	case AclResourceListener:
		return AuthFeatureListeners
	}
	return 0
}

// What one rule's compute keys hold, before they are checked against its destinations.
type aclComputeRuleKeys struct {
	users  []string
	check  time.Duration
	shapes []string
	// which keys were written, for the refusals
	hasUsers  bool
	hasCheck  bool
	hasShapes bool
}

// The read for a grant's compute key, nil for any other: users, check and shapes.
func (self *aclPolicyReader) readComputeRuleField(key string, keys *aclComputeRuleKeys) func() error {
	settings := DefaultAclComputeBlockSettings()
	switch key {
	case "users":
		return func() (err error) {
			keys.hasUsers = true
			keys.users, err = self.readComputeNames(len(aclComputeSshUsers), len("agent"), false, func(text string) bool {
				return slices.Contains(aclComputeSshUsers, text)
			})
			return err
		}
	case "check":
		return func() (err error) {
			keys.hasCheck = true
			keys.check, err = aclPolicyRead(self, parseAclDuration)
			return err
		}
	case "shapes":
		return func() (err error) {
			keys.hasShapes = true
			keys.shapes, err = self.readComputeNames(settings.ShapeMaxCount, settings.ShapeMaxByteCount, false, aclComputeSlug)
			return err
		}
	}
	return nil
}

// Refuses a rule whose compute destinations or actions do not go together (the file header): a compute destination
// beside another kind, an action its destination does not take, one of §16.2's actions on any other destination, an
// ssh grant without users or an ssh rule with any other action, and users, check or shapes on a rule they do not fit.
// A requests rule names no users: the filed request carries its own.
func (self *aclPolicyReader) checkComputeDestinations(rule *aclPolicyRule, keys *aclComputeRuleKeys, request bool) error {
	kinds := map[AclResourceKind]bool{}
	resources := map[protocol.AclComputeResource]bool{}
	for _, resource := range rule.dst {
		kinds[resource.Kind] = true
		if resource.Kind == AclResourceCompute {
			resources[resource.ComputeResource] = true
		}
	}
	computeKind := kinds[AclResourceModel] || kinds[AclResourceCompute] || kinds[AclResourceListener]
	ssh := slices.Contains(rule.allow, protocol.AclAction_ACL_ACTION_SSH)
	switch {
	case computeKind && len(kinds) != 1:
		return self.refuse(aclPolicyRefusal("a model:, compute: or listener: destination beside another kind"))
	case kinds[AclResourceCompute] && len(resources) != 1:
		return self.refuse(aclPolicyRefusal("two compute: resources in one rule"))
	case ssh && (len(rule.allow) != 1 || len(kinds) != 1 || !kinds[AclResourceSubject]):
		return self.refuse(aclPolicyRefusal("ssh stands alone, on subjects"))
	case ssh && !request && !keys.hasUsers:
		return self.refuse(aclPolicyRefusal("an ssh grant with no users"))
	case !ssh && (keys.hasUsers || keys.hasCheck):
		return self.refuse(aclPolicyRefusal("users and check are an ssh rule's"))
	case keys.hasShapes && !resources[protocol.AclComputeResource_ACL_COMPUTE_RESOURCE_ENCLAVE]:
		return self.refuse(aclPolicyRefusal("shapes are a compute:enclave rule's"))
	}
	var own []protocol.AclAction
	switch {
	case kinds[AclResourceModel]:
		own = []protocol.AclAction{protocol.AclAction_ACL_ACTION_INFER}
	case kinds[AclResourceCompute]:
		for resource := range resources {
			own = aclComputeResourceActions[resource]
		}
	case kinds[AclResourceListener]:
		own = []protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}
	}
	for _, action := range rule.allow {
		switch {
		case own != nil && !slices.Contains(own, action):
			return self.refuse(aclPolicyRefusal("an action this destination does not take"))
		case own == nil && aclComputeAction(action) && action != protocol.AclAction_ACL_ACTION_SSH:
			return self.refuse(aclPolicyRefusal("an action of §16.2's on a destination that does not take it"))
		}
	}
	return nil
}

// The targets a compute resource compiles to, under its feature: refused while the head does not turn it on, so every
// release compiles the same rows before that base.
func (self *aclCompiler) computeTargets(resource AclResource) ([]*protocol.AclTarget, error) {
	if feature := aclComputeResourceFeature(resource); self.input.AuthFeatures&feature == 0 {
		return nil, aclCompileRefusal("a %s destination while the network's %s feature is off", strings.SplitN(aclComputeResourceText(resource), ":", 2)[0], feature)
	}
	switch resource.Kind {
	case AclResourceModel:
		return []*protocol.AclTarget{{ModelGlob: resource.Name}}, nil
	case AclResourceCompute:
		return []*protocol.AclTarget{{ComputeResource: resource.ComputeResource}}, nil
	case AclResourceListener:
		atomId, err := self.atom(resource.Subject)
		if err != nil {
			return nil, err
		}
		return []*protocol.AclTarget{{Listener: atomId.Bytes()}}, nil
	}
	return nil, aclCompileRefusal("a resource of no kind")
}

// Refuses one of §16.2's actions while the head does not turn compute_policy on (§16.6's before row).
func (self *aclCompiler) checkComputeActions(actions []protocol.AclAction) error {
	if self.input.AuthFeatures&AuthFeatureComputePolicy != 0 {
		return nil
	}
	if slices.ContainsFunc(actions, aclComputeAction) {
		return aclCompileRefusal("an action of §16.2's while the network's compute_policy feature is off")
	}
	return nil
}

// An ssh grant's users and check period (§12.5), which only devices read: the enclave's SSH server holds a login to
// them (SSH's C§12.5), never a gate.
type AclLocalSsh struct {
	// Among agent, root and edit, in the order written.
	Users []string
	// How often the server checks the grant still stands, 0 for its own default.
	Check time.Duration
}

// The compute_policy feature's implicit rules (DESIGN-COMPUTE §16.5): model:* infer and compute:search query for every
// member device and its agents, alike in personal and Team networks, Team's starting document carrying them in its
// compute_policy block. compute:buy keeps its roles' default and the budgets are BudgetSettings', which the broker
// applies whatever a document says, so the fragment adds neither; fetch's default is the block's (ComputePolicyView).
//
//go:embed acl_compute_implicit.hujson
var aclComputeImplicitFragment []byte

// This build implements the compute_policy feature (DESIGN-COMPUTE §16.6; CACL-M12-03, CACL-M12-04): every reader of the
// log here reads the document's compute block and §16.2's resources and actions past the base that turns it on and
// refuses them before it, and its implicit rules compile after the frozen implicit document only once a base turns it
// on, so every release compiles the same rows before that base and acl_implicit.hujson's golden does not move.
func init() {
	registerAuthFeature(AuthFeatureComputePolicy, aclComputeImplicitFragment)
}
