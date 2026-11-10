// §8.5's implicit document, versioned in this repo: what a writer compiles whenever a network has no document
// (has_document false), through the same path as any document, so gates and clients evaluate one function (D-ACL-20).
// It carries the team directory's reach-request rule from M2, autogroup:dst-owner and all (D-PHASE-9), and it is
// frozen: readers of every version must compile equal rows from it, so a change must fail acl_compile_test.go's
// golden, and none may land without a design change.
//
// Its first rule's * reaches every application socket and share/, since a bare * dst compiles to a token prefix of no
// segment, which every blinded name has (SOCK-M5-15's share/<token>; acl-policy-small-readings #2).
//
// Its rules have no table: rule i takes the first 16 bytes of SHA-256("urnetwork-sidecar-v1/acl-implicit-rule" ||
// 0x00 || u32be(i)), i counting the grants in order, then the requests (plan-ACL-atom-and-rule-ids #3).
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	_ "embed"
)

//go:embed acl_implicit.hujson
var aclImplicitSource []byte

// The implicit document's source, a copy.
func AclImplicitPolicySource() []byte {
	return append([]byte{}, aclImplicitSource...)
}

// The implicit document, parsed. It is the binary's own and parses on every leg, which acl_compile_test.go holds.
func aclImplicitPolicy() (*AclPolicy, error) {
	return ParseAclPolicy(aclImplicitSource)
}

// The implicit document's rule i, grants first, then requests.
func aclImplicitRuleId(index uint32) Id {
	return aclConstantRuleId("urnetwork-sidecar-v1/acl-implicit-rule", index)
}
