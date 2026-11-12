# GO may name a wrapper, as in make check GO=lowgo.

GO ?= go

# How long one package's tests may run. go test's own 10 minutes is too little: smtpproof's circuit
# tests take minutes on an idle machine and pass that limit on a loaded one, which fails make check
# on the clock and says nothing about the code.
TEST_TIMEOUT ?= 30m

# The nested modules sit beside this file in development. A release branch moves the root module
# into v2026/ beside them and smtpproof into its own v2026/ (§4.9), and make check runs there too.
ifneq ($(wildcard cli/go.mod),)
modules := . cli smtpproof mlsinterop
else
modules := . ../cli $(patsubst %/go.mod,%,$(wildcard ../smtpproof/v*/go.mod)) ../mlsinterop
endif

.PHONY: check leaktest size ios-extension-leg proto metadata stack-test

# Every module's tests, then again under sidecar_testhooks, then §4.7's rules in check/. -count=1
# throughout: go test caches on what a test opens, and not on what a go list it runs reads, so a
# cached pass would hide a new violation. Each go test runs under TEST_TIMEOUT, above. check/ runs
# from its own directory, go test's local mode, so a passing run still prints what it leaned on.
# RELEASE_BINARIES names built artifacts for the rules to read as well. This needs the module proxy
# and vuln.go.dev for govulncheck, protoc once a .proto exists, node, which the sidecar_http leg's
# tests run in, and on a darwin host Xcode, which the ios legs compile with, and fails without them:
# a rule that did not run has not passed. Every leg compiles; a cgo leg whose C toolchain this host
# lacks compiles with cgo off, and the run's last lines name each one.
check:
	@set -e; for module in $(modules); do \
		echo "go test in $$module"; \
		(cd $$module && $(GO) test -count=1 -timeout $(TEST_TIMEOUT) ./...); \
		echo "go test -tags sidecar_testhooks in $$module"; \
		(cd $$module && $(GO) test -count=1 -timeout $(TEST_TIMEOUT) -tags sidecar_testhooks ./...); \
	done
	$(MAKE) leaktest GO="$(GO)"
	cd check && $(GO) test -count=1 -timeout $(TEST_TIMEOUT) -tags sidecar_check

# §22.7's self-test, the leak leg: a sidecar_leaktest build leaks a canary into each capture class,
# which must catch it (sidecartest/leak_enabled.go), and the untagged legs above only skip it. Only
# sidecartest links leaks, and check/ fails a release leg built with the tag.
leaktest:
	$(GO) test -count=1 -timeout $(TEST_TIMEOUT) -tags sidecar_leaktest ./sidecartest/...

# §4.9's size gates, which build and link, so they are not part of make check. check/size_test.go
# says what is measured: the ios_extension leg stripped, as sdk ships it, and the sidecar_http leg
# unstripped. The ios_extension leg needs Xcode.
size:
	$(GO) test -count=1 -v -timeout $(TEST_TIMEOUT) -tags sidecar_check,sidecar_size -run '^TestSizeGate' ./check

# The ios_extension legs' list, check/testdata/ios_extension_leg.txt, against the forwarding role's
# file closure, which check/legs_closure_test.go computes by compiling the legs round after round
# (DESIGN-DETAILS 4.2.3). It needs Xcode, as make size does, and make check holds the list as
# written. With SIDECAR_REGENERATE_IOS_EXTENSION_LEG=1 in the environment it rewrites the list.
ios-extension-leg:
	$(GO) test -count=1 -v -timeout $(TEST_TIMEOUT) -tags sidecar_check,sidecar_size -run '^TestIosExtensionLeg' ./check

proto:
	$(MAKE) -C protocol GO="$(GO)"

# The store suites on §22.4's local stack, which needs Docker, so make check leaves it out.
stack-test:
	GO="$(GO)" local/stack.sh test

# §22.7's list: the fenced block under **The list** in §2.8, byte for byte and comments included, at
# the top of the repository. check/metadata_list_test.go fails when the two differ, so a row changes
# in the design and comes here through this target, never by hand. It stops rather than write nothing
# when §2.8 holds no such block.
metadata:
	awk '/^\*\*The list\*\*/ { found = 1; next } found && /^```yaml$$/ { open = 1; next } open && /^```$$/ { exit } open' \
		design/source/sections/02-TRUST.md > metadata_list.yml.new
	test -s metadata_list.yml.new
	mv metadata_list.yml.new metadata_list.yml
