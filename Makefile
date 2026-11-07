# GO may name a wrapper, as in make check GO=lowgo.

GO ?= go

# The nested modules sit beside this file in development. A release branch moves the root module
# into v2026/ beside them and smtpproof into its own v2026/ (§4.9), and make check runs there too.
ifneq ($(wildcard cli/go.mod),)
modules := . cli smtpproof mlsinterop
else
modules := . ../cli $(patsubst %/go.mod,%,$(wildcard ../smtpproof/v*/go.mod)) ../mlsinterop
endif

.PHONY: check size proto stack-test

# Every module's tests, then again under sidecar_testhooks, then §4.7's rules in check/. -count=1
# throughout: go test caches on what a test opens, and not on what a go list it runs reads, so a
# cached pass would hide a new violation. check/ runs from its own directory, go test's local mode,
# so a passing run still prints what it leaned on. RELEASE_BINARIES names built artifacts for the
# rules to read as well. This needs the module proxy and vuln.go.dev for govulncheck, protoc once a
# .proto exists, and node, which the sidecar_http leg's tests run in, and fails without them: a rule
# that did not run has not passed.
check:
	@set -e; for module in $(modules); do \
		echo "go test in $$module"; \
		(cd $$module && $(GO) test -count=1 ./...); \
		echo "go test -tags sidecar_testhooks in $$module"; \
		(cd $$module && $(GO) test -count=1 -tags sidecar_testhooks ./...); \
	done
	cd check && $(GO) test -count=1 -timeout 30m -tags sidecar_check

# §4.9's size gates, which build and link, so they are not part of make check. check/size_test.go
# says what is measured. The ios_extension leg needs Xcode.
size:
	$(GO) test -count=1 -v -timeout 30m -tags sidecar_check,sidecar_size -run '^TestSizeGate' ./check

proto:
	$(MAKE) -C protocol GO="$(GO)"

# The store suites on §22.4's local stack, which needs Docker, so make check leaves it out.
stack-test:
	GO="$(GO)" local/stack.sh test
