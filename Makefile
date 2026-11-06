# GO may name a wrapper, as in make check GO=lowgo.

GO ?= go

modules := . cli smtpproof mlsinterop

.PHONY: check proto

# A placeholder until the make-check track replaces it. It only runs go test over each module, so it
# enforces none of §4.7's deps, layering, legs, cgo or hygiene checks, and a pass here says nothing
# about them.
check:
	@echo "make check is a placeholder: go test only, none of §4.7's checks" >&2
	@set -e; for module in $(modules); do \
		echo "go test in $$module"; \
		(cd $$module && $(GO) test ./...); \
	done
	$(GO) test -tags sidecar_testhooks .

proto:
	$(MAKE) -C protocol GO="$(GO)"
