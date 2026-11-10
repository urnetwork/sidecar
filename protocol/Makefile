# Regenerates the committed .pb.go files here and in bridge/ (§4.9). protoc runs from the repo root,
# so files register as protocol/<name>.proto and protocol/bridge/<name>.proto: sdk and server link
# connect's and sidecar's packages, and a duplicate path or name panics at init.
#
# The plugin is go.mod's tool, protoc-gen-go v1.36.11, never one found on PATH.
# GO may name a wrapper, as in make GO=lowgo.
#
# protoc-gen-go writes no build constraint, so each generated file here that the ios_extension leg's
# list does not name then gains //go:build !ios_extension: the forwarding leg links of protocol only
# the list's files (DESIGN-DETAILS 4.2.3), and check/'s stale rule regenerates the same way. bridge/
# is linked whole and takes no tag.

GO ?= go

# Root-relative, and expanded here because protoc takes a glob that matches nothing as a missing
# file, which would fail while either directory has no .proto yet.
protos := $(addprefix protocol/,$(wildcard *.proto bridge/*.proto))

# The ios_extension leg's list, from this directory.
leg_list := ../check/testdata/ios_extension_leg.txt

.PHONY: build

build:
ifeq ($(strip $(protos)),)
	@echo "no .proto files yet"
else
	cd .. && plugin=$$($(GO) tool -n protoc-gen-go) && \
		protoc -I=. --plugin=protoc-gen-go="$$plugin" --go_out=. --go_opt=paths=source_relative $(protos)
	test -f $(leg_list)
	for file in *.pb.go; do \
		if ! grep -qxF "protocol/$$file" $(leg_list); then \
			{ printf '//go:build !ios_extension\n\n'; cat "$$file"; } > "$$file.tagged" && mv "$$file.tagged" "$$file"; \
		fi; \
	done
endif
