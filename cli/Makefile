# ur's release build (DESIGN.md §4.10; REPO-M1-01): the six targets, CGO_ENABLED=0 -trimpath, with
# GOEXPERIMENT=greenteagc and -ldflags "-w -s" as build/all/run.sh's sn_cli_release builds release
# binaries (plan-REPO-small-readings #13). Build info survives both, and make check's
# TestHygieneReleaseBinary reads it. build/all/build-ur.sh runs `make build OUT=<directory>`; each
# binary lands at <directory>/<os>/<arch>/ur, with .exe on windows, since go build -o adds no suffix to
# a named output. GOFLAGS is set here rather than taken from the caller, so no tag reaches a release
# leg through it. The version comes from the release's sed of sidecar.go (§4.9), never from here.

GO ?= go
OUT ?= build
TARGETS ?= darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64
# ur-engine, the local engine's helper (DESIGN-COMPUTE §6.5, D-INFER-2; QD-1401): this package built with the ur_engine
# tag, which selects main_ur_engine.go's main, for the four targets with an engine build; macOS on Intel and Windows on
# arm64 get remote models only. `make engine OUT=<directory>` lands each at <directory>/<os>/<arch>/ur-engine, .exe on
# windows, beside that target's ur.
ENGINE_TARGETS ?= darwin/arm64 linux/amd64 linux/arm64 windows/amd64

.PHONY: build engine

build:
	@set -e; for target in $(TARGETS); do \
		os=$${target%/*}; arch=$${target#*/}; suffix=; \
		if [ "$$os" = windows ]; then suffix=.exe; fi; \
		echo "ur $$os/$$arch"; \
		env GOFLAGS=-mod=readonly GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch GOEXPERIMENT=greenteagc \
			$(GO) build -trimpath -ldflags "-w -s" -o "$(OUT)/$$os/$$arch/ur$$suffix" . ; \
	done

engine:
	@set -e; for target in $(ENGINE_TARGETS); do \
		os=$${target%/*}; arch=$${target#*/}; suffix=; \
		if [ "$$os" = windows ]; then suffix=.exe; fi; \
		echo "ur-engine $$os/$$arch"; \
		env GOFLAGS=-mod=readonly GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch GOEXPERIMENT=greenteagc \
			$(GO) build -trimpath -tags ur_engine -ldflags "-w -s" -o "$(OUT)/$$os/$$arch/ur-engine$$suffix" . ; \
	done
