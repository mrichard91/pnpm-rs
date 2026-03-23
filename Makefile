SHELL := /bin/bash

SAFETY_CHECK_IMAGE ?= pnpm-rs-safety-check
OLDER_THAN_YEARS ?= 5
YARA ?=
NO_DEPS ?= 0
INSPECT ?= 0
OUT_DIR ?=
PACKAGE ?= $(strip $(firstword $(filter-out safety-check safety-check-image safety-check-help,$(MAKECMDGOALS))))

.PHONY: safety-check safety-check-image safety-check-help

safety-check-help:
	@echo "usage: make safety-check <package> [OLDER_THAN_YEARS=5] [YARA=rules.yar] [NO_DEPS=1] [INSPECT=1] [OUT_DIR=artifacts]"
	@echo "example: make safety-check @teale.io/eslin1234"
	@echo "example: make safety-check react@19 OLDER_THAN_YEARS=3"
	@echo "example: make safety-check react@19 NO_DEPS=1"
	@echo "example: make safety-check react@19 NO_DEPS=1 INSPECT=1"
	@echo "example: make safety-check react@19 NO_DEPS=1 OUT_DIR=artifacts"
	@echo "example: make safety-check '@opengov/*' YARA=test.yara NO_DEPS=1 OUT_DIR=artifacts"
	@echo "example: make safety-check PACKAGE='@opengov/*' YARA=test.yara NO_DEPS=1"

safety-check-image:
	@docker build -f Dockerfile.safety-check -t $(SAFETY_CHECK_IMAGE) .

safety-check: safety-check-image
	@if [[ -z "$(PACKAGE)" ]]; then \
		echo "missing package name"; \
		$(MAKE) --no-print-directory safety-check-help; \
		exit 1; \
	fi
	@if [[ -n "$(OUT_DIR)" ]]; then mkdir -p "$(OUT_DIR)"; fi
	@docker run --rm \
		$(if $(filter 1 true yes on,$(INSPECT)),-it,) \
		--cap-drop ALL \
		--security-opt no-new-privileges \
		--pids-limit 256 \
		--read-only \
		--tmpfs /tmp:rw,noexec,nosuid,nodev,size=1g,mode=1777 \
		$(if $(YARA),-v "$(CURDIR):/workspace:ro",) \
		$(if $(OUT_DIR),-v "$(abspath $(OUT_DIR)):/out:rw",) \
		$(SAFETY_CHECK_IMAGE) \
		"$(PACKAGE)" \
		--older-than-years="$(OLDER_THAN_YEARS)" \
		$(if $(filter 1 true yes on,$(NO_DEPS)),--no-deps,) \
		$(if $(filter 1 true yes on,$(INSPECT)),--inspect-shell,) \
		$(if $(OUT_DIR),--out-dir /out,) \
		$(if $(YARA),--yara "/workspace/$(YARA)",)

%:
	@:
