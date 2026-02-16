# Copyright The Moby Authors.
# SPDX-License-Identifier: Apache-2.0

# Makefile for building and testing Moby profiles packages
PROJECT_ROOT ?= $(shell pwd)
SCRIPTDIR ?= $(PROJECT_ROOT)/script
PACKAGES ?= apparmor seccomp
CROSSBUILDS ?= linux/arm linux/arm64 linux/amd64 linux/ppc64le linux/s390x

.PHONY: all
all: crossbuild test  ## cross build and run tests for all modules

.PHONY: foreach
foreach:
	@if test -z '$(CMD)'; then \
		echo 'Usage: make foreach CMD="commands to run for every package"'; \
		exit 1; \
	fi
	set -eu; \
	for p in $(PACKAGES); do \
		(cd $$p; $(CMD);) \
	done

.PHONY: crossbuild
crossbuild: ## cross build all modules
	set -eu; \
	for osarch in $(CROSSBUILDS); do \
		export GOOS=$${osarch%/*} GOARCH=$${osarch#*/}; \
		echo "# building for $$GOOS/$$GOARCH"; \
		$(MAKE) foreach CMD="GOOS=$$GOOS GOARCH=$$GOARCH go build ."; \
	done

.PHONY: test
test: ## run tests for all modules
test: CMD=go test -v ./...
test: foreach

.PHONY: validate-codegen
validate-codegen: ## validate code generation for seccomp
	@echo "Validating code generation..."
	bash $(SCRIPTDIR)/validate/default-seccomp

.PHONY: help
help: ## display this help message
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
