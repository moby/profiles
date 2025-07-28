# Copyright The Moby Authors.
# SPDX-License-Identifier: Apache-2.0

# Makefile for building and testing Moby profiles packages
PROJECT_ROOT ?= $(shell pwd)
SCRIPTDIR ?= $(PROJECT_ROOT)/script
PACKAGES ?= apparmor seccomp
CROSSBUILDS ?= linux/arm linux/arm64 linux/amd64 linux/ppc64le linux/s390x

.PHONY: all
all: crossbuild test

.PHONY: foreach
foreach: ## Run $(CMD) for every package.
	@if test -z '$(CMD)'; then \
		echo 'Usage: make foreach CMD="commands to run for every package"'; \
		exit 1; \
	fi
	set -eu; \
	for p in $(PACKAGES); do \
		(cd $$p; $(CMD);) \
	done

.PHONY: crossbuild
crossbuild:
	set -eu; \
	for osarch in $(CROSSBUILDS); do \
		export GOOS=$${osarch%/*} GOARCH=$${osarch#*/}; \
		echo "# building for $$GOOS/$$GOARCH"; \
		$(MAKE) foreach CMD="GOOS=$$GOOS GOARCH=$$GOARCH go build ."; \
	done

.PHONY: test
test: CMD=go test -v ./...
test: foreach

.PHONY: validate-codegen
validate-codegen:
	@echo "Validating code generation..."
	bash $(SCRIPTDIR)/validate/default-seccomp

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  crossbuild       - Cross build all modules"
	@echo "  test             - Run tests for all modules"
	@echo "  validate-codegen - Validate code generation for seccomp"
	@echo "  help             - Display this help message"
