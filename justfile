set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# Mirror the Buildkite source-ready gate. The Makefile stays the single
# definition of those steps so the pipeline and local runs cannot diverge.
check:
    make check

test:
    make test

test-race:
    make test-race

web-check:
    make web-check

validate-source:
    make validate-source

policy-check:
    make policy-check

# estate-ci is Buildkite-only: a repository-local GitHub Actions catalog is a
# hard invariant violation, so lint asserts the absence rather than scanning
# workflows that must never exist. zizmor is still in the toolchain so the
# invariant can be audited by hand if a workflow directory ever appears.
lint:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -e .github/workflows ]]; then
      echo "repository-local GitHub Actions workflows are forbidden for estate-ci" >&2
      exit 1
    fi
    unformatted="$(gofmt -l cmd internal)"
    if [[ -n "${unformatted}" ]]; then
      echo "gofmt reported unformatted files:" >&2
      echo "${unformatted}" >&2
      exit 1
    fi

# Vulnerability scan of declared dependencies. Requires network access to the
# OSV database, so it is deliberately separate from the hermetic source gate.
security:
    osv-scanner scan source --recursive .

ci: check lint security

flake-check:
    nix flake check --no-accept-flake-config --no-build --no-update-lock-file
