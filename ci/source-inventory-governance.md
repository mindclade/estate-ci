# Estate-CI Source Inventory Governance

## Buildkite-Only Execution Contract

`estate-ci` is a GitHub Operations control-plane service and its execution contract is
**Buildkite-first, no repository-local GitHub Actions workflow catalog**.

Hard invariant (do not waive this):

- Do not add a `.github/workflows` directory to this repository.
- Do not add repository-local copies of the organization required workflow.
- Do not add any workflow files under `.github/workflows/`.
- Do not add or vendor any workflow directory under any alternate path that GitHub Actions could execute for this repository.

The required contract is intentionally centralized in `.github` as:

- `workflow` profile `buildkite-isolated`
- stable required context `Pull request / required`

`tools/verify_source_inventory.py` enforces the no-workflow-policy by rejecting any
repository-local workflow directory or workflow files for this repository.
The verifier is part of source-ready checks; any attempt to add local catalog workflow files fails
before merge.

This document is tracked in `ci/source-inventory.json` to make the contract part of
source evidence and source-ready verification.
