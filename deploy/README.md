# GitOps handoff

The base is intentionally source-ready and non-connectable as committed. Its images use an invalid
registry with zero digests, workflow IDs are unresolved, the IAP audience and Workspace group IDs
are placeholders, and the API runs with `ESTATE_MODE=source-ready`, whose dispatcher always rejects.

The `gitops` repository owns connected overlays. A reviewed overlay must replace both image digests,
bind the GKE service account to a dedicated Google service account, provide real 90-day health and
400-day audit buckets, mount an Ed25519 signing key from the approved secret controller, configure
IAP, route `/api/*` directly to the API and all other paths to the web service, and replace the fixed
catalog with observed workflow IDs. Connected mode additionally mounts distinct observation and
dispatch GitHub App keys and sets `ESTATE_MODE=connected` only after a no-mutation canary passes.

No manifest in this repository should be applied directly to a cluster.
