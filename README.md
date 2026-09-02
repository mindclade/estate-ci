# estate-ci

`estate-ci` is the Mindclade estate health and controlled CI operations service. It provides a
read-only health console plus three narrowly defined, evidence-bound operations. The repository is
currently **source-ready and unqualified**: no cloud resource, GitHub App installation, deployment,
or live mutation has been created or validated from this source.

## Security boundary

- Google Cloud IAP authenticates every `/api/v1/*` request. The API verifies the ES256 signature,
  exact IAP issuer, exact configured audience, and validity window before reading identity claims.
- Google Workspace groups resolve `viewer`, `operator`, `approver`, and `admin` roles through Cloud
  Identity. Resolution failures deny access. A distinct approver is required for every operation.
- Browsers receive no Google or GitHub credential. The API uses GKE Workload Identity through the
  metadata server; there is no service-account key, OAuth client secret, or database.
- Health and audit records use canonical JSON, SHA-256 content digests, and create-only GCS writes.
  The health bucket contract is exactly 90 days and the audit bucket contract is exactly 400 days.
- Signed operation requests expire within ten minutes and bind the request UUID, nonce, exact
  operation, repository, workflow ID/run ID, protected `main` SHA, plan digest, and evidence digest.
- A second create-only replay reservation binds that operation tuple independently of the request
  UUID, so changing only the UUID cannot repeat an operation against the same evidence.
- Separate GitHub Apps observe repository state and perform the approved mutation. The broker
  re-observes protected `main` and the workflow run immediately before dispatch.

The exact operation allowlist is:

| Operation | Connected action |
| --- | --- |
| `refresh_estate_health` | Dispatch the catalogued health workflow on `main` |
| `rerun_failed_required_workflow` | Rerun failed jobs for the bound failed run |
| `cancel_superseded_workflow_run` | Cancel the bound queued/running superseded run |

There is no generic workflow dispatch, arbitrary command, repository name, branch, or workflow ID
input. Anything absent from the fixed catalog fails closed.

## Components

- `cmd/estate-ci-api`: Go API and operations broker.
- `internal/contract`: canonical v1 JSON models, content digests, and Ed25519 signing.
- `internal/auth`: IAP JWT verification and Workspace group role resolution.
- `internal/storage`: create-only GCS interfaces and the local in-memory implementation.
- `internal/githubapp`: isolated observation/dispatch GitHub App clients.
- `web`: Next.js operations console for overview, repository health, history, evidence, and operations.
- `schemas` and `api/openapi.json`: versioned interchange contracts.
- `deploy/base`: deliberately non-connectable GitOps handoff manifests.

## Local development

Prerequisites are Go 1.24+, Node 20.9+, npm, and Python 3. No cloud credential is needed for the
fixed local simulation.

```bash
ESTATE_MODE=development \
ESTATE_ALLOWED_ORIGIN=http://localhost:3000 \
go run ./cmd/estate-ci-api
```

In another shell:

```bash
cd web
npm ci --ignore-scripts
NEXT_PUBLIC_ESTATE_DEV_ASSERTION=local-development npm run dev
```

The assertion value is accepted only by `ESTATE_MODE=development`; it is not a credential and is
never recognized in source-ready or connected mode. Open `http://localhost:3000`.

Run the complete source checks with:

```bash
make check
make test-race
```

`make validate-source` verifies the organization policy pin, exact generated artifact inventory,
required source inventory, JSON documents, formatting, secret patterns, Buildkite profile, and the
absence of a repository-local required workflow.

## API

Unauthenticated probes are `GET /healthz` and `GET /readyz`. All other routes require IAP:

- `GET /api/v1/session`
- `GET /api/v1/estate` and `GET /api/v1/estate/history`
- `GET /api/v1/repositories` and `GET /api/v1/repositories/{owner}/{repo}`
- `GET /api/v1/evidence?digest=sha256:...`
- `GET /api/v1/operations/options`
- `GET /api/v1/operations` and `GET /api/v1/operations/{receipt_id}`
- `POST /api/v1/operations`

The POST route is the only mutation surface. It additionally requires operator role, exact origin,
`Sec-Fetch-Site: same-origin`, double-submit CSRF, `application/json`, a 32 KiB body limit, and the
closed v1 intent schema. See `api/openapi.json` for the wire contract.

## Runtime configuration

| Setting | Contract |
| --- | --- |
| `ESTATE_MODE` | `source-ready` by default; only reviewed overlays may select `connected` |
| `ESTATE_CATALOG_PATH` | Fixed v1 repository/workflow catalog; all IDs must resolve in connected mode |
| `ESTATE_ALLOWED_ORIGIN` | Exact HTTPS UI origin used by CSRF validation |
| `IAP_AUDIENCE` | Exact IAP backend-service audience |
| `WORKSPACE_GROUP_BINDINGS_JSON` | Array of Cloud Identity `groups/...` resources and fixed roles |
| `HEALTH_BUCKET` / `AUDIT_BUCKET` | Dedicated 90-day and 400-day immutable object stores |
| `OPERATION_SIGNING_KEY_ID` / `_FILE` | Ed25519 receipt/request signing identity and PKCS#8 key |
| `OBSERVATION_GITHUB_APP_ID` / `_INSTALLATION_ID` / `_PRIVATE_KEY_FILE` | Read-only App identity |
| `DISPATCH_GITHUB_APP_ID` / `_INSTALLATION_ID` / `_PRIVATE_KEY_FILE` | Actions-write App identity |
| `GITHUB_API_URL` | HTTPS GitHub Enterprise API base; defaults to `https://api.github.com` |

The observation App needs repository metadata, contents, and Actions read access. The dispatch App
needs Actions write access and no contents write access. Both installations are restricted to the
catalogued repositories; the service rejects reused App IDs, installation IDs, or key paths.

## Connection handoff

`source-ready` initializes real IAP, Workspace, GCS, and signing boundaries but always uses a
rejecting dispatcher. `connected` additionally requires a fully resolved catalog and two distinct
GitHub App identities. Activation is owned by reviewed configuration in the `gitops` repository:

1. Publish both container images by immutable digest and attach build evidence.
2. Create dedicated 90-day health and 400-day audit buckets with retention/lifecycle controls.
3. Bind a dedicated Google service account through Workload Identity with least privilege.
4. Configure IAP and exact Workspace group resource names.
5. Install separate observation and dispatch GitHub Apps with repository-scoped permissions.
6. Resolve every catalog workflow ID from GitHub, review it, and change `connected` to `true`.
7. Mount separate GitHub App keys and an Ed25519 operation signing key as 0400/0600 owner-only
   files or 0440 files readable only by the dedicated pod `fsGroup`.
8. Exercise a no-mutation canary, then qualify each allowlisted operation with recorded evidence.

The base manifests retain invalid image digests, placeholder identities, unresolved workflow IDs,
default-deny networking, and `ESTATE_MODE=source-ready`. Do not apply them directly.

## CI contract

The repository uses the centrally owned organization workflow profile `buildkite-isolated`. The
stable required check remains exactly `Pull request / required`; this repository intentionally has
no `.github/workflows` copy of it. Buildkite performs the Go, UI, container, and source-ready gates.

The four files under `generated/` are byte-for-byte outputs from `mindclade/.github` implementation
revision `b4d28faa5fde98087f60262110a43f25f6da9eb8`. Update them only as one reviewed policy upgrade,
including `ci/source-inventory.json`; `tools/verify_source_inventory.py` rejects partial or extra
artifacts.
