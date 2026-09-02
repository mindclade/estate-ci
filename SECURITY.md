# Security policy

Do not file a public issue for a suspected vulnerability. Use GitHub's private vulnerability
reporting for `mindclade/estate-ci` and include the affected revision, reproduction, expected impact,
and whether any connected estate resource may be involved. Do not test against production systems
or perform a live GitHub mutation without written authorization.

## Supported state

This initial revision is source-ready and has not been deployed or operationally qualified. Security
fixes apply to the latest `main` revision only until a release policy is published.

## Non-negotiable controls

- IAP is the only external authentication boundary.
- Workspace groups are the only authorization source.
- Observation and dispatch GitHub Apps remain separate identities.
- Operation inputs remain limited to the fixed catalog and exact allowlist.
- GCS audit writes remain create-only; retention is 400 days.
- No long-lived Google credential, OAuth client secret, browser credential, or database is added.
- Connected failures deny operations and retain a signed rejection receipt where a request was
  already accepted into the audit boundary.

Changes to authentication, authorization, schemas, signatures, catalog validation, storage,
GitHub App dispatch, containers, or deployment configuration require code-owner review and focused
negative tests.
