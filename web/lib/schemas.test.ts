import fs from "node:fs";
import path from "node:path";
import Ajv2020, { type AnySchema } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";

const schemaDirectory = path.resolve(process.cwd(), "../schemas");
const load = (name: string): AnySchema => JSON.parse(fs.readFileSync(path.join(schemaDirectory, name), "utf8")) as AnySchema;
const schemas = {
  health: load("estate-health-v1.schema.json"),
  request: load("operation-request-v1.schema.json"),
  receipt: load("operation-receipt-v1.schema.json"),
  evidence: load("workflow-evidence-v1.schema.json"),
};

const ajv = new Ajv2020({ allErrors: true, strict: true, formats: {
  "date-time": { type: "string", validate: (value: string) => !Number.isNaN(Date.parse(value)) },
} });
Object.values(schemas).forEach((schema) => ajv.addSchema(schema));

const sha = "0123456789abcdef0123456789abcdef01234567";
const digest = `sha256:${"a".repeat(64)}`;
const requestId = "11111111-1111-4111-8111-111111111111";
const receiptId = "22222222-2222-4222-8222-222222222222";
const signature = { algorithm: "Ed25519", key_id: "test-key-v1", value: "A".repeat(86) };

const evidence = {
  schema_version: "estate.evidence/v1", repository: "mindclade/.github", workflow_id: 42, workflow_run_id: 84,
  protected_main_sha: sha, plan_digest: digest, conclusion: "success", superseded: true,
  approval: { approvers: ["approver@mindclade.example"], approved_at: "2026-09-02T10:00:00Z", decision: "approved" },
  observed_at: "2026-09-02T10:00:00Z", expires_at: "2026-09-02T11:00:00Z", digest,
};

const request = {
  schema_version: "estate.operation-request/v1", request_id: requestId, operation: "rerun_failed_required_workflow",
  repository: "mindclade/.github", workflow_id: 42, workflow_run_id: 84, protected_main_sha: sha,
  plan_digest: digest, evidence_digest: digest, reason: "Retry after runner recovery", requested_by: "operator@mindclade.example",
  issued_at: "2026-09-02T10:00:00Z", expires_at: "2026-09-02T10:05:00Z", nonce: "b".repeat(32), digest, signature,
};

describe("published v1 schemas", () => {
  it("accepts the canonical models including the .github repository", () => {
    const health = {
      schema_version: "estate.health/v1", snapshot_id: requestId, observed_at: "2026-09-02T10:00:00Z",
      protected_main_sha: sha, summary: { healthy: 1, degraded: 0, blocked: 0, unknown: 0 },
      repositories: [{ repository: "mindclade/.github", profile: "nix-standard", head_sha: sha, last_green_sha: sha,
        required_check_status: "success", queue_seconds: 1, execution_seconds: 2, failure_class: "none",
        cache_hit_basis_points: 9000, evidence_digest: digest, observed_at: "2026-09-02T10:00:00Z" }], digest,
    };
    const receipt = {
      schema_version: "estate.operation-receipt/v1", receipt_id: receiptId, request_id: requestId, request_digest: digest,
      operation: "rerun_failed_required_workflow", repository: "mindclade/.github", status: "accepted",
      reason_code: "GITHUB_OPERATION_ACCEPTED", provider_reference: "https://github.example/run/84",
      recorded_at: "2026-09-02T10:00:00Z", audit_object: `audit/operations/2026/09/02/${receiptId}.json`, digest, signature,
    };
    expect(ajv.validate(schemas.health, health), JSON.stringify(ajv.errors)).toBe(true);
    expect(ajv.validate(schemas.evidence, evidence), JSON.stringify(ajv.errors)).toBe(true);
    expect(ajv.validate(schemas.request, request), JSON.stringify(ajv.errors)).toBe(true);
    expect(ajv.validate(schemas.receipt, receipt), JSON.stringify(ajv.errors)).toBe(true);
  });

  it("rejects generic dispatch, identity escape, and unsafe provider references", () => {
    expect(ajv.validate(schemas.request, { ...request, operation: "workflow_dispatch" })).toBe(false);
    expect(ajv.validate(schemas.evidence, { ...evidence, approval: { ...evidence.approval, approvers: ["o'hare@mindclade.example"] } })).toBe(false);
    expect(ajv.validate(schemas.receipt, {
      schema_version: "estate.operation-receipt/v1", receipt_id: receiptId, request_id: requestId, request_digest: digest,
      operation: "rerun_failed_required_workflow", repository: "mindclade/bootstrap", status: "accepted", reason_code: "ACCEPTED",
      provider_reference: "javascript:alert(1)", recorded_at: "2026-09-02T10:00:00Z",
      audit_object: `audit/operations/2026/09/02/${receiptId}.json`, digest, signature,
    })).toBe(false);
  });
});
