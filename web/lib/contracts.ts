export type HealthSummary = { healthy: number; degraded: number; blocked: number; unknown: number };

export type RepositoryHealth = {
  repository: string;
  profile: string;
  head_sha: string;
  last_green_sha: string;
  required_check_status: string;
  queue_seconds: number;
  execution_seconds: number;
  failure_class: string;
  cache_hit_basis_points: number;
  evidence_digest: string;
  observed_at: string;
};

export type EstateHealthSnapshot = {
  schema_version: "estate.health/v1";
  snapshot_id: string;
  observed_at: string;
  protected_main_sha: string;
  summary: HealthSummary;
  repositories: RepositoryHealth[];
  digest: string;
};

export type WorkflowEvidence = {
  schema_version: "estate.evidence/v1";
  repository: string;
  workflow_id: number;
  workflow_run_id: number;
  protected_main_sha: string;
  plan_digest: string;
  conclusion: string;
  superseded: boolean;
  approval: { approvers: string[]; approved_at: string; decision: string };
  observed_at: string;
  expires_at: string;
  digest: string;
};

export type OperationName =
  | "refresh_estate_health"
  | "rerun_failed_required_workflow"
  | "cancel_superseded_workflow_run";

export type RepositoryTarget = {
  repository: string;
  main_branch: "main";
  workflow_ids: Record<OperationName, number>;
};

export type OperationReceipt = {
  schema_version: "estate.operation-receipt/v1";
  receipt_id: string;
  request_id: string;
  request_digest: string;
  operation: OperationName;
  repository: string;
  status: "accepted" | "rejected";
  reason_code: string;
  provider_reference: string;
  recorded_at: string;
  audit_object: string;
  digest: string;
  signature: { algorithm: "Ed25519"; key_id: string; value: string };
};

export type Session = {
  email: string;
  role: "viewer" | "operator" | "approver" | "admin";
  csrf_token: string;
  runtime_state: "development-simulation" | "source-ready" | "connected";
  connected_dispatch: boolean;
  operation_submission_enabled: boolean;
};

export type Problem = { status: number; code: string; detail: string };
