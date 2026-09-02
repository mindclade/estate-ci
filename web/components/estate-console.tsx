"use client";

import {
  Activity,
  Archive,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Clock3,
  FileKey2,
  GitBranch,
  History,
  LoaderCircle,
  Play,
  RefreshCw,
  SearchCheck,
  ServerCog,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import type {
  EstateHealthSnapshot,
  OperationName,
  OperationReceipt,
  Problem,
  RepositoryHealth,
  RepositoryTarget,
  Session,
  WorkflowEvidence,
} from "@/lib/contracts";
import { duration, operationLabel, percent, shortSHA, timestamp } from "@/lib/present";

type View = "overview" | "repositories" | "history" | "evidence" | "operations";
type LoadState = "loading" | "ready" | "error";

const devAssertion = process.env.NODE_ENV === "development" ? process.env.NEXT_PUBLIC_ESTATE_DEV_ASSERTION : undefined;

function requestHeaders(extra: HeadersInit = {}): Headers {
  const headers = new Headers(extra);
  if (devAssertion) headers.set("X-Goog-IAP-JWT-Assertion", devAssertion);
  return headers;
}

async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, { ...init, cache: "no-store", credentials: "same-origin", headers: requestHeaders(init.headers) });
  const body = (await response.json()) as T | Problem;
  if (!response.ok) {
    const problem = body as Problem;
    throw new Error(problem.detail || `Request failed with HTTP ${response.status}`);
  }
  return body as T;
}

export function EstateConsole() {
  const [view, setView] = useState<View>("overview");
  const [state, setState] = useState<LoadState>("loading");
  const [error, setError] = useState("");
  const [session, setSession] = useState<Session | null>(null);
  const [snapshot, setSnapshot] = useState<EstateHealthSnapshot | null>(null);
  const [history, setHistory] = useState<EstateHealthSnapshot[]>([]);
  const [operations, setOperations] = useState<OperationReceipt[]>([]);
  const [targets, setTargets] = useState<RepositoryTarget[]>([]);
  const [evidence, setEvidence] = useState<WorkflowEvidence | null>(null);

  const load = useCallback(async () => {
    setState("loading");
    setError("");
    try {
      const [currentSession, currentSnapshot, historyResult, operationResult, optionResult] = await Promise.all([
        api<Session>("/api/v1/session"),
        api<EstateHealthSnapshot>("/api/v1/estate"),
        api<{ snapshots: EstateHealthSnapshot[] }>("/api/v1/estate/history?limit=20"),
        api<{ operations: OperationReceipt[] }>("/api/v1/operations?limit=50"),
        api<{ connected: boolean; operation_submission_enabled: boolean; repositories: RepositoryTarget[] }>("/api/v1/operations/options"),
      ]);
      setSession(currentSession);
      setSnapshot(currentSnapshot);
      setHistory(historyResult.snapshots);
      setOperations(operationResult.operations);
      setTargets(optionResult.repositories);
      if (currentSnapshot.repositories[0]) {
        setEvidence(await api<WorkflowEvidence>(`/api/v1/evidence?digest=${encodeURIComponent(currentSnapshot.repositories[0].evidence_digest)}`));
      }
      setState("ready");
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Estate data could not be loaded.");
      setState("error");
    }
  }, []);

  useEffect(() => {
    void Promise.resolve().then(load);
  }, [load]);

  const selectEvidence = async (digest: string) => {
    try {
      setEvidence(await api<WorkflowEvidence>(`/api/v1/evidence?digest=${encodeURIComponent(digest)}`));
      setView("evidence");
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Evidence could not be loaded.");
    }
  };

  const navigation = [
    { id: "overview" as const, label: "Overview", icon: Activity },
    { id: "repositories" as const, label: "Repositories", icon: GitBranch },
    { id: "history" as const, label: "History", icon: History },
    { id: "evidence" as const, label: "Evidence", icon: FileKey2 },
    { id: "operations" as const, label: "Operations", icon: ServerCog },
  ];

  return (
    <div className="shell">
      <aside className="rail">
        <div className="brand-block">
          <span className="brand-mark"><SearchCheck size={21} strokeWidth={2.2} /></span>
          <div><strong>Estate CI</strong><span>Mindclade</span></div>
        </div>
        <nav aria-label="Estate views">
          {navigation.map(({ id, label, icon: Icon }) => (
            <button key={id} className={view === id ? "nav-item active" : "nav-item"} onClick={() => setView(id)}>
              <Icon size={18} /><span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="rail-status">
          <span className={session?.connected_dispatch ? "status-dot healthy" : "status-dot warning"} />
          <div><strong>{runtimeLabel(session)}</strong><span>{session?.role ?? "Resolving access"}</span></div>
        </div>
      </aside>

      <main>
        <header className="topbar">
          <div>
            <p className="section-label">Organization qualification</p>
            <h1>{navigation.find((item) => item.id === view)?.label}</h1>
          </div>
          <div className="topbar-actions">
            <span className="identity"><ShieldCheck size={16} />{session?.email ?? "IAP verification"}</span>
            <button className="icon-button" onClick={() => void load()} title="Refresh estate data" aria-label="Refresh estate data">
              <RefreshCw size={18} />
            </button>
          </div>
        </header>

        {state === "loading" && <div className="state-panel"><LoaderCircle className="spin" size={24} />Loading estate state</div>}
        {state === "error" && <div className="state-panel error"><CircleAlert size={24} /><div><strong>Estate state unavailable</strong><span>{error}</span></div></div>}
        {state === "ready" && snapshot && (
          <div className="workspace">
            {error && <div className="inline-alert"><CircleAlert size={17} />{error}<button onClick={() => setError("")} aria-label="Dismiss alert"><XCircle size={17} /></button></div>}
            {view === "overview" && <Overview snapshot={snapshot} onEvidence={selectEvidence} />}
            {view === "repositories" && <Repositories repositories={snapshot.repositories} onEvidence={selectEvidence} />}
            {view === "history" && <SnapshotHistory snapshots={history} />}
            {view === "evidence" && <Evidence evidence={evidence} repositories={snapshot.repositories} onSelect={selectEvidence} />}
            {view === "operations" && session && (
              <Operations session={session} repositories={snapshot.repositories} targets={targets} receipts={operations} onReceipt={(receipt) => setOperations((current) => [receipt, ...current])} />
            )}
          </div>
        )}
      </main>
    </div>
  );
}

function Overview({ snapshot, onEvidence }: { snapshot: EstateHealthSnapshot; onEvidence: (digest: string) => void }) {
  const total = snapshot.repositories.length;
  const healthyPercent = total === 0 ? 0 : Math.round((snapshot.summary.healthy / total) * 100);
  return (
    <>
      <section className="estate-banner">
        <div className="estate-score">
          <span className="score-number">{healthyPercent}</span><span className="score-unit">%</span>
          <p>required checks healthy</p>
        </div>
        <div className="signal-rail" aria-label={`${snapshot.summary.healthy} healthy, ${snapshot.summary.degraded} degraded`}>
          {snapshot.repositories.map((repository) => <span key={repository.repository} className={`signal ${statusClass(repository.required_check_status)}`} title={repository.repository} />)}
        </div>
        <div className="banner-meta">
          <span><Clock3 size={16} />Observed {timestamp(snapshot.observed_at)}</span>
          <span><GitBranch size={16} />main {shortSHA(snapshot.protected_main_sha)}</span>
          <span><Archive size={16} />{snapshot.repositories.length} repositories</span>
        </div>
      </section>
      <section className="metric-strip" aria-label="Estate summary">
        <Metric label="Healthy" value={snapshot.summary.healthy} tone="healthy" />
        <Metric label="Degraded" value={snapshot.summary.degraded} tone="warning" />
        <Metric label="Blocked" value={snapshot.summary.blocked} tone="danger" />
        <Metric label="Unknown" value={snapshot.summary.unknown} tone="neutral" />
      </section>
      <section>
        <SectionHeading title="Repository signals" detail="Latest required-check contract" />
        <RepositoryTable repositories={snapshot.repositories} onEvidence={onEvidence} compact />
      </section>
    </>
  );
}

function Metric({ label, value, tone }: { label: string; value: number; tone: string }) {
  return <div className="metric"><span className={`metric-bar ${tone}`} /><div><span>{label}</span><strong>{value}</strong></div></div>;
}

function Repositories({ repositories, onEvidence }: { repositories: RepositoryHealth[]; onEvidence: (digest: string) => void }) {
  return <section><SectionHeading title="All repositories" detail={`${repositories.length} governed repositories`} /><RepositoryTable repositories={repositories} onEvidence={onEvidence} /></section>;
}

function RepositoryTable({ repositories, onEvidence, compact = false }: { repositories: RepositoryHealth[]; onEvidence: (digest: string) => void; compact?: boolean }) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Repository</th><th>Required</th><th>Head</th><th>Queue</th>{!compact && <th>Execution</th>}<th>Cache</th><th>Failure class</th><th aria-label="Evidence" /></tr></thead>
        <tbody>{repositories.map((repository) => (
          <tr key={repository.repository}>
            <td><strong>{repository.repository.replace("mindclade/", "")}</strong><span className="subcell">{repository.profile}</span></td>
            <td><Status value={repository.required_check_status} /></td>
            <td><code>{shortSHA(repository.head_sha)}</code></td>
            <td>{duration(repository.queue_seconds)}</td>
            {!compact && <td>{duration(repository.execution_seconds)}</td>}
            <td>{percent(repository.cache_hit_basis_points)}</td>
            <td><span className={repository.failure_class === "none" ? "quiet" : "failure"}>{repository.failure_class}</span></td>
            <td><button className="row-action" onClick={() => void onEvidence(repository.evidence_digest)} title="Open evidence" aria-label={`Open evidence for ${repository.repository}`}><ChevronRight size={18} /></button></td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  );
}

function Status({ value }: { value: string }) {
  const healthy = value === "success";
  const Icon = healthy ? CheckCircle2 : value === "failure" ? XCircle : CircleAlert;
  return <span className={`status-pill ${statusClass(value)}`}><Icon size={14} />{value}</span>;
}

function SnapshotHistory({ snapshots }: { snapshots: EstateHealthSnapshot[] }) {
  return (
    <section><SectionHeading title="Snapshot history" detail="Immutable 90-day health records" />
      <div className="timeline">{snapshots.map((snapshot) => (
        <article key={snapshot.snapshot_id} className="timeline-row">
          <span className="timeline-marker" />
          <div><strong>{timestamp(snapshot.observed_at)}</strong><code>{snapshot.digest.slice(0, 22)}...</code></div>
          <div className="timeline-counts"><span className="healthy">{snapshot.summary.healthy} healthy</span><span className="warning">{snapshot.summary.degraded} degraded</span><span className="danger">{snapshot.summary.blocked} blocked</span></div>
        </article>
      ))}</div>
    </section>
  );
}

function Evidence({ evidence, repositories, onSelect }: { evidence: WorkflowEvidence | null; repositories: RepositoryHealth[]; onSelect: (digest: string) => void }) {
  return (
    <section><SectionHeading title="Qualification evidence" detail="Head-bound workflow decisions" />
      <label className="field compact-field"><span>Repository evidence</span><select value={evidence?.digest ?? ""} onChange={(event) => void onSelect(event.target.value)}>{repositories.map((repository) => <option key={repository.repository} value={repository.evidence_digest}>{repository.repository}</option>)}</select></label>
      {evidence ? <dl className="evidence-grid">
        <EvidenceField label="Repository" value={evidence.repository} />
        <EvidenceField label="Conclusion" value={evidence.conclusion} />
        <EvidenceField label="Workflow" value={`${evidence.workflow_id} / run ${evidence.workflow_run_id}`} />
        <EvidenceField label="Protected main" value={evidence.protected_main_sha} code />
        <EvidenceField label="Plan digest" value={evidence.plan_digest} code />
        <EvidenceField label="Evidence digest" value={evidence.digest} code />
        <EvidenceField label="Approval ID" value={evidence.approval.approval_id} code />
        <EvidenceField label="Approved operation" value={operationLabel(evidence.approval.operation)} />
        <EvidenceField label="Approved requester" value={evidence.approval.requested_by} />
        <EvidenceField label="Approved reason" value={evidence.approval.reason} />
        <EvidenceField label="Approvers" value={evidence.approval.approvers.join(", ")} />
        <EvidenceField label="Expires" value={timestamp(evidence.expires_at)} />
      </dl> : <div className="empty-state">No evidence selected</div>}
    </section>
  );
}

function EvidenceField({ label, value, code = false }: { label: string; value: string; code?: boolean }) {
  return <div><dt>{label}</dt><dd className={code ? "code-wrap" : ""}>{value}</dd></div>;
}

function Operations({ session, repositories, targets, receipts, onReceipt }: { session: Session; repositories: RepositoryHealth[]; targets: RepositoryTarget[]; receipts: OperationReceipt[]; onReceipt: (receipt: OperationReceipt) => void }) {
  const [repository, setRepository] = useState(repositories[0]?.repository ?? "");
  const [operation, setOperation] = useState<OperationName>("rerun_failed_required_workflow");
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState("");
  const [selectedEvidence, setSelectedEvidence] = useState<WorkflowEvidence | null>(null);
  const target = targets.find((item) => item.repository === repository);
  const health = repositories.find((item) => item.repository === repository);

  useEffect(() => {
    if (!health) return;
    api<WorkflowEvidence>(`/api/v1/evidence?digest=${encodeURIComponent(health.evidence_digest)}`).then((approved) => {
      setSelectedEvidence(approved);
      setOperation(approved.approval.operation);
      setReason(approved.approval.reason);
    }).catch((error: Error) => setMessage(error.message));
  }, [health]);

  const approvalMatches = selectedEvidence?.approval.operation === operation &&
    selectedEvidence.approval.requested_by === session.email && selectedEvidence.approval.reason === reason &&
    selectedEvidence.repository === repository && selectedEvidence.workflow_id === target?.workflow_ids[operation];
  const canOperate = session.operation_submission_enabled && ["operator", "approver", "admin"].includes(session.role) && target && selectedEvidence && approvalMatches;
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!target || !selectedEvidence) return;
    setSubmitting(true);
    setMessage("");
    const body = {
      schema_version: "estate.operation-intent/v1",
      request_id: crypto.randomUUID(),
      operation,
      repository,
      workflow_id: target.workflow_ids[operation],
      workflow_run_id: operation === "refresh_estate_health" ? 0 : selectedEvidence.workflow_run_id,
      protected_main_sha: selectedEvidence.protected_main_sha,
      plan_digest: selectedEvidence.plan_digest,
      evidence_digest: selectedEvidence.digest,
      reason,
      expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, "Z"),
    };
    try {
      const receipt = await api<OperationReceipt>("/api/v1/operations", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Estate-CSRF": session.csrf_token },
        body: JSON.stringify(body),
      });
      onReceipt(receipt);
      setReason("");
      setMessage(`${operationLabel(operation)} accepted.`);
    } catch (submitError) {
      setMessage(submitError instanceof Error ? submitError.message : "Operation was not accepted.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="operations-layout">
      <section><SectionHeading title="Governed operation" detail={session.connected_dispatch ? "Connected dispatcher" : session.runtime_state === "development-simulation" ? "Local simulation" : "Dispatch disabled"} />
        <form className="operation-form" onSubmit={submit}>
          <label className="field"><span>Repository</span><select value={repository} onChange={(event) => setRepository(event.target.value)}>{repositories.map((item) => <option key={item.repository}>{item.repository}</option>)}</select></label>
          <label className="field"><span>Operation</span><select value={operation} onChange={(event) => setOperation(event.target.value as OperationName)}><option value="rerun_failed_required_workflow">Rerun failed required workflow</option><option value="cancel_superseded_workflow_run">Cancel superseded workflow run</option><option value="refresh_estate_health">Refresh estate health</option></select></label>
          <div className="binding-row"><span><GitBranch size={15} />main <code>{shortSHA(selectedEvidence?.protected_main_sha ?? "")}</code></span><span><ShieldCheck size={15} />workflow {target?.workflow_ids[operation] || "unresolved"}</span></div>
          <label className="field"><span>Reason</span><textarea value={reason} onChange={(event) => setReason(event.target.value)} minLength={10} maxLength={500} rows={4} required /></label>
          <button className="primary-button" disabled={!canOperate || submitting || reason.trim().length < 10} type="submit">{submitting ? <LoaderCircle className="spin" size={17} /> : <Play size={17} />}{submitting ? "Submitting" : operationLabel(operation)}</button>
          {message && <p className="form-message">{message}</p>}
        </form>
      </section>
      <section><SectionHeading title="Operation receipts" detail="Immutable 400-day audit records" /><ReceiptList receipts={receipts} /></section>
    </div>
  );
}

function ReceiptList({ receipts }: { receipts: OperationReceipt[] }) {
  if (receipts.length === 0) return <div className="empty-state">No operations recorded</div>;
  return <div className="receipt-list">{receipts.map((receipt) => <article key={receipt.receipt_id} className="receipt"><Status value={receipt.status === "accepted" ? "success" : "failure"} /><div><strong>{operationLabel(receipt.operation)}</strong><span>{receipt.repository} · {timestamp(receipt.recorded_at)}</span><code>{receipt.reason_code}</code></div></article>)}</div>;
}

function SectionHeading({ title, detail }: { title: string; detail: string }) {
  return <div className="section-heading"><div><h2>{title}</h2><p>{detail}</p></div></div>;
}

function statusClass(status: string): string {
  if (status === "success") return "healthy";
  if (status === "failure" || status === "blocked") return "danger";
  return "warning";
}

function runtimeLabel(session: Session | null): string {
  if (!session) return "Resolving";
  if (session.connected_dispatch) return "Connected";
  if (session.runtime_state === "development-simulation") return "Simulation";
  return "Source-ready";
}
