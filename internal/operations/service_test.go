package operations

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mindclade/estate-ci/internal/auth"
	"github.com/mindclade/estate-ci/internal/contract"
	"github.com/mindclade/estate-ci/internal/storage"
)

const (
	serviceSHA    = "0123456789abcdef0123456789abcdef01234567"
	servicePlan   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	serviceReason = "Retry the failed required workflow after runner recovery"
)

type roleFixture map[string]auth.Role

func (fixture roleFixture) RoleFor(_ context.Context, email string) (auth.Role, error) {
	return fixture[email], nil
}

func serviceFixture(t *testing.T, superseded bool, approvers []string) (*Service, *storage.MemoryRepository, contract.OperationIntent) {
	t.Helper()
	repository := storage.NewMemoryRepository()
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	evidence := contract.WorkflowEvidence{
		Repository: "mindclade/bootstrap", WorkflowID: 42, WorkflowRunID: 84, ProtectedMainSHA: serviceSHA,
		PlanDigest: servicePlan, Conclusion: "success", Superseded: superseded,
		Approval: contract.ApprovalEvidence{
			ApprovalID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Operation: contract.OperationRerunFailed,
			RequestedBy: "operator@mindclade.example", Reason: serviceReason,
			Approvers: approvers, ApprovedAt: contract.Timestamp(now), Decision: "approved",
		},
		ObservedAt: contract.Timestamp(now), ExpiresAt: contract.Timestamp(now.Add(time.Hour)),
	}
	if err := evidence.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := repository.SeedEvidence(evidence); err != nil {
		t.Fatal(err)
	}
	catalog, err := NewCatalog(CatalogDocument{SchemaVersion: "estate.operation-catalog/v1", Connected: true, Repositories: []RepositoryTarget{{
		Repository: "mindclade/bootstrap", MainBranch: "main", WorkflowIDs: map[string]int64{
			string(contract.OperationRefreshHealth): 43,
			string(contract.OperationRerunFailed):   42,
			string(contract.OperationCancelRun):     42,
		},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := contract.NewEphemeralSigner("test-key-v1")
	service, err := NewService(catalog, repository, roleFixture{
		"operator@mindclade.example": auth.RoleOperator,
		"approver@mindclade.example": auth.RoleApprover,
	}, SimulationDispatcher{}, signer)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	service.uuid = func() (string, error) { return "22222222-2222-4222-8222-222222222222", nil }
	intent := contract.OperationIntent{
		SchemaVersion: IntentSchemaVersion, RequestID: "11111111-1111-4111-8111-111111111111",
		Operation: contract.OperationRerunFailed, Repository: "mindclade/bootstrap", WorkflowID: 42, WorkflowRunID: 84,
		ProtectedMainSHA: serviceSHA, PlanDigest: servicePlan, EvidenceDigest: evidence.Digest,
		Reason: serviceReason, ExpiresAt: contract.Timestamp(now.Add(5 * time.Minute)),
	}
	return service, repository, intent
}

func TestServiceCreatesSignedReceiptAndRejectsReplay(t *testing.T) {
	service, _, intent := serviceFixture(t, false, []string{"approver@mindclade.example"})
	identity := auth.Identity{Email: "operator@mindclade.example"}
	receipt, err := service.Create(context.Background(), identity, auth.RoleOperator, intent)
	if err != nil || receipt.Status != "accepted" || receipt.RequestDigest == "" || receipt.Signature.Value == "" {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	repeated, err := service.Create(context.Background(), identity, auth.RoleOperator, intent)
	if err != nil || repeated.Digest != receipt.Digest {
		t.Fatalf("idempotent retry receipt=%#v err=%v", repeated, err)
	}
	intent.RequestID = "33333333-3333-4333-8333-333333333333"
	if _, err := service.Create(context.Background(), identity, auth.RoleOperator, intent); !errors.Is(err, ErrReplay) {
		t.Fatalf("same binding with new request ID error=%v, want replay", err)
	}
}

func TestApprovalBindsExactRequesterOperationAndReason(t *testing.T) {
	identity := auth.Identity{Email: "operator@mindclade.example"}
	for name, mutate := range map[string]func(*contract.OperationIntent, *auth.Identity){
		"requester": func(_ *contract.OperationIntent, identity *auth.Identity) { identity.Email = "other@mindclade.example" },
		"operation": func(intent *contract.OperationIntent, _ *auth.Identity) {
			intent.Operation = contract.OperationCancelRun
		},
		"reason": func(intent *contract.OperationIntent, _ *auth.Identity) {
			intent.Reason = "Use the same evidence for a different approved reason"
		},
	} {
		t.Run(name, func(t *testing.T) {
			service, _, intent := serviceFixture(t, true, []string{"approver@mindclade.example"})
			caller := identity
			mutate(&intent, &caller)
			if _, err := service.Create(context.Background(), caller, auth.RoleOperator, intent); !errors.Is(err, ErrDenied) {
				t.Fatalf("mismatched approval error=%v, want denied", err)
			}
		})
	}
}

func TestApprovalIDIsSingleUseAcrossResealedEvidence(t *testing.T) {
	service, repository, intent := serviceFixture(t, false, []string{"approver@mindclade.example"})
	identity := auth.Identity{Email: "operator@mindclade.example"}
	if _, err := service.Create(context.Background(), identity, auth.RoleOperator, intent); err != nil {
		t.Fatal(err)
	}
	evidence, err := repository.GetEvidence(context.Background(), intent.EvidenceDigest)
	if err != nil {
		t.Fatal(err)
	}
	observed, _ := time.Parse(time.RFC3339, evidence.ObservedAt)
	evidence.ObservedAt = contract.Timestamp(observed.Add(time.Second))
	evidence.ExpiresAt = contract.Timestamp(observed.Add(time.Hour + time.Second))
	evidence.Digest = ""
	if err := evidence.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := repository.SeedEvidence(evidence); err != nil {
		t.Fatal(err)
	}
	intent.RequestID = "55555555-5555-4555-8555-555555555555"
	intent.EvidenceDigest = evidence.Digest
	if _, err := service.Create(context.Background(), identity, auth.RoleOperator, intent); !errors.Is(err, ErrReplay) {
		t.Fatalf("resealed approval error=%v, want replay", err)
	}
}

type recoveryDispatcher struct {
	mu            sync.Mutex
	dispatchCalls int
	recoverCalls  int
	dispatch      DispatchOutcome
	recover       DispatchOutcome
}

func (*recoveryDispatcher) Prepare(context.Context, RepositoryTarget, contract.OperationRequest) (string, DispatchOutcome) {
	return "cmVjb3ZlcnktdjE", DispatchOutcome{}
}
func (dispatcher *recoveryDispatcher) Dispatch(context.Context, RepositoryTarget, contract.OperationRequest, string) DispatchOutcome {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	dispatcher.dispatchCalls++
	return dispatcher.dispatch
}
func (dispatcher *recoveryDispatcher) Recover(context.Context, RepositoryTarget, contract.OperationRequest, string) DispatchOutcome {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	dispatcher.recoverCalls++
	return dispatcher.recover
}

func TestServiceRecoversAmbiguousProviderResponseWithoutRedispatch(t *testing.T) {
	service, repository, intent := serviceFixture(t, false, []string{"approver@mindclade.example"})
	dispatcher := &recoveryDispatcher{
		dispatch: DispatchOutcome{ReasonCode: "GITHUB_DISPATCH_OUTCOME_PENDING"},
		recover:  DispatchOutcome{Final: true, Accepted: true, ReasonCode: "GITHUB_OPERATION_RECOVERED", ProviderReference: "https://github.example/run/84"},
	}
	service.dispatcher = dispatcher
	identity := auth.Identity{Email: "operator@mindclade.example"}
	if receipt, err := service.Create(context.Background(), identity, auth.RoleOperator, intent); !errors.Is(err, ErrPending) || receipt.ReceiptID != "" {
		t.Fatalf("ambiguous dispatch receipt=%#v err=%v", receipt, err)
	}
	if receipts, err := repository.ListReceipts(context.Background(), 10); err != nil || len(receipts) != 0 {
		t.Fatalf("ambiguous provider outcome created receipts=%#v err=%v", receipts, err)
	}
	receipt, err := service.Create(context.Background(), identity, auth.RoleOperator, intent)
	if err != nil || receipt.Status != "accepted" || receipt.ReasonCode != "GITHUB_OPERATION_RECOVERED" {
		t.Fatalf("recovered receipt=%#v err=%v", receipt, err)
	}
	if dispatcher.dispatchCalls != 1 || dispatcher.recoverCalls != 1 {
		t.Fatalf("dispatch=%d recover=%d, want 1/1", dispatcher.dispatchCalls, dispatcher.recoverCalls)
	}
}

type receiptFailureRepository struct {
	*storage.MemoryRepository
	failOnce bool
}

func (repository *receiptFailureRepository) PutReceipt(ctx context.Context, receipt contract.OperationReceipt) error {
	if repository.failOnce {
		repository.failOnce = false
		return errors.New("injected receipt storage failure")
	}
	return repository.MemoryRepository.PutReceipt(ctx, receipt)
}

func TestServiceRecoversPersistedResultAfterReceiptWriteFailure(t *testing.T) {
	service, memory, intent := serviceFixture(t, false, []string{"approver@mindclade.example"})
	repository := &receiptFailureRepository{MemoryRepository: memory, failOnce: true}
	dispatcher := &recoveryDispatcher{dispatch: DispatchOutcome{Final: true, Accepted: true, ReasonCode: "GITHUB_OPERATION_ACCEPTED", ProviderReference: "https://github.example/run/84"}}
	service.repository = repository
	service.dispatcher = dispatcher
	identity := auth.Identity{Email: "operator@mindclade.example"}
	if _, err := service.Create(context.Background(), identity, auth.RoleOperator, intent); !errors.Is(err, ErrPending) {
		t.Fatalf("receipt storage error=%v, want pending", err)
	}
	receipt, err := service.Create(context.Background(), identity, auth.RoleOperator, intent)
	if err != nil || receipt.Status != "accepted" {
		t.Fatalf("recovered receipt=%#v err=%v", receipt, err)
	}
	if dispatcher.dispatchCalls != 1 || dispatcher.recoverCalls != 0 {
		t.Fatalf("dispatch=%d recover=%d, want 1/0", dispatcher.dispatchCalls, dispatcher.recoverCalls)
	}
}

func TestServiceRejectsRoleDenialAndApprovalBypass(t *testing.T) {
	service, _, intent := serviceFixture(t, false, []string{"operator@mindclade.example"})
	identity := auth.Identity{Email: "operator@mindclade.example"}
	if _, err := service.Create(context.Background(), identity, auth.RoleViewer, intent); !errors.Is(err, ErrDenied) {
		t.Fatalf("viewer error=%v, want denied", err)
	}
	if _, err := service.Create(context.Background(), identity, auth.RoleOperator, intent); !errors.Is(err, ErrDenied) {
		t.Fatalf("self approval error=%v, want denied", err)
	}
}

func TestCancellationRequiresSupersededEvidence(t *testing.T) {
	service, _, intent := serviceFixture(t, false, []string{"approver@mindclade.example"})
	intent.Operation = contract.OperationCancelRun
	if _, err := service.Create(context.Background(), auth.Identity{Email: "operator@mindclade.example"}, auth.RoleOperator, intent); !errors.Is(err, ErrDenied) {
		t.Fatalf("non-superseded cancellation error=%v, want denied", err)
	}
}
