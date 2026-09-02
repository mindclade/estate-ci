package operations

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mindclade/estate-ci/internal/auth"
	"github.com/mindclade/estate-ci/internal/contract"
	"github.com/mindclade/estate-ci/internal/storage"
)

const (
	serviceSHA  = "0123456789abcdef0123456789abcdef01234567"
	servicePlan = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
		Approval:   contract.ApprovalEvidence{Approvers: approvers, ApprovedAt: contract.Timestamp(now), Decision: "approved"},
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
		Reason: "Retry the failed required workflow after runner recovery", ExpiresAt: contract.Timestamp(now.Add(5 * time.Minute)),
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
	if _, err := service.Create(context.Background(), identity, auth.RoleOperator, intent); !errors.Is(err, ErrReplay) {
		t.Fatalf("duplicate error=%v, want replay", err)
	}
	intent.RequestID = "33333333-3333-4333-8333-333333333333"
	if _, err := service.Create(context.Background(), identity, auth.RoleOperator, intent); !errors.Is(err, ErrReplay) {
		t.Fatalf("same binding with new request ID error=%v, want replay", err)
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
