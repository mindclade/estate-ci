package operations

import (
	"errors"
	"testing"

	"github.com/mindclade/estate-ci/internal/contract"
)

func TestCapabilityCatalogAuthorizesOnlyEnabledDeclaredOperations(t *testing.T) {
	catalog, err := NewCatalog(CatalogDocument{
		SchemaVersion: "estate.operation-catalog/v2",
		Connected:     true,
		Repositories: []RepositoryTarget{{
			Repository: "mindclade/.github",
			MainBranch: "main",
			Operations: map[string]OperationTarget{
				string(contract.OperationRefreshHealth): {WorkflowID: 41, Enabled: true},
				string(contract.OperationRerunFailed):   {WorkflowID: 42, Enabled: false},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Authorize(contract.OperationIntent{Repository: "mindclade/.github", Operation: contract.OperationRefreshHealth, WorkflowID: 41}); err != nil {
		t.Fatalf("enabled capability was rejected: %v", err)
	}
	if _, err := catalog.Authorize(contract.OperationIntent{Repository: "mindclade/.github", Operation: contract.OperationRerunFailed, WorkflowID: 42}); !errors.Is(err, ErrOperationDisabled) {
		t.Fatalf("disabled capability error = %v", err)
	}
	if _, err := catalog.Authorize(contract.OperationIntent{Repository: "mindclade/.github", Operation: contract.OperationCancelRun, WorkflowID: 42}); !errors.Is(err, ErrOperationNotCatalogued) {
		t.Fatalf("unsupported capability error = %v", err)
	}
}

func TestCapabilityCatalogRejectsUnresolvedWorkflow(t *testing.T) {
	_, err := NewCatalog(CatalogDocument{
		SchemaVersion: "estate.operation-catalog/v2",
		Connected:     true,
		Repositories: []RepositoryTarget{{Repository: "mindclade/.github", MainBranch: "main", Operations: map[string]OperationTarget{
			string(contract.OperationRefreshHealth): {WorkflowID: 0, Enabled: false},
		}}},
	})
	if err == nil {
		t.Fatal("unresolved workflow ID was accepted")
	}
}
