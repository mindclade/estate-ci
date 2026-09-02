package operations

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"

	"github.com/mindclade/estate-ci/internal/contract"
)

type RepositoryTarget struct {
	Repository  string           `json:"repository"`
	MainBranch  string           `json:"main_branch"`
	WorkflowIDs map[string]int64 `json:"workflow_ids"`
}

type CatalogDocument struct {
	SchemaVersion string             `json:"schema_version"`
	Connected     bool               `json:"connected"`
	Repositories  []RepositoryTarget `json:"repositories"`
}

type Catalog struct {
	connected bool
	targets   map[string]RepositoryTarget
}

func LoadCatalog(path string) (*Catalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read operation catalog: %w", err)
	}
	var document CatalogDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode operation catalog: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("operation catalog contains trailing data")
	}
	return NewCatalog(document)
}

func NewCatalog(document CatalogDocument) (*Catalog, error) {
	if document.SchemaVersion != "estate.operation-catalog/v1" || len(document.Repositories) == 0 || len(document.Repositories) > 100 {
		return nil, errors.New("operation catalog identity or repository count is invalid")
	}
	targets := make(map[string]RepositoryTarget, len(document.Repositories))
	repositoryPattern := regexp.MustCompile(`^mindclade/(\.github|[a-z0-9][a-z0-9._-]{0,99})$`)
	for _, target := range document.Repositories {
		if !repositoryPattern.MatchString(target.Repository) || target.MainBranch != "main" || targets[target.Repository].Repository != "" {
			return nil, errors.New("operation catalog repository binding is invalid")
		}
		expected := []contract.Operation{contract.OperationRefreshHealth, contract.OperationRerunFailed, contract.OperationCancelRun}
		if len(target.WorkflowIDs) != len(expected) {
			return nil, errors.New("operation catalog must declare every exact operation")
		}
		for _, operation := range expected {
			workflowID, ok := target.WorkflowIDs[string(operation)]
			if !ok || workflowID < 0 || document.Connected && workflowID == 0 {
				return nil, errors.New("operation catalog workflow ID is unresolved")
			}
		}
		for operation := range target.WorkflowIDs {
			if !contract.AllowedOperation(contract.Operation(operation)) {
				return nil, errors.New("operation catalog contains a generic or unsupported operation")
			}
		}
		targets[target.Repository] = target
	}
	return &Catalog{connected: document.Connected, targets: targets}, nil
}

func (catalog *Catalog) Authorize(intent contract.OperationIntent) (RepositoryTarget, error) {
	target, ok := catalog.targets[intent.Repository]
	if !ok || !catalog.connected {
		return RepositoryTarget{}, errors.New("repository operation catalog is not connected")
	}
	expected := target.WorkflowIDs[string(intent.Operation)]
	if expected <= 0 || intent.WorkflowID != expected {
		return RepositoryTarget{}, errors.New("workflow ID does not match the exact operation catalog")
	}
	return target, nil
}

func (catalog *Catalog) Repositories() []RepositoryTarget {
	values := make([]RepositoryTarget, 0, len(catalog.targets))
	for _, target := range catalog.targets {
		values = append(values, target)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Repository < values[j].Repository })
	return values
}

func (catalog *Catalog) Connected() bool { return catalog.connected }
