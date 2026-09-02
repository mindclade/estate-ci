package storage

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/mindclade/estate-ci/internal/contract"
)

var (
	ErrNotFound = errors.New("object not found")
	ErrConflict = errors.New("create-only object already exists")
)

const (
	HealthRetentionDays = 90
	AuditRetentionDays  = 400
)

type Repository interface {
	LatestSnapshot(context.Context) (contract.EstateHealthSnapshot, error)
	ListSnapshots(context.Context, int) ([]contract.EstateHealthSnapshot, error)
	GetEvidence(context.Context, string) (contract.WorkflowEvidence, error)
	ReserveRequest(context.Context, string, string, string, string, string) error
	PutRequest(context.Context, contract.OperationRequest) error
	GetRequest(context.Context, string) (contract.OperationRequest, error)
	PutDispatch(context.Context, contract.OperationDispatch) error
	GetDispatch(context.Context, string) (contract.OperationDispatch, error)
	PutDispatchResult(context.Context, contract.OperationDispatchResult) error
	GetDispatchResult(context.Context, string) (contract.OperationDispatchResult, error)
	PutReceipt(context.Context, contract.OperationReceipt) error
	GetReceiptByObject(context.Context, string) (contract.OperationReceipt, error)
	GetReceipt(context.Context, string) (contract.OperationReceipt, error)
	ListReceipts(context.Context, int) ([]contract.OperationReceipt, error)
}

type MemoryRepository struct {
	mu           sync.RWMutex
	snapshots    []contract.EstateHealthSnapshot
	evidence     map[string]contract.WorkflowEvidence
	reservations map[string]string
	bindings     map[string]string
	approvals    map[string]string
	requests     map[string]contract.OperationRequest
	dispatches   map[string]contract.OperationDispatch
	results      map[string]contract.OperationDispatchResult
	receipts     map[string]contract.OperationReceipt
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		evidence: map[string]contract.WorkflowEvidence{}, reservations: map[string]string{},
		bindings: map[string]string{}, approvals: map[string]string{}, requests: map[string]contract.OperationRequest{},
		dispatches: map[string]contract.OperationDispatch{}, results: map[string]contract.OperationDispatchResult{}, receipts: map[string]contract.OperationReceipt{},
	}
}

func (repository *MemoryRepository) SeedSnapshot(snapshot contract.EstateHealthSnapshot) error {
	if err := snapshot.VerifyDigest(); err != nil {
		return errors.New("seed snapshot is invalid or unsealed")
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.snapshots = append(repository.snapshots, snapshot)
	return nil
}

func (repository *MemoryRepository) SeedEvidence(evidence contract.WorkflowEvidence) error {
	if err := evidence.VerifyDigest(time.Time{}); err != nil {
		return errors.New("seed evidence is invalid or unsealed")
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.evidence[evidence.Digest]; exists {
		return ErrConflict
	}
	repository.evidence[evidence.Digest] = evidence
	return nil
}

func (repository *MemoryRepository) LatestSnapshot(_ context.Context) (contract.EstateHealthSnapshot, error) {
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	if len(repository.snapshots) == 0 {
		return contract.EstateHealthSnapshot{}, ErrNotFound
	}
	return repository.snapshots[len(repository.snapshots)-1], nil
}

func (repository *MemoryRepository) ListSnapshots(_ context.Context, limit int) ([]contract.EstateHealthSnapshot, error) {
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	if limit <= 0 || limit > 100 {
		return nil, errors.New("snapshot list limit is invalid")
	}
	start := len(repository.snapshots) - limit
	if start < 0 {
		start = 0
	}
	result := append([]contract.EstateHealthSnapshot(nil), repository.snapshots[start:]...)
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result, nil
}

func (repository *MemoryRepository) GetEvidence(_ context.Context, digest string) (contract.WorkflowEvidence, error) {
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	evidence, ok := repository.evidence[digest]
	if !ok {
		return contract.WorkflowEvidence{}, ErrNotFound
	}
	return evidence, nil
}

func (repository *MemoryRepository) ReserveRequest(_ context.Context, requestID, bindingDigest, approvalID, nonce, expiresAt string) error {
	if err := validateReservation(requestID, bindingDigest, approvalID, nonce, expiresAt); err != nil {
		return err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.reservations[requestID]; exists {
		return ErrConflict
	}
	if _, exists := repository.bindings[bindingDigest]; exists {
		return ErrConflict
	}
	if _, exists := repository.approvals[approvalID]; exists {
		return ErrConflict
	}
	repository.reservations[requestID] = nonce + ":" + expiresAt
	repository.bindings[bindingDigest] = requestID
	repository.approvals[approvalID] = requestID
	return nil
}

func (repository *MemoryRepository) GetRequest(_ context.Context, requestID string) (contract.OperationRequest, error) {
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	request, ok := repository.requests[requestID]
	if !ok {
		return contract.OperationRequest{}, ErrNotFound
	}
	return request, nil
}

func (repository *MemoryRepository) PutDispatch(_ context.Context, dispatch contract.OperationDispatch) error {
	if err := dispatch.VerifyDigest(); err != nil {
		return errors.New("operation dispatch is invalid or unsealed")
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.dispatches[dispatch.RequestID]; exists {
		return ErrConflict
	}
	repository.dispatches[dispatch.RequestID] = dispatch
	return nil
}

func (repository *MemoryRepository) GetDispatch(_ context.Context, requestID string) (contract.OperationDispatch, error) {
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	dispatch, ok := repository.dispatches[requestID]
	if !ok {
		return contract.OperationDispatch{}, ErrNotFound
	}
	return dispatch, nil
}

func (repository *MemoryRepository) PutDispatchResult(_ context.Context, result contract.OperationDispatchResult) error {
	if err := result.VerifyDigest(); err != nil {
		return errors.New("operation dispatch result is invalid or unsealed")
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.results[result.RequestID]; exists {
		return ErrConflict
	}
	repository.results[result.RequestID] = result
	return nil
}

func (repository *MemoryRepository) GetDispatchResult(_ context.Context, requestID string) (contract.OperationDispatchResult, error) {
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	result, ok := repository.results[requestID]
	if !ok {
		return contract.OperationDispatchResult{}, ErrNotFound
	}
	return result, nil
}

func (repository *MemoryRepository) PutRequest(_ context.Context, request contract.OperationRequest) error {
	if err := request.VerifyDigest(time.Time{}); err != nil {
		return errors.New("operation request is invalid or unsealed")
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.requests[request.RequestID]; exists {
		return ErrConflict
	}
	repository.requests[request.RequestID] = request
	return nil
}

func (repository *MemoryRepository) PutReceipt(_ context.Context, receipt contract.OperationReceipt) error {
	if err := receipt.VerifyDigest(); err != nil {
		return errors.New("operation receipt is invalid or unsealed")
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.receipts[receipt.ReceiptID]; exists {
		return ErrConflict
	}
	repository.receipts[receipt.ReceiptID] = receipt
	return nil
}

func (repository *MemoryRepository) GetReceipt(_ context.Context, receiptID string) (contract.OperationReceipt, error) {
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	receipt, ok := repository.receipts[receiptID]
	if !ok {
		return contract.OperationReceipt{}, ErrNotFound
	}
	return receipt, nil
}

func (repository *MemoryRepository) GetReceiptByObject(_ context.Context, objectName string) (contract.OperationReceipt, error) {
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	for _, receipt := range repository.receipts {
		if receipt.AuditObject == objectName {
			return receipt, nil
		}
	}
	return contract.OperationReceipt{}, ErrNotFound
}

func (repository *MemoryRepository) ListReceipts(_ context.Context, limit int) ([]contract.OperationReceipt, error) {
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	if limit <= 0 || limit > 100 {
		return nil, errors.New("receipt list limit is invalid")
	}
	result := make([]contract.OperationReceipt, 0, len(repository.receipts))
	for _, receipt := range repository.receipts {
		result = append(result, receipt)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RecordedAt > result[j].RecordedAt })
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func ReceiptObject(receipt contract.OperationReceipt) string {
	observed, err := time.Parse(time.RFC3339, receipt.RecordedAt)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("audit/operations/%s/%s.json", observed.UTC().Format("2006/01/02"), receipt.ReceiptID)
}

func validateReservation(requestID, bindingDigest, approvalID, nonce, expiresAt string) error {
	requestIDPattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	if !requestIDPattern.MatchString(requestID) || !requestIDPattern.MatchString(approvalID) || !digestPattern.MatchString(bindingDigest) || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(nonce) {
		return errors.New("replay reservation identity is invalid")
	}
	if _, err := time.Parse(time.RFC3339, expiresAt); err != nil {
		return errors.New("replay reservation expiry is invalid")
	}
	return nil
}
