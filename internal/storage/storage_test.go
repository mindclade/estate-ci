package storage

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mindclade/estate-ci/internal/contract"
)

func TestMemoryRepositoryIsCreateOnlyAndReplayProtected(t *testing.T) {
	repository := NewMemoryRepository()
	ctx := context.Background()
	expiresAt := contract.Timestamp(time.Now().Add(5 * time.Minute))
	binding := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	approval := "44444444-4444-4444-8444-444444444444"
	if err := repository.ReserveRequest(ctx, "11111111-1111-4111-8111-111111111111", binding, approval, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", expiresAt); err != nil {
		t.Fatal(err)
	}
	if err := repository.ReserveRequest(ctx, "11111111-1111-4111-8111-111111111111", binding, approval, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", expiresAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate reservation = %v, want conflict", err)
	}
	if err := repository.ReserveRequest(ctx, "33333333-3333-4333-8333-333333333333", binding, approval, "cccccccccccccccccccccccccccccccc", expiresAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate binding = %v, want conflict", err)
	}
	now := time.Now()
	recordedAt := contract.Timestamp(now)
	receipt := contract.OperationReceipt{
		ReceiptID: "22222222-2222-4222-8222-222222222222", RequestID: "11111111-1111-4111-8111-111111111111",
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Operation:     contract.OperationRerunFailed, Repository: "mindclade/bootstrap", Status: "accepted", ReasonCode: "LOCAL_SIMULATION_ACCEPTED",
		ProviderReference: "simulation://operations/11111111-1111-4111-8111-111111111111", RecordedAt: recordedAt,
		AuditObject: "audit/operations/" + now.UTC().Format("2006/01/02") + "/22222222-2222-4222-8222-222222222222.json",
	}
	signer, _ := contract.NewEphemeralSigner("test-key-v1")
	if err := contract.SealReceipt(&receipt, signer); err != nil {
		t.Fatal(err)
	}
	if err := repository.PutReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if err := repository.PutReceipt(ctx, receipt); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate receipt = %v, want conflict", err)
	}
}

func TestGCSRetentionContractFailsClosed(t *testing.T) {
	objects := &fakeObjectStore{}
	if _, err := NewGCSRepository(objects, "estate-health-bucket", "estate-audit-bucket", 89, 400); err == nil {
		t.Fatal("wrong health retention was accepted")
	}
	if _, err := NewGCSRepository(objects, "estate-health-bucket", "estate-audit-bucket", 90, 399); err == nil {
		t.Fatal("wrong audit retention was accepted")
	}
}

func TestGCSCreateIsGenerationMatchedAndMapsConflict(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodPost || request.URL.Path != "/upload/storage/v1/b/estate-health-bucket/o" ||
			request.URL.Query().Get("uploadType") != "media" || request.URL.Query().Get("ifGenerationMatch") != "0" ||
			request.URL.Query().Get("name") != "health/snapshots/one.json" {
			t.Errorf("unexpected create request: %s %s", request.Method, request.URL.String())
		}
		if requests == 1 {
			writer.WriteHeader(http.StatusCreated)
			return
		}
		writer.WriteHeader(http.StatusPreconditionFailed)
	}))
	defer server.Close()
	objects, _ := NewGCSObjectStore(server.Client())
	objects.baseURL = server.URL
	if err := objects.Create(context.Background(), "estate-health-bucket", "health/snapshots/one.json", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := objects.Create(context.Background(), "estate-health-bucket", "health/snapshots/one.json", []byte("{}")); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate create = %v, want conflict", err)
	}
}

func TestGCSRepositoryRejectsTamperedReceipt(t *testing.T) {
	receipt := signedReceipt(t)
	receipt.ReasonCode = "TAMPERED"
	raw, _ := json.Marshal(receipt)
	objects := &fakeObjectStore{listed: []Object{{Name: receipt.AuditObject, Data: raw}}}
	repository, err := NewGCSRepository(objects, "estate-health-bucket", "estate-audit-bucket", 90, 400)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ListReceipts(context.Background(), 10); err == nil {
		t.Fatal("tampered stored receipt was accepted")
	}
}

func TestGCSOutboxIsCreateOnlyAndRoundTripsRecoveryState(t *testing.T) {
	objects := &mapObjectStore{values: map[string][]byte{}}
	repository, err := NewGCSRepository(objects, "estate-health-bucket", "estate-audit-bucket", 90, 400)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := contract.NewEphemeralSigner("test-key-v1")
	request := contract.OperationRequest{
		RequestID: "11111111-1111-4111-8111-111111111111", Operation: contract.OperationRerunFailed,
		Repository: "mindclade/bootstrap", WorkflowID: 42, WorkflowRunID: 84,
		ProtectedMainSHA: "0123456789abcdef0123456789abcdef01234567",
		PlanDigest:       "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", EvidenceDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Reason: "Retry the failed required workflow after runner recovery", RequestedBy: "operator@mindclade.example",
		IssuedAt: "2026-09-02T10:00:00Z", ExpiresAt: "2026-09-02T10:05:00Z", Nonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	if err := contract.SealRequest(&request, signer); err != nil {
		t.Fatal(err)
	}
	if err := repository.PutRequest(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	dispatch := contract.OperationDispatch{
		RequestID: request.RequestID, RequestDigest: request.Digest, ReceiptID: "22222222-2222-4222-8222-222222222222",
		RecoveryToken: "cmVjb3ZlcnktdjE", PreparedAt: "2026-09-02T10:00:01Z",
	}
	if err := contract.SealDispatch(&dispatch, signer); err != nil {
		t.Fatal(err)
	}
	if err := repository.PutDispatch(context.Background(), dispatch); err != nil {
		t.Fatal(err)
	}
	if err := repository.PutDispatch(context.Background(), dispatch); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate dispatch error=%v, want conflict", err)
	}
	stored, err := repository.GetDispatch(context.Background(), request.RequestID)
	if err != nil || stored.Digest != dispatch.Digest {
		t.Fatalf("stored dispatch=%#v err=%v", stored, err)
	}
	result := contract.OperationDispatchResult{
		RequestID: request.RequestID, RequestDigest: request.Digest, ReceiptID: dispatch.ReceiptID,
		Status: "accepted", ReasonCode: "GITHUB_OPERATION_RECOVERED", ProviderReference: "https://github.example/run/84",
		RecordedAt: "2026-09-02T10:00:02Z",
	}
	if err := contract.SealDispatchResult(&result, signer); err != nil {
		t.Fatal(err)
	}
	if err := repository.PutDispatchResult(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	storedResult, err := repository.GetDispatchResult(context.Background(), request.RequestID)
	if err != nil || storedResult.Digest != result.Digest {
		t.Fatalf("stored result=%#v err=%v", storedResult, err)
	}
}

func signedReceipt(t *testing.T) contract.OperationReceipt {
	t.Helper()
	now := time.Now()
	receipt := contract.OperationReceipt{
		ReceiptID: "22222222-2222-4222-8222-222222222222", RequestID: "11111111-1111-4111-8111-111111111111",
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Operation:     contract.OperationRerunFailed, Repository: "mindclade/bootstrap", Status: "accepted", ReasonCode: "LOCAL_SIMULATION_ACCEPTED",
		ProviderReference: "simulation://operations/11111111-1111-4111-8111-111111111111", RecordedAt: contract.Timestamp(now),
		AuditObject: "audit/operations/" + now.UTC().Format("2006/01/02") + "/22222222-2222-4222-8222-222222222222.json",
	}
	signer, _ := contract.NewEphemeralSigner("test-key-v1")
	if err := contract.SealReceipt(&receipt, signer); err != nil {
		t.Fatal(err)
	}
	return receipt
}

type fakeObjectStore struct{ listed []Object }

func (*fakeObjectStore) Create(context.Context, string, string, []byte) error { return nil }
func (*fakeObjectStore) Get(context.Context, string, string) ([]byte, error)  { return nil, ErrNotFound }
func (store *fakeObjectStore) List(context.Context, string, string, int) ([]Object, error) {
	return append([]Object(nil), store.listed...), nil
}

type mapObjectStore struct{ values map[string][]byte }

func (store *mapObjectStore) Create(_ context.Context, bucket, name string, data []byte) error {
	key := bucket + "/" + name
	if _, exists := store.values[key]; exists {
		return ErrConflict
	}
	store.values[key] = append([]byte(nil), data...)
	return nil
}
func (store *mapObjectStore) Get(_ context.Context, bucket, name string) ([]byte, error) {
	value, exists := store.values[bucket+"/"+name]
	if !exists {
		return nil, ErrNotFound
	}
	return append([]byte(nil), value...), nil
}
func (*mapObjectStore) List(context.Context, string, string, int) ([]Object, error) {
	return nil, nil
}
