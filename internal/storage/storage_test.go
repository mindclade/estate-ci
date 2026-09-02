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
	if err := repository.ReserveRequest(ctx, "11111111-1111-4111-8111-111111111111", binding, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", expiresAt); err != nil {
		t.Fatal(err)
	}
	if err := repository.ReserveRequest(ctx, "11111111-1111-4111-8111-111111111111", binding, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", expiresAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate reservation = %v, want conflict", err)
	}
	if err := repository.ReserveRequest(ctx, "33333333-3333-4333-8333-333333333333", binding, "cccccccccccccccccccccccccccccccc", expiresAt); !errors.Is(err, ErrConflict) {
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
