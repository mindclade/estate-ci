package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mindclade/estate-ci/internal/contract"
)

type Object struct {
	Name string
	Data []byte
}

type ObjectStore interface {
	Create(context.Context, string, string, []byte) error
	Get(context.Context, string, string) ([]byte, error)
	List(context.Context, string, string, int) ([]Object, error)
}

type GCSObjectStore struct {
	client  *http.Client
	baseURL string
}

func NewGCSObjectStore(client *http.Client) (*GCSObjectStore, error) {
	if client == nil {
		return nil, errors.New("GCS ADC client is required")
	}
	return &GCSObjectStore{client: client, baseURL: "https://storage.googleapis.com"}, nil
}

func (store *GCSObjectStore) Create(ctx context.Context, bucket, name string, data []byte) error {
	if err := validateObjectAddress(bucket, name); err != nil {
		return err
	}
	endpoint := store.baseURL + "/upload/storage/v1/b/" + url.PathEscape(bucket) + "/o?uploadType=media&ifGenerationMatch=0&name=" + url.QueryEscape(name)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := store.client.Do(request)
	if err != nil {
		return fmt.Errorf("create GCS object: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusPreconditionFailed || response.StatusCode == http.StatusConflict {
		return ErrConflict
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		return fmt.Errorf("create GCS object: HTTP %d", response.StatusCode)
	}
	return nil
}

func (store *GCSObjectStore) Get(ctx context.Context, bucket, name string) ([]byte, error) {
	if err := validateObjectAddress(bucket, name); err != nil {
		return nil, err
	}
	endpoint := store.baseURL + "/storage/v1/b/" + url.PathEscape(bucket) + "/o/" + url.PathEscape(name) + "?alt=media"
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	response, err := store.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("read GCS object: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("read GCS object: HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024+1))
	if err != nil || len(data) > 2*1024*1024 {
		return nil, errors.New("GCS object exceeds the 2 MiB contract")
	}
	return data, nil
}

func (store *GCSObjectStore) List(ctx context.Context, bucket, prefix string, limit int) ([]Object, error) {
	if err := validateObjectAddress(bucket, prefix+"sentinel"); err != nil || limit <= 0 || limit > 1000 {
		return nil, errors.New("GCS list contract is invalid")
	}
	endpoint := store.baseURL + "/storage/v1/b/" + url.PathEscape(bucket) + "/o?fields=items(name),nextPageToken&maxResults=" + fmt.Sprint(limit) + "&prefix=" + url.QueryEscape(prefix)
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	response, err := store.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("list GCS objects: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list GCS objects: HTTP %d", response.StatusCode)
	}
	var payload struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
		NextPageToken string `json:"nextPageToken"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1024*1024))
	if err := decoder.Decode(&payload); err != nil || payload.NextPageToken != "" {
		return nil, errors.New("GCS listing is invalid or exceeds its fixed bound")
	}
	objects := make([]Object, 0, len(payload.Items))
	for _, item := range payload.Items {
		data, err := store.Get(ctx, bucket, item.Name)
		if err != nil {
			return nil, err
		}
		objects = append(objects, Object{Name: item.Name, Data: data})
	}
	return objects, nil
}

func validateObjectAddress(bucket, name string) error {
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{4,61}[a-z0-9]$`).MatchString(bucket) {
		return errors.New("GCS bucket name is invalid")
	}
	if name == "" || len(name) > 512 || strings.HasPrefix(name, "/") || strings.Contains(name, "..") || strings.ContainsAny(name, "\r\n\x00") {
		return errors.New("GCS object name is invalid")
	}
	return nil
}

type GCSRepository struct {
	objects      ObjectStore
	healthBucket string
	auditBucket  string
}

func NewGCSRepository(objects ObjectStore, healthBucket, auditBucket string, healthRetentionDays, auditRetentionDays int) (*GCSRepository, error) {
	if objects == nil || healthRetentionDays != HealthRetentionDays || auditRetentionDays != AuditRetentionDays {
		return nil, errors.New("GCS repository retention contract must be exactly 90/400 days")
	}
	if err := validateObjectAddress(healthBucket, "health/sentinel"); err != nil {
		return nil, err
	}
	if err := validateObjectAddress(auditBucket, "audit/sentinel"); err != nil {
		return nil, err
	}
	return &GCSRepository{objects: objects, healthBucket: healthBucket, auditBucket: auditBucket}, nil
}

func (repository *GCSRepository) LatestSnapshot(ctx context.Context) (contract.EstateHealthSnapshot, error) {
	values, err := repository.ListSnapshots(ctx, 100)
	if err != nil || len(values) == 0 {
		if err == nil {
			err = ErrNotFound
		}
		return contract.EstateHealthSnapshot{}, err
	}
	return values[0], nil
}

func (repository *GCSRepository) ListSnapshots(ctx context.Context, limit int) ([]contract.EstateHealthSnapshot, error) {
	objects, err := repository.objects.List(ctx, repository.healthBucket, "health/snapshots/", 1000)
	if err != nil {
		return nil, err
	}
	values := make([]contract.EstateHealthSnapshot, 0, len(objects))
	for _, object := range objects {
		var snapshot contract.EstateHealthSnapshot
		if err := strictJSON(object.Data, &snapshot); err != nil || snapshot.VerifyDigest() != nil {
			return nil, errors.New("stored health snapshot is invalid")
		}
		values = append(values, snapshot)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ObservedAt > values[j].ObservedAt })
	if limit <= 0 || limit > 100 {
		return nil, errors.New("snapshot list limit is invalid")
	}
	if len(values) > limit {
		values = values[:limit]
	}
	return values, nil
}

func (repository *GCSRepository) GetEvidence(ctx context.Context, digest string) (contract.WorkflowEvidence, error) {
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(digest) {
		return contract.WorkflowEvidence{}, ErrNotFound
	}
	raw, err := repository.objects.Get(ctx, repository.auditBucket, "audit/evidence/"+strings.TrimPrefix(digest, "sha256:")+".json")
	if err != nil {
		return contract.WorkflowEvidence{}, err
	}
	var evidence contract.WorkflowEvidence
	if err := strictJSON(raw, &evidence); err != nil || evidence.VerifyDigest(time.Time{}) != nil {
		return contract.WorkflowEvidence{}, errors.New("stored workflow evidence is invalid")
	}
	return evidence, nil
}

func (repository *GCSRepository) ReserveRequest(ctx context.Context, requestID, bindingDigest, nonce, expiresAt string) error {
	if err := validateReservation(requestID, bindingDigest, nonce, expiresAt); err != nil {
		return err
	}
	payload, _ := contract.CanonicalJSON(map[string]string{"request_id": requestID, "binding_digest": bindingDigest, "nonce": nonce, "expires_at": expiresAt})
	if err := repository.objects.Create(ctx, repository.auditBucket, "audit/replay/requests/"+requestID+".json", payload); err != nil {
		return err
	}
	return repository.objects.Create(ctx, repository.auditBucket, "audit/replay/bindings/"+strings.TrimPrefix(bindingDigest, "sha256:")+".json", payload)
}

func (repository *GCSRepository) PutRequest(ctx context.Context, request contract.OperationRequest) error {
	if err := request.VerifyDigest(time.Time{}); err != nil {
		return errors.New("operation request is invalid or unsealed")
	}
	payload, err := contract.CanonicalJSON(request)
	if err != nil {
		return err
	}
	return repository.objects.Create(ctx, repository.auditBucket, "audit/requests/"+request.RequestID+".json", payload)
}

func (repository *GCSRepository) PutReceipt(ctx context.Context, receipt contract.OperationReceipt) error {
	if err := receipt.VerifyDigest(); err != nil {
		return errors.New("operation receipt is invalid or unsealed")
	}
	payload, err := contract.CanonicalJSON(receipt)
	if err != nil {
		return err
	}
	return repository.objects.Create(ctx, repository.auditBucket, ReceiptObject(receipt), payload)
}

func (repository *GCSRepository) GetReceipt(ctx context.Context, receiptID string) (contract.OperationReceipt, error) {
	objects, err := repository.objects.List(ctx, repository.auditBucket, "audit/operations/", 1000)
	if err != nil {
		return contract.OperationReceipt{}, err
	}
	for _, object := range objects {
		if strings.HasSuffix(object.Name, "/"+receiptID+".json") {
			var receipt contract.OperationReceipt
			if err := strictJSON(object.Data, &receipt); err != nil || receipt.VerifyDigest() != nil {
				return contract.OperationReceipt{}, errors.New("stored operation receipt is invalid")
			}
			return receipt, nil
		}
	}
	return contract.OperationReceipt{}, ErrNotFound
}

func (repository *GCSRepository) ListReceipts(ctx context.Context, limit int) ([]contract.OperationReceipt, error) {
	objects, err := repository.objects.List(ctx, repository.auditBucket, "audit/operations/", 1000)
	if err != nil {
		return nil, err
	}
	values := make([]contract.OperationReceipt, 0, len(objects))
	for _, object := range objects {
		var receipt contract.OperationReceipt
		if err := strictJSON(object.Data, &receipt); err != nil || receipt.VerifyDigest() != nil {
			return nil, errors.New("stored operation receipt is invalid")
		}
		values = append(values, receipt)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].RecordedAt > values[j].RecordedAt })
	if limit <= 0 || limit > 100 {
		return nil, errors.New("receipt list limit is invalid")
	}
	if len(values) > limit {
		values = values[:limit]
	}
	return values, nil
}

func strictJSON(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("JSON contains trailing data")
	}
	return nil
}
