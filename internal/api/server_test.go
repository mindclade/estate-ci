package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mindclade/estate-ci/internal/auth"
	"github.com/mindclade/estate-ci/internal/contract"
	"github.com/mindclade/estate-ci/internal/operations"
	"github.com/mindclade/estate-ci/internal/storage"
)

type apiValidator struct{}

func (apiValidator) Validate(_ context.Context, token string) (auth.Identity, error) {
	if token == "operator" {
		return auth.Identity{Email: "operator@mindclade.example"}, nil
	}
	if token == "viewer" {
		return auth.Identity{Email: "viewer@mindclade.example"}, nil
	}
	return auth.Identity{}, context.Canceled
}

type apiRoles map[string]auth.Role

func (roles apiRoles) RoleFor(_ context.Context, email string) (auth.Role, error) {
	return roles[email], nil
}

func apiFixture(t *testing.T) (*Server, contract.OperationIntent) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	repository := storage.NewMemoryRepository()
	evidence := contract.WorkflowEvidence{
		Repository: "mindclade/bootstrap", WorkflowID: 42, WorkflowRunID: 84,
		ProtectedMainSHA: testSHA, PlanDigest: testDigest, Conclusion: "success",
		Approval:   contract.ApprovalEvidence{Approvers: []string{"approver@mindclade.example"}, ApprovedAt: contract.Timestamp(now), Decision: "approved"},
		ObservedAt: contract.Timestamp(now), ExpiresAt: contract.Timestamp(now.Add(time.Hour)),
	}
	if err := evidence.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := repository.SeedEvidence(evidence); err != nil {
		t.Fatal(err)
	}
	snapshot := contract.EstateHealthSnapshot{
		SnapshotID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ObservedAt: contract.Timestamp(now), ProtectedMainSHA: testSHA,
		Summary: contract.HealthSummary{Healthy: 1},
		Repositories: []contract.RepositoryHealth{{Repository: "mindclade/bootstrap", Profile: "buildkite-isolated", HeadSHA: testSHA, LastGreenSHA: testSHA,
			RequiredCheckStatus: "success", FailureClass: "none", EvidenceDigest: evidence.Digest, ObservedAt: contract.Timestamp(now)}},
	}
	if err := snapshot.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := repository.SeedSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	catalog, err := operations.NewCatalog(operations.CatalogDocument{SchemaVersion: "estate.operation-catalog/v1", Connected: true, Repositories: []operations.RepositoryTarget{{
		Repository: "mindclade/bootstrap", MainBranch: "main", WorkflowIDs: map[string]int64{
			string(contract.OperationRefreshHealth): 43, string(contract.OperationRerunFailed): 42, string(contract.OperationCancelRun): 42,
		},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	roles := apiRoles{"operator@mindclade.example": auth.RoleOperator, "viewer@mindclade.example": auth.RoleViewer, "approver@mindclade.example": auth.RoleApprover}
	signer, _ := contract.NewEphemeralSigner("test-key-v1")
	service, _ := operations.NewService(catalog, repository, roles, operations.SimulationDispatcher{}, signer)
	server, err := NewServer(Config{AllowedOrigin: "http://estate.local", SecureCookies: false, RuntimeState: "development-simulation"}, apiValidator{}, roles, repository, service, catalog)
	if err != nil {
		t.Fatal(err)
	}
	intent := contract.OperationIntent{
		SchemaVersion: operations.IntentSchemaVersion, RequestID: "11111111-1111-4111-8111-111111111111",
		Operation: contract.OperationRerunFailed, Repository: "mindclade/bootstrap", WorkflowID: 42, WorkflowRunID: 84,
		ProtectedMainSHA: testSHA, PlanDigest: testDigest, EvidenceDigest: evidence.Digest,
		Reason: "Retry the failed required workflow after runner recovery", ExpiresAt: contract.Timestamp(now.Add(5 * time.Minute)),
	}
	return server, intent
}

func TestAPIRequiresIAPAndDeniesViewerOperations(t *testing.T) {
	server, intent := apiFixture(t)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/estate", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing IAP status=%d", recorder.Code)
	}

	body, _ := json.Marshal(intent)
	request = httptest.NewRequest(http.MethodPost, "/api/v1/operations", bytes.NewReader(body))
	request.Header.Set("X-Goog-IAP-JWT-Assertion", "viewer")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("viewer operation status=%d", recorder.Code)
	}
}

func TestAPICSRFAndDuplicateProtection(t *testing.T) {
	server, intent := apiFixture(t)
	session := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	session.Header.Set("X-Goog-IAP-JWT-Assertion", "operator")
	sessionRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(sessionRecorder, session)
	if sessionRecorder.Code != http.StatusOK {
		t.Fatalf("session status=%d", sessionRecorder.Code)
	}
	var sessionBody map[string]any
	_ = json.Unmarshal(sessionRecorder.Body.Bytes(), &sessionBody)
	cookie := sessionRecorder.Result().Cookies()[0]
	body, _ := json.Marshal(intent)

	post := func(withCSRF bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/operations", bytes.NewReader(body))
		request.Header.Set("X-Goog-IAP-JWT-Assertion", "operator")
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(cookie)
		if withCSRF {
			request.Header.Set("Origin", "http://estate.local")
			request.Header.Set("Sec-Fetch-Site", "same-origin")
			request.Header.Set("X-Estate-CSRF", sessionBody["csrf_token"].(string))
		}
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		return recorder
	}
	if got := post(false).Code; got != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d", got)
	}
	if got := post(true).Code; got != http.StatusAccepted {
		t.Fatalf("valid operation status=%d", got)
	}
	if got := post(true).Code; got != http.StatusConflict {
		t.Fatalf("duplicate operation status=%d", got)
	}
}

func TestAPIStrictSchemaRejectsUnknownFieldsAndPathEscape(t *testing.T) {
	server, _ := apiFixture(t)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/repositories/mindclade/bootstrap/../../secret", nil)
	request.Header.Set("X-Goog-IAP-JWT-Assertion", "operator")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest && recorder.Code != http.StatusNotFound {
		t.Fatalf("escape status=%d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "secret") {
		t.Fatal("path escape leaked input")
	}
}

const (
	testSHA    = "0123456789abcdef0123456789abcdef01234567"
	testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)
