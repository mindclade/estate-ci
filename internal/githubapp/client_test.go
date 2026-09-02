package githubapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mindclade/estate-ci/internal/contract"
	"github.com/mindclade/estate-ci/internal/operations"
)

type staticToken string

func (token staticToken) Token(context.Context) (string, error) { return string(token), nil }

func TestBrokerUsesSeparateAppsAndObservesBindingsBeforeMutation(t *testing.T) {
	var mu sync.Mutex
	mutations := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authorization := request.Header.Get("Authorization")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/repos/mindclade/bootstrap/branches/main":
			if authorization != "Bearer observe-token" {
				t.Errorf("branch observation token = %q", authorization)
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"protected": true, "commit": map[string]string{"sha": testSHA}})
		case request.Method == http.MethodGet && request.URL.Path == "/repos/mindclade/bootstrap/actions/runs/84":
			if authorization != "Bearer observe-token" {
				t.Errorf("run observation token = %q", authorization)
			}
			_ = json.NewEncoder(writer).Encode(WorkflowRun{ID: 84, WorkflowID: 42, HeadSHA: testSHA, HeadBranch: "main", Status: "completed", Conclusion: "failure", HTMLURL: "https://github.example/run/84", RunAttempt: 1})
		case request.Method == http.MethodPost && request.URL.Path == "/repos/mindclade/bootstrap/actions/runs/84/rerun-failed-jobs":
			if authorization != "Bearer dispatch-token" {
				t.Errorf("dispatch token = %q", authorization)
			}
			mu.Lock()
			mutations++
			mu.Unlock()
			writer.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	observer, _ := NewClient(server.Client(), staticToken("observe-token"), server.URL)
	dispatcher, _ := NewClient(server.Client(), staticToken("dispatch-token"), server.URL)
	broker, err := NewBroker(observer, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	request := contract.OperationRequest{Operation: contract.OperationRerunFailed, Repository: "mindclade/bootstrap", WorkflowID: 42, WorkflowRunID: 84, ProtectedMainSHA: testSHA}
	target := operations.RepositoryTarget{Repository: request.Repository, MainBranch: "main", WorkflowIDs: map[string]int64{string(request.Operation): request.WorkflowID}}
	recoveryToken, prepared := broker.Prepare(context.Background(), target, request)
	if prepared.Final {
		t.Fatalf("preparation=%#v", prepared)
	}
	outcome := broker.Dispatch(context.Background(), target, request, recoveryToken)
	if !outcome.Accepted || outcome.ProviderReference == "" {
		t.Fatalf("outcome=%#v", outcome)
	}
	mu.Lock()
	got := mutations
	mu.Unlock()
	if got != 1 {
		t.Fatalf("mutations=%d, want 1", got)
	}

	request.ProtectedMainSHA = strings.Repeat("f", 40)
	_, outcome = broker.Prepare(context.Background(), target, request)
	if outcome.Accepted {
		t.Fatal("wrong protected main SHA was accepted")
	}
	mu.Lock()
	got = mutations
	mu.Unlock()
	if got != 1 {
		t.Fatalf("mutation occurred before binding validation: %d", got)
	}
}

func TestRefreshDispatchUsesObservedSHAAndRecoversLostResponse(t *testing.T) {
	var mu sync.Mutex
	dispatched := false
	postedRef := ""
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/repos/mindclade/bootstrap/branches/main":
			_ = json.NewEncoder(writer).Encode(map[string]any{"protected": true, "commit": map[string]string{"sha": testSHA}})
		case request.Method == http.MethodGet && request.URL.Path == "/repos/mindclade/bootstrap/actions/workflows/43/runs":
			mu.Lock()
			wasDispatched := dispatched
			mu.Unlock()
			runs := []WorkflowRun{}
			if wasDispatched {
				runs = append(runs, WorkflowRun{ID: 99, WorkflowID: 43, HeadSHA: testSHA, HeadBranch: "main", Status: "queued", HTMLURL: "https://github.example/run/99"})
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"workflow_runs": runs})
		case request.Method == http.MethodPost && request.URL.Path == "/repos/mindclade/bootstrap/actions/workflows/43/dispatches":
			var body struct {
				Ref    string            `json:"ref"`
				Inputs map[string]string `json:"inputs"`
			}
			_ = json.NewDecoder(request.Body).Decode(&body)
			mu.Lock()
			postedRef = body.Ref
			if body.Inputs["source_revision"] != testSHA || body.Inputs["evidence_digest"] != "sha256:"+strings.Repeat("a", 64) {
				t.Errorf("workflow dispatch inputs = %#v", body.Inputs)
			}
			dispatched = true
			mu.Unlock()
			panic(http.ErrAbortHandler)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	observer, _ := NewClient(server.Client(), staticToken("observe-token"), server.URL)
	dispatcher, _ := NewClient(server.Client(), staticToken("dispatch-token"), server.URL)
	broker, _ := NewBroker(observer, dispatcher)
	request := contract.OperationRequest{Operation: contract.OperationRefreshHealth, Repository: "mindclade/bootstrap", WorkflowID: 43, ProtectedMainSHA: testSHA, EvidenceDigest: "sha256:" + strings.Repeat("a", 64)}
	target := operations.RepositoryTarget{Repository: request.Repository, MainBranch: "main", WorkflowIDs: map[string]int64{string(request.Operation): request.WorkflowID}}
	token, prepared := broker.Prepare(context.Background(), target, request)
	if prepared.Final {
		t.Fatalf("preparation=%#v", prepared)
	}
	outcome := broker.Dispatch(context.Background(), target, request, token)
	if outcome.Final || outcome.ReasonCode != "GITHUB_DISPATCH_OUTCOME_PENDING" {
		t.Fatalf("ambiguous outcome=%#v", outcome)
	}
	mu.Lock()
	gotRef := postedRef
	mu.Unlock()
	if gotRef != testSHA {
		t.Fatalf("workflow dispatch ref=%q, want immutable %s", gotRef, testSHA)
	}
	recovered := broker.Recover(context.Background(), target, request, token)
	if !recovered.Final || !recovered.Accepted || recovered.ProviderReference != "https://github.example/run/99" {
		t.Fatalf("recovered outcome=%#v", recovered)
	}
}

func TestLoadGitHubAppKeyFromProjectedSecret(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	version := filepath.Join(root, "..2026_09_02")
	if err := os.Mkdir(version, 0o700); err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)})
	if err := os.WriteFile(filepath.Join(version, "private-key.pem"), raw, 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(version), filepath.Join(root, "..data")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "private-key.pem")
	if err := os.Symlink(filepath.Join("..data", "private-key.pem"), path); err != nil {
		t.Fatal(err)
	}
	loaded, err := readPrivateKey(path)
	if err != nil || loaded.N.Cmp(private.N) != 0 {
		t.Fatalf("projected GitHub App key err=%v", err)
	}
}

const testSHA = "0123456789abcdef0123456789abcdef01234567"
