package githubapp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
			_ = json.NewEncoder(writer).Encode(WorkflowRun{ID: 84, WorkflowID: 42, HeadSHA: testSHA, HeadBranch: "main", Status: "completed", Conclusion: "failure", HTMLURL: "https://github.example/run/84"})
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
	outcome := broker.Dispatch(context.Background(), target, request)
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
	outcome = broker.Dispatch(context.Background(), target, request)
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

const testSHA = "0123456789abcdef0123456789abcdef01234567"
