package githubapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mindclade/estate-ci/internal/contract"
	"github.com/mindclade/estate-ci/internal/operations"
	"github.com/mindclade/estate-ci/internal/securefile"
)

type TokenSource interface {
	Token(context.Context) (string, error)
}

type AppConfig struct {
	AppID          int64  `json:"app_id"`
	InstallationID int64  `json:"installation_id"`
	PrivateKeyFile string `json:"private_key_file"`
}

type InstallationTokenSource struct {
	config  AppConfig
	client  *http.Client
	apiBase string
	now     func() time.Time
	mu      sync.Mutex
	token   string
	expires time.Time
}

func NewInstallationTokenSource(config AppConfig, client *http.Client, apiBase string) (*InstallationTokenSource, error) {
	if config.AppID <= 0 || config.InstallationID <= 0 || config.PrivateKeyFile == "" || client == nil {
		return nil, errors.New("GitHub App identity configuration is incomplete")
	}
	if err := validateAPIBase(apiBase); err != nil {
		return nil, err
	}
	return &InstallationTokenSource{config: config, client: client, apiBase: strings.TrimSuffix(apiBase, "/"), now: time.Now}, nil
}

func (source *InstallationTokenSource) Token(ctx context.Context) (string, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.token != "" && source.now().Add(time.Minute).Before(source.expires) {
		return source.token, nil
	}
	privateKey, err := readPrivateKey(source.config.PrivateKeyFile)
	if err != nil {
		return "", err
	}
	now := source.now().UTC()
	appJWT, err := signAppJWT(privateKey, source.config.AppID, now)
	if err != nil {
		return "", err
	}
	endpoint := fmt.Sprintf("%s/app/installations/%d/access_tokens", source.apiBase, source.config.InstallationID)
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte("{}")))
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+appJWT)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := source.client.Do(request)
	if err != nil {
		return "", errors.New("exchange GitHub App installation token")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("exchange GitHub App installation token: HTTP %d", response.StatusCode)
	}
	var payload struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 32*1024))
	if err := decoder.Decode(&payload); err != nil || decoder.Decode(&struct{}{}) != io.EOF || payload.Token == "" || len(payload.Token) > 4096 || strings.TrimSpace(payload.Token) != payload.Token || strings.ContainsAny(payload.Token, "\r\n\x00") {
		return "", errors.New("GitHub App installation token response is invalid")
	}
	expires, err := time.Parse(time.RFC3339, payload.ExpiresAt)
	if err != nil || !expires.After(now.Add(time.Minute)) || expires.After(now.Add(2*time.Hour)) {
		return "", errors.New("GitHub App installation token expiry is invalid")
	}
	source.token, source.expires = payload.Token, expires
	return source.token, nil
}

func readPrivateKey(path string) (*rsa.PrivateKey, error) {
	raw, err := securefile.ReadProjected(path, 64*1024, 0o400, 0o440, 0o600)
	if err != nil {
		return nil, errors.New("GitHub App private key must be a small 0400, 0440, or 0600 projected or regular file")
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "RSA PRIVATE KEY" && block.Type != "PRIVATE KEY" {
		return nil, errors.New("GitHub App private key PEM is invalid")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return validatePrivateKey(key)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("GitHub App private key is not PKCS#1 or PKCS#8")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("GitHub App private key is not RSA")
	}
	return validatePrivateKey(key)
}

func validatePrivateKey(key *rsa.PrivateKey) (*rsa.PrivateKey, error) {
	if key == nil || key.N.BitLen() < 2048 || key.N.BitLen() > 4096 || key.E < 3 || key.Validate() != nil {
		return nil, errors.New("GitHub App private key is outside the RSA security contract")
	}
	return key, nil
}

func signAppJWT(key *rsa.PrivateKey, appID int64, now time.Time) (string, error) {
	encode := func(value any) (string, error) {
		raw, err := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(raw), err
	}
	header, _ := encode(map[string]string{"alg": "RS256", "typ": "JWT"})
	payload, _ := encode(map[string]any{"iat": now.Add(-30 * time.Second).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": appID})
	signingInput := header + "." + payload
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", errors.New("sign GitHub App JWT")
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

type Client struct {
	client  *http.Client
	tokens  TokenSource
	apiBase string
}

func NewClient(client *http.Client, tokens TokenSource, apiBase string) (*Client, error) {
	if client == nil || tokens == nil {
		return nil, errors.New("GitHub client and token source are required")
	}
	if err := validateAPIBase(apiBase); err != nil {
		return nil, err
	}
	client.Timeout = 15 * time.Second
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("GitHub API redirects are forbidden")
	}
	return &Client{client: client, tokens: tokens, apiBase: strings.TrimSuffix(apiBase, "/")}, nil
}

func validateAPIBase(value string) error {
	parsed, err := url.Parse(value)
	localHTTP := parsed != nil && parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost")
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" || parsed.Scheme != "https" && !localHTTP {
		return errors.New("GitHub API base must use HTTPS")
	}
	return nil
}

type WorkflowRun struct {
	ID         int64  `json:"id"`
	WorkflowID int64  `json:"workflow_id"`
	HeadSHA    string `json:"head_sha"`
	HeadBranch string `json:"head_branch"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	HTMLURL    string `json:"html_url"`
	RunAttempt int64  `json:"run_attempt"`
}

func (client *Client) ObserveMain(ctx context.Context, repository string) (string, bool, error) {
	var payload struct {
		Protected bool `json:"protected"`
		Commit    struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if err := client.get(ctx, "/repos/"+repository+"/branches/main", &payload); err != nil {
		return "", false, err
	}
	return payload.Commit.SHA, payload.Protected, nil
}

func (client *Client) ObserveRun(ctx context.Context, repository string, runID int64) (WorkflowRun, error) {
	var run WorkflowRun
	if err := client.get(ctx, fmt.Sprintf("/repos/%s/actions/runs/%d", repository, runID), &run); err != nil {
		return WorkflowRun{}, err
	}
	return run, nil
}

func (client *Client) ObserveWorkflowRuns(ctx context.Context, repository string, workflowID int64, headSHA string) ([]WorkflowRun, error) {
	var payload struct {
		WorkflowRuns []WorkflowRun `json:"workflow_runs"`
	}
	path := fmt.Sprintf("/repos/%s/actions/workflows/%d/runs?branch=main&event=workflow_dispatch&head_sha=%s&per_page=100", repository, workflowID, headSHA)
	if err := client.get(ctx, path, &payload); err != nil {
		return nil, err
	}
	if len(payload.WorkflowRuns) > 100 {
		return nil, errors.New("GitHub workflow run observation exceeds its fixed bound")
	}
	return payload.WorkflowRuns, nil
}

func (client *Client) get(ctx context.Context, path string, destination any) error {
	response, err := client.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub observation returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 256*1024))
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("GitHub observation response is invalid")
	}
	return nil
}

func (client *Client) mutate(ctx context.Context, request contract.OperationRequest) (int, error) {
	var methodPath string
	var body []byte
	switch request.Operation {
	case contract.OperationRerunFailed:
		methodPath = fmt.Sprintf("/repos/%s/actions/runs/%d/rerun-failed-jobs", request.Repository, request.WorkflowRunID)
		body = []byte("{}")
	case contract.OperationCancelRun:
		methodPath = fmt.Sprintf("/repos/%s/actions/runs/%d/cancel", request.Repository, request.WorkflowRunID)
		body = []byte("{}")
	case contract.OperationRefreshHealth:
		methodPath = fmt.Sprintf("/repos/%s/actions/workflows/%d/dispatches", request.Repository, request.WorkflowID)
		body = []byte(fmt.Sprintf(`{"ref":"%s"}`, request.ProtectedMainSHA))
	default:
		return 0, errors.New("unsupported GitHub mutation")
	}
	response, err := client.do(ctx, http.MethodPost, methodPath, body)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	return response.StatusCode, nil
}

func (client *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	if !regexp.MustCompile(`^/repos/mindclade/(\.github|[a-z0-9][a-z0-9._-]{0,99})/`).MatchString(path) {
		return nil, errors.New("GitHub API path is outside the estate repository boundary")
	}
	token, err := client.tokens.Token(ctx)
	if err != nil {
		return nil, errors.New("obtain GitHub App installation token")
	}
	request, err := http.NewRequestWithContext(ctx, method, client.apiBase+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return client.client.Do(request)
}

type Broker struct {
	observer   *Client
	dispatcher *Client
}

type recoveryState struct {
	Operation          contract.Operation `json:"operation"`
	Repository         string             `json:"repository"`
	WorkflowID         int64              `json:"workflow_id"`
	WorkflowRunID      int64              `json:"workflow_run_id"`
	ProtectedMainSHA   string             `json:"protected_main_sha"`
	BaselineRunID      int64              `json:"baseline_run_id"`
	BaselineRunAttempt int64              `json:"baseline_run_attempt"`
	ProviderReference  string             `json:"provider_reference"`
}

func NewBroker(observer, dispatcher *Client) (*Broker, error) {
	if observer == nil || dispatcher == nil || observer == dispatcher {
		return nil, errors.New("separate observation and dispatch GitHub App clients are required")
	}
	return &Broker{observer: observer, dispatcher: dispatcher}, nil
}

func (broker *Broker) Prepare(ctx context.Context, target operations.RepositoryTarget, request contract.OperationRequest) (string, operations.DispatchOutcome) {
	if target.Repository != request.Repository || target.WorkflowIDs[string(request.Operation)] != request.WorkflowID {
		return rejectedPreparation("EXACT_CATALOG_BINDING_FAILED")
	}
	mainSHA, protected, err := broker.observer.ObserveMain(ctx, request.Repository)
	if err != nil || !protected || mainSHA != request.ProtectedMainSHA || target.MainBranch != "main" {
		return rejectedPreparation("PROTECTED_MAIN_OBSERVATION_FAILED")
	}
	state := recoveryState{
		Operation: request.Operation, Repository: request.Repository, WorkflowID: request.WorkflowID,
		WorkflowRunID: request.WorkflowRunID, ProtectedMainSHA: request.ProtectedMainSHA,
	}
	if request.Operation == contract.OperationRefreshHealth {
		runs, err := broker.observer.ObserveWorkflowRuns(ctx, request.Repository, request.WorkflowID, request.ProtectedMainSHA)
		if err != nil {
			return rejectedPreparation("WORKFLOW_RUN_BASELINE_FAILED")
		}
		for _, run := range runs {
			if run.WorkflowID == request.WorkflowID && run.HeadSHA == request.ProtectedMainSHA && run.ID > state.BaselineRunID {
				state.BaselineRunID = run.ID
			}
		}
	} else {
		run, err := broker.observer.ObserveRun(ctx, request.Repository, request.WorkflowRunID)
		if err != nil || run.ID != request.WorkflowRunID || run.WorkflowID != request.WorkflowID || run.HeadSHA != request.ProtectedMainSHA || run.HeadBranch != "main" {
			return rejectedPreparation("WORKFLOW_RUN_BINDING_FAILED")
		}
		state.ProviderReference = run.HTMLURL
		state.BaselineRunAttempt = run.RunAttempt
		if len(state.ProviderReference) > 512 || !strings.HasPrefix(state.ProviderReference, "https://") || strings.ContainsAny(state.ProviderReference, "\r\n\x00") {
			return rejectedPreparation("WORKFLOW_RUN_REFERENCE_INVALID")
		}
		if request.Operation == contract.OperationRerunFailed && (run.Status != "completed" || run.Conclusion == "success" || run.Conclusion == "") {
			return rejectedPreparation("WORKFLOW_RUN_NOT_FAILED")
		}
		if request.Operation == contract.OperationCancelRun && run.Status != "queued" && run.Status != "in_progress" {
			return rejectedPreparation("WORKFLOW_RUN_NOT_CANCELLABLE")
		}
	}
	token, err := encodeRecoveryState(state)
	if err != nil {
		return rejectedPreparation("RECOVERY_STATE_INVALID")
	}
	return token, operations.DispatchOutcome{}
}

func (broker *Broker) Dispatch(ctx context.Context, target operations.RepositoryTarget, request contract.OperationRequest, recoveryToken string) operations.DispatchOutcome {
	state, err := decodeRecoveryState(recoveryToken, target, request)
	if err != nil {
		return operations.DispatchOutcome{Final: true, ReasonCode: "RECOVERY_STATE_INVALID"}
	}
	status, err := broker.dispatcher.mutate(ctx, request)
	if err != nil {
		return operations.DispatchOutcome{ReasonCode: "GITHUB_DISPATCH_OUTCOME_PENDING"}
	}
	expected := http.StatusCreated
	if request.Operation == contract.OperationCancelRun {
		expected = http.StatusAccepted
	} else if request.Operation == contract.OperationRefreshHealth {
		expected = http.StatusNoContent
	}
	if status != expected {
		if status >= http.StatusInternalServerError {
			return operations.DispatchOutcome{ReasonCode: "GITHUB_DISPATCH_OUTCOME_PENDING"}
		}
		return operations.DispatchOutcome{Final: true, ReasonCode: "GITHUB_DISPATCH_REJECTED"}
	}
	return operations.DispatchOutcome{Final: true, Accepted: true, ReasonCode: "GITHUB_OPERATION_ACCEPTED", ProviderReference: state.ProviderReference}
}

func (broker *Broker) Recover(ctx context.Context, target operations.RepositoryTarget, request contract.OperationRequest, recoveryToken string) operations.DispatchOutcome {
	state, err := decodeRecoveryState(recoveryToken, target, request)
	if err != nil {
		return operations.DispatchOutcome{Final: true, ReasonCode: "RECOVERY_STATE_INVALID"}
	}
	if request.Operation == contract.OperationRefreshHealth {
		runs, err := broker.observer.ObserveWorkflowRuns(ctx, request.Repository, request.WorkflowID, request.ProtectedMainSHA)
		if err != nil {
			return operations.DispatchOutcome{ReasonCode: "GITHUB_DISPATCH_OUTCOME_PENDING"}
		}
		var candidate *WorkflowRun
		for index := range runs {
			run := &runs[index]
			if run.ID > state.BaselineRunID && run.WorkflowID == request.WorkflowID && run.HeadSHA == request.ProtectedMainSHA {
				if candidate != nil {
					return operations.DispatchOutcome{ReasonCode: "GITHUB_DISPATCH_OUTCOME_PENDING"}
				}
				candidate = run
			}
		}
		if candidate != nil && len(candidate.HTMLURL) <= 512 && strings.HasPrefix(candidate.HTMLURL, "https://") && !strings.ContainsAny(candidate.HTMLURL, "\r\n\x00") {
			return operations.DispatchOutcome{Final: true, Accepted: true, ReasonCode: "GITHUB_OPERATION_RECOVERED", ProviderReference: candidate.HTMLURL}
		}
		return operations.DispatchOutcome{ReasonCode: "GITHUB_DISPATCH_OUTCOME_PENDING"}
	}
	run, err := broker.observer.ObserveRun(ctx, request.Repository, request.WorkflowRunID)
	if err != nil || run.ID != request.WorkflowRunID || run.WorkflowID != request.WorkflowID || run.HeadSHA != request.ProtectedMainSHA {
		return operations.DispatchOutcome{ReasonCode: "GITHUB_DISPATCH_OUTCOME_PENDING"}
	}
	if request.Operation == contract.OperationRerunFailed && run.RunAttempt > state.BaselineRunAttempt {
		return operations.DispatchOutcome{Final: true, Accepted: true, ReasonCode: "GITHUB_OPERATION_RECOVERED", ProviderReference: state.ProviderReference}
	}
	if request.Operation == contract.OperationCancelRun && run.Status == "completed" && run.Conclusion == "cancelled" {
		return operations.DispatchOutcome{Final: true, Accepted: true, ReasonCode: "GITHUB_OPERATION_RECOVERED", ProviderReference: state.ProviderReference}
	}
	return operations.DispatchOutcome{ReasonCode: "GITHUB_DISPATCH_OUTCOME_PENDING"}
}

func rejectedPreparation(reason string) (string, operations.DispatchOutcome) {
	return "cHJlcGFyYXRpb24tcmVqZWN0ZWQ", operations.DispatchOutcome{Final: true, ReasonCode: reason}
}

func encodeRecoveryState(state recoveryState) (string, error) {
	raw, err := contract.CanonicalJSON(state)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeRecoveryState(token string, target operations.RepositoryTarget, request contract.OperationRequest) (recoveryState, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) > 3072 {
		return recoveryState{}, errors.New("recovery state is invalid")
	}
	var state recoveryState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return recoveryState{}, errors.New("recovery state is invalid")
	}
	if state.Operation != request.Operation || state.Repository != request.Repository || state.WorkflowID != request.WorkflowID ||
		state.WorkflowRunID != request.WorkflowRunID || state.ProtectedMainSHA != request.ProtectedMainSHA ||
		target.Repository != request.Repository || target.WorkflowIDs[string(request.Operation)] != request.WorkflowID {
		return recoveryState{}, errors.New("recovery state does not bind the request")
	}
	return state, nil
}
