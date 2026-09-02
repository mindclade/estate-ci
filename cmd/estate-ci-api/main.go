package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mindclade/estate-ci/internal/adc"
	"github.com/mindclade/estate-ci/internal/api"
	"github.com/mindclade/estate-ci/internal/auth"
	"github.com/mindclade/estate-ci/internal/contract"
	"github.com/mindclade/estate-ci/internal/githubapp"
	"github.com/mindclade/estate-ci/internal/operations"
	"github.com/mindclade/estate-ci/internal/storage"
)

const cloudIdentityScope = "https://www.googleapis.com/auth/cloud-identity.groups.readonly"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(context.Background(), logger); err != nil {
		logger.Error("estate-ci API stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	mode := environment("ESTATE_MODE", "source-ready")
	if mode != "development" && mode != "source-ready" && mode != "connected" {
		return errors.New("ESTATE_MODE must be development, source-ready, or connected")
	}
	catalogPath := environment("ESTATE_CATALOG_PATH", "config/repositories.source-ready.json")
	if mode == "development" && os.Getenv("ESTATE_CATALOG_PATH") == "" {
		catalogPath = "config/repositories.development.json"
	}
	catalog, err := operations.LoadCatalog(catalogPath)
	if err != nil {
		return err
	}
	if mode == "connected" && !catalog.Connected() {
		return errors.New("connected mode requires a connected exact workflow catalog")
	}

	var repository storage.Repository
	var validator auth.TokenValidator
	var roles auth.RoleResolver
	var dispatcher operations.Dispatcher
	var signer contract.Signer
	secureCookies := mode != "development"
	origin := environment("ESTATE_ALLOWED_ORIGIN", "https://estate-ci.invalid")

	if mode == "development" {
		memory := storage.NewMemoryRepository()
		if err := seedDevelopment(memory, catalog); err != nil {
			return err
		}
		repository = memory
		validator = developmentValidator{}
		roles = developmentRoles{}
		dispatcher = operations.SimulationDispatcher{}
		signer, err = contract.NewEphemeralSigner("development-ephemeral-v1")
		origin = environment("ESTATE_ALLOWED_ORIGIN", "http://localhost:3000")
	} else {
		iapAudience, err := required("IAP_AUDIENCE")
		if err != nil {
			return err
		}
		validator, err = auth.NewJWKSValidator(iapAudience)
		if err != nil {
			return err
		}
		bindingsJSON, err := required("WORKSPACE_GROUP_BINDINGS_JSON")
		if err != nil {
			return err
		}
		bindings, err := groupBindings(bindingsJSON)
		if err != nil {
			return err
		}
		identityClient, err := adc.NewMetadataClient(cloudIdentityScope)
		if err != nil {
			return errors.New("initialize Cloud Identity ADC")
		}
		checker, err := auth.NewCloudIdentityChecker(identityClient)
		if err != nil {
			return err
		}
		roles, err = auth.NewWorkspaceRoleResolver(bindings, checker)
		if err != nil {
			return err
		}
		storageClient, err := adc.NewMetadataClient("https://www.googleapis.com/auth/devstorage.read_write")
		if err != nil {
			return errors.New("initialize GCS ADC")
		}
		storageClient.Timeout = 15 * time.Second
		objects, err := storage.NewGCSObjectStore(storageClient)
		if err != nil {
			return err
		}
		healthBucket, err := required("HEALTH_BUCKET")
		if err != nil {
			return err
		}
		auditBucket, err := required("AUDIT_BUCKET")
		if err != nil {
			return err
		}
		repository, err = storage.NewGCSRepository(objects, healthBucket, auditBucket, storage.HealthRetentionDays, storage.AuditRetentionDays)
		if err != nil {
			return err
		}
		signingKeyID, err := required("OPERATION_SIGNING_KEY_ID")
		if err != nil {
			return err
		}
		signingKeyFile, err := required("OPERATION_SIGNING_KEY_FILE")
		if err != nil {
			return err
		}
		signer, err = contract.LoadEd25519Signer(signingKeyID, signingKeyFile)
		if err != nil {
			return err
		}
		dispatcher = operations.FailClosedDispatcher{}
		if mode == "connected" {
			dispatcher, err = connectedDispatcher()
			if err != nil {
				return err
			}
		}
	}

	service, err := operations.NewService(catalog, repository, roles, dispatcher, signer)
	if err != nil {
		return err
	}
	runtimeState := mode
	if mode == "development" {
		runtimeState = "development-simulation"
	}
	apiServer, err := api.NewServer(api.Config{AllowedOrigin: origin, SecureCookies: secureCookies, RuntimeState: runtimeState, Logger: logger}, validator, roles, repository, service, catalog)
	if err != nil {
		return err
	}
	port := environment("PORT", "8080")
	server := &http.Server{
		Addr: ":" + port, Handler: requestLog(logger, apiServer.Handler()),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 32 * 1024,
	}
	shutdownContext, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errorsChannel := make(chan error, 1)
	go func() {
		logger.Info("estate-ci API listening", "address", server.Addr, "mode", mode, "connected_dispatch", catalog.Connected() && mode == "connected")
		errorsChannel <- server.ListenAndServe()
	}()
	select {
	case err := <-errorsChannel:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-shutdownContext.Done():
		deadline, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return server.Shutdown(deadline)
	}
}

func connectedDispatcher() (operations.Dispatcher, error) {
	observationConfig, err := appConfig("OBSERVATION_GITHUB_APP")
	if err != nil {
		return nil, err
	}
	dispatchConfig, err := appConfig("DISPATCH_GITHUB_APP")
	if err != nil {
		return nil, err
	}
	if observationConfig.AppID == dispatchConfig.AppID || observationConfig.InstallationID == dispatchConfig.InstallationID ||
		filepath.Clean(observationConfig.PrivateKeyFile) == filepath.Clean(dispatchConfig.PrivateKeyFile) {
		return nil, errors.New("observation and dispatch GitHub Apps must be separate identities")
	}
	apiBase := environment("GITHUB_API_URL", "https://api.github.com")
	observationHTTP := &http.Client{Timeout: 15 * time.Second}
	dispatchHTTP := &http.Client{Timeout: 15 * time.Second}
	observationTokens, err := githubapp.NewInstallationTokenSource(observationConfig, observationHTTP, apiBase)
	if err != nil {
		return nil, err
	}
	dispatchTokens, err := githubapp.NewInstallationTokenSource(dispatchConfig, dispatchHTTP, apiBase)
	if err != nil {
		return nil, err
	}
	observer, err := githubapp.NewClient(observationHTTP, observationTokens, apiBase)
	if err != nil {
		return nil, err
	}
	dispatcher, err := githubapp.NewClient(dispatchHTTP, dispatchTokens, apiBase)
	if err != nil {
		return nil, err
	}
	return githubapp.NewBroker(observer, dispatcher)
}

func appConfig(prefix string) (githubapp.AppConfig, error) {
	appIDText, err := required(prefix + "_ID")
	if err != nil {
		return githubapp.AppConfig{}, err
	}
	appID, err := strconv.ParseInt(appIDText, 10, 64)
	if err != nil {
		return githubapp.AppConfig{}, fmt.Errorf("%s_ID is invalid", prefix)
	}
	installationIDText, err := required(prefix + "_INSTALLATION_ID")
	if err != nil {
		return githubapp.AppConfig{}, err
	}
	installationID, err := strconv.ParseInt(installationIDText, 10, 64)
	if err != nil {
		return githubapp.AppConfig{}, fmt.Errorf("%s_INSTALLATION_ID is invalid", prefix)
	}
	privateKeyFile, err := required(prefix + "_PRIVATE_KEY_FILE")
	if err != nil {
		return githubapp.AppConfig{}, err
	}
	return githubapp.AppConfig{AppID: appID, InstallationID: installationID, PrivateKeyFile: privateKeyFile}, nil
}

func groupBindings(raw string) ([]auth.GroupBinding, error) {
	var bindings []auth.GroupBinding
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bindings); err != nil {
		return nil, errors.New("WORKSPACE_GROUP_BINDINGS_JSON is invalid")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("WORKSPACE_GROUP_BINDINGS_JSON contains trailing data")
	}
	return bindings, nil
}

func seedDevelopment(repository *storage.MemoryRepository, catalog *operations.Catalog) error {
	now := time.Now().UTC().Truncate(time.Second)
	mainSHA := "0123456789abcdef0123456789abcdef01234567"
	repositories := make([]contract.RepositoryHealth, 0)
	for index, target := range catalog.Repositories() {
		workflowID := target.WorkflowIDs[string(contract.OperationRerunFailed)]
		planDigest := fmt.Sprintf("sha256:%064x", index+1)
		evidence := contract.WorkflowEvidence{
			Repository: target.Repository, WorkflowID: workflowID, WorkflowRunID: int64(10000 + index), ProtectedMainSHA: mainSHA,
			PlanDigest: planDigest, Conclusion: "success", Superseded: true,
			Approval:   contract.ApprovalEvidence{Approvers: []string{"approver@mindclade.example"}, ApprovedAt: contract.Timestamp(now), Decision: "approved"},
			ObservedAt: contract.Timestamp(now), ExpiresAt: contract.Timestamp(now.Add(24 * time.Hour)),
		}
		if err := evidence.Seal(); err != nil {
			return err
		}
		if err := repository.SeedEvidence(evidence); err != nil {
			return err
		}
		status, failure := "success", "none"
		if index == 4 {
			status, failure = "failure", "permissions"
		}
		profile := "nix-standard"
		if target.Repository == "mindclade/estate-ci" {
			profile = "buildkite-isolated"
		}
		repositories = append(repositories, contract.RepositoryHealth{
			Repository: target.Repository, Profile: profile, HeadSHA: mainSHA, LastGreenSHA: mainSHA,
			RequiredCheckStatus: status, QueueSeconds: int64(18 + index*4), ExecutionSeconds: int64(92 + index*11),
			FailureClass: failure, CacheHitBasisPoints: int64(8700 - index*190), EvidenceDigest: evidence.Digest, ObservedAt: contract.Timestamp(now),
		})
	}
	snapshot := contract.EstateHealthSnapshot{
		SnapshotID: "10000000-0000-4000-8000-000000000001", ObservedAt: contract.Timestamp(now), ProtectedMainSHA: mainSHA,
		Summary: contract.HealthSummary{Healthy: int64(len(repositories) - 1), Degraded: 1}, Repositories: repositories,
	}
	if err := snapshot.Seal(); err != nil {
		return err
	}
	return repository.SeedSnapshot(snapshot)
}

type developmentValidator struct{}

func (developmentValidator) Validate(_ context.Context, token string) (auth.Identity, error) {
	if token != "local-development" {
		return auth.Identity{}, errors.New("invalid development assertion")
	}
	return auth.Identity{Subject: "development", Email: "dev@mindclade.example", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}, nil
}

type developmentRoles struct{}

func (developmentRoles) RoleFor(_ context.Context, email string) (auth.Role, error) {
	switch strings.ToLower(email) {
	case "dev@mindclade.example":
		return auth.RoleAdmin, nil
	case "approver@mindclade.example":
		return auth.RoleApprover, nil
	default:
		return auth.RoleNone, nil
	}
}

func environment(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func required(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("required environment variable is missing: %s", name)
	}
	return value, nil
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (writer *statusWriter) WriteHeader(status int) {
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func requestLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		wrapped := &statusWriter{ResponseWriter: writer, status: http.StatusOK}
		next.ServeHTTP(wrapped, request)
		logger.Info("request completed", "method", request.Method, "path", request.URL.Path, "status", wrapped.status, "duration_ms", time.Since(started).Milliseconds())
	})
}
