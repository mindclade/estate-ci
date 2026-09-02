package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mindclade/estate-ci/internal/auth"
	"github.com/mindclade/estate-ci/internal/contract"
	"github.com/mindclade/estate-ci/internal/operations"
	"github.com/mindclade/estate-ci/internal/storage"
)

type Config struct {
	AllowedOrigin string
	SecureCookies bool
	RuntimeState  string
	Logger        *slog.Logger
}

var (
	repositoryPathPattern = regexp.MustCompile(`^mindclade/(\.github|[a-z0-9][a-z0-9._-]{0,99})$`)
	receiptIDPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type Server struct {
	config     Config
	validator  auth.TokenValidator
	roles      auth.RoleResolver
	repository storage.Repository
	operations *operations.Service
	catalog    *operations.Catalog
	handler    http.Handler
}

type principalContextKey struct{}

type Principal struct {
	Identity auth.Identity
	Role     auth.Role
}

func NewServer(config Config, validator auth.TokenValidator, roles auth.RoleResolver, repository storage.Repository, operationService *operations.Service, catalog *operations.Catalog) (*Server, error) {
	if validator == nil || roles == nil || repository == nil || operationService == nil || catalog == nil {
		return nil, errors.New("API dependencies are required")
	}
	origin, err := url.Parse(config.AllowedOrigin)
	if err != nil || origin.Scheme != "http" && origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" && origin.Path != "/" {
		return nil, errors.New("allowed origin must be an exact scheme and host")
	}
	if config.SecureCookies && origin.Scheme != "https" {
		return nil, errors.New("secure API requires an HTTPS origin")
	}
	if config.RuntimeState != "development-simulation" && config.RuntimeState != "source-ready" && config.RuntimeState != "connected" {
		return nil, errors.New("API runtime state is invalid")
	}
	if config.RuntimeState == "source-ready" && catalog.Connected() || config.RuntimeState != "source-ready" && !catalog.Connected() {
		return nil, errors.New("API runtime state and exact operation catalog disagree")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	server := &Server{config: config, validator: validator, roles: roles, repository: repository, operations: operationService, catalog: catalog}
	server.handler = server.securityHeaders(server.authenticate(http.HandlerFunc(server.route)))
	return server, nil
}

func (server *Server) Handler() http.Handler { return server.handler }

func (server *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		writer.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(writer, request)
	})
}

func (server *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/healthz" || request.URL.Path == "/readyz" {
			next.ServeHTTP(writer, request)
			return
		}
		if !strings.HasPrefix(request.URL.Path, "/api/v1/") {
			problem(writer, http.StatusNotFound, "NOT_FOUND", "The requested route does not exist.")
			return
		}
		assertion := request.Header.Get("X-Goog-IAP-JWT-Assertion")
		if assertion == "" {
			problem(writer, http.StatusUnauthorized, "IAP_ASSERTION_REQUIRED", "A valid IAP assertion is required.")
			return
		}
		identity, err := server.validator.Validate(request.Context(), assertion)
		if err != nil {
			problem(writer, http.StatusUnauthorized, "IAP_ASSERTION_INVALID", "The IAP assertion could not be verified.")
			return
		}
		role, err := server.roles.RoleFor(request.Context(), identity.Email)
		if err != nil {
			problem(writer, http.StatusServiceUnavailable, "ROLE_RESOLUTION_FAILED", "Workspace role resolution is unavailable.")
			return
		}
		if role < auth.RoleViewer {
			problem(writer, http.StatusForbidden, "ROLE_DENIED", "The authenticated account has no estate role.")
			return
		}
		principal := Principal{Identity: identity, Role: role}
		next.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), principalContextKey{}, principal)))
	})
}

func (server *Server) route(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/healthz" {
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, http.MethodGet)
			return
		}
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	if request.URL.Path == "/readyz" {
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, http.MethodGet)
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"status": "ready", "connected_dispatch": server.config.RuntimeState == "connected"})
		return
	}
	principal := request.Context().Value(principalContextKey{}).(Principal)
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/api/v1/session":
		server.session(writer, principal)
	case request.Method == http.MethodGet && request.URL.Path == "/api/v1/estate":
		server.latestEstate(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/api/v1/estate/history":
		server.estateHistory(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/api/v1/repositories":
		server.repositories(writer, request)
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/api/v1/repositories/"):
		server.repositoryHealth(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/api/v1/evidence":
		server.evidence(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/api/v1/operations/options":
		writeJSON(writer, http.StatusOK, map[string]any{"connected": server.config.RuntimeState == "connected", "operation_submission_enabled": server.config.RuntimeState != "source-ready", "repositories": server.catalog.Repositories()})
	case request.Method == http.MethodGet && request.URL.Path == "/api/v1/operations":
		server.listOperations(writer, request)
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/api/v1/operations/"):
		server.getOperation(writer, request)
	case request.Method == http.MethodPost && request.URL.Path == "/api/v1/operations":
		server.createOperation(writer, request, principal)
	case request.URL.Path == "/api/v1/operations":
		methodNotAllowed(writer, http.MethodGet+", "+http.MethodPost)
	default:
		problem(writer, http.StatusNotFound, "NOT_FOUND", "The requested route does not exist.")
	}
}

func (server *Server) session(writer http.ResponseWriter, principal Principal) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		problem(writer, http.StatusInternalServerError, "CSRF_TOKEN_FAILED", "A session token could not be created.")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	name := "estate-csrf"
	if server.config.SecureCookies {
		name = "__Host-estate-csrf"
	}
	http.SetCookie(writer, &http.Cookie{Name: name, Value: token, Path: "/", MaxAge: 1800, Secure: server.config.SecureCookies, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(writer, http.StatusOK, map[string]any{
		"email": principal.Identity.Email, "role": principal.Role.String(), "csrf_token": token,
		"runtime_state": server.config.RuntimeState, "connected_dispatch": server.config.RuntimeState == "connected",
		"operation_submission_enabled": server.config.RuntimeState != "source-ready",
	})
}

func (server *Server) latestEstate(writer http.ResponseWriter, request *http.Request) {
	snapshot, err := server.repository.LatestSnapshot(request.Context())
	if err != nil {
		storageProblem(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, snapshot)
}

func (server *Server) estateHistory(writer http.ResponseWriter, request *http.Request) {
	limit, ok := queryLimit(request, 20)
	if !ok {
		problem(writer, http.StatusBadRequest, "INVALID_LIMIT", "limit must be between 1 and 100.")
		return
	}
	snapshots, err := server.repository.ListSnapshots(request.Context(), limit)
	if err != nil {
		storageProblem(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"snapshots": snapshots})
}

func (server *Server) repositories(writer http.ResponseWriter, request *http.Request) {
	snapshot, err := server.repository.LatestSnapshot(request.Context())
	if err != nil {
		storageProblem(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"observed_at": snapshot.ObservedAt, "repositories": snapshot.Repositories})
}

func (server *Server) repositoryHealth(writer http.ResponseWriter, request *http.Request) {
	identifier := strings.TrimPrefix(request.URL.Path, "/api/v1/repositories/")
	if !repositoryPathPattern.MatchString(identifier) {
		problem(writer, http.StatusBadRequest, "INVALID_REPOSITORY", "Repository identity is invalid.")
		return
	}
	snapshot, err := server.repository.LatestSnapshot(request.Context())
	if err != nil {
		storageProblem(writer, err)
		return
	}
	for _, item := range snapshot.Repositories {
		if item.Repository == identifier {
			writeJSON(writer, http.StatusOK, item)
			return
		}
	}
	problem(writer, http.StatusNotFound, "REPOSITORY_NOT_FOUND", "Repository health was not found.")
}

func (server *Server) evidence(writer http.ResponseWriter, request *http.Request) {
	digest := request.URL.Query().Get("digest")
	evidence, err := server.repository.GetEvidence(request.Context(), digest)
	if err != nil {
		storageProblem(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, evidence)
}

func (server *Server) listOperations(writer http.ResponseWriter, request *http.Request) {
	limit, ok := queryLimit(request, 50)
	if !ok {
		problem(writer, http.StatusBadRequest, "INVALID_LIMIT", "limit must be between 1 and 100.")
		return
	}
	receipts, err := server.repository.ListReceipts(request.Context(), limit)
	if err != nil {
		storageProblem(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"operations": receipts})
}

func (server *Server) getOperation(writer http.ResponseWriter, request *http.Request) {
	receiptID := strings.TrimPrefix(request.URL.Path, "/api/v1/operations/")
	if !receiptIDPattern.MatchString(receiptID) {
		problem(writer, http.StatusBadRequest, "INVALID_RECEIPT_ID", "Receipt identity is invalid.")
		return
	}
	receipt, err := server.repository.GetReceipt(request.Context(), receiptID)
	if err != nil {
		storageProblem(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, receipt)
}

func (server *Server) createOperation(writer http.ResponseWriter, request *http.Request, principal Principal) {
	if principal.Role < auth.RoleOperator {
		problem(writer, http.StatusForbidden, "OPERATOR_ROLE_REQUIRED", "An operator role is required.")
		return
	}
	if !server.validCSRF(request) {
		problem(writer, http.StatusForbidden, "CSRF_VALIDATION_FAILED", "The operation request did not pass same-origin CSRF validation.")
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		problem(writer, http.StatusUnsupportedMediaType, "JSON_REQUIRED", "Content-Type must be application/json.")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 32*1024)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var intent contract.OperationIntent
	if err := decoder.Decode(&intent); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		problem(writer, http.StatusBadRequest, "INVALID_OPERATION_SCHEMA", "The operation body does not match the v1 schema.")
		return
	}
	receipt, err := server.operations.Create(request.Context(), principal.Identity, principal.Role, intent)
	if err != nil {
		switch {
		case errors.Is(err, operations.ErrReplay):
			problem(writer, http.StatusConflict, "OPERATION_REPLAYED", "This request identity has already been used.")
		case errors.Is(err, operations.ErrDenied):
			problem(writer, http.StatusForbidden, "OPERATION_DENIED", "Approval or evidence policy denied this operation.")
		case errors.Is(err, operations.ErrUnready) && receipt.ReceiptID != "":
			writeJSON(writer, http.StatusServiceUnavailable, receipt)
		case errors.Is(err, operations.ErrUnready):
			problem(writer, http.StatusServiceUnavailable, "CONNECTED_DISPATCH_UNAVAILABLE", "Connected dispatch is disabled or unresolved.")
		default:
			problem(writer, http.StatusBadRequest, "INVALID_OPERATION", "The operation request is invalid.")
		}
		return
	}
	writeJSON(writer, http.StatusAccepted, receipt)
}

func (server *Server) validCSRF(request *http.Request) bool {
	if request.Header.Get("Origin") != strings.TrimSuffix(server.config.AllowedOrigin, "/") || request.Header.Get("Sec-Fetch-Site") != "same-origin" {
		return false
	}
	name := "estate-csrf"
	if server.config.SecureCookies {
		name = "__Host-estate-csrf"
	}
	cookie, err := request.Cookie(name)
	header := request.Header.Get("X-Estate-CSRF")
	if err != nil || len(header) < 32 || len(header) > 128 || len(cookie.Value) != len(header) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) == 1
}

func queryLimit(request *http.Request, fallback int) (int, bool) {
	value := request.URL.Query().Get("limit")
	if value == "" {
		return fallback, true
	}
	parsed, err := strconv.Atoi(value)
	return parsed, err == nil && parsed >= 1 && parsed <= 100
}

func methodNotAllowed(writer http.ResponseWriter, allow string) {
	writer.Header().Set("Allow", allow)
	problem(writer, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "The HTTP method is not allowed for this route.")
}

func storageProblem(writer http.ResponseWriter, err error) {
	if errors.Is(err, storage.ErrNotFound) {
		problem(writer, http.StatusNotFound, "OBJECT_NOT_FOUND", "The requested immutable object was not found.")
		return
	}
	problem(writer, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", "Immutable storage is unavailable.")
}

func problem(writer http.ResponseWriter, status int, code, detail string) {
	writer.Header().Set("Content-Type", "application/problem+json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"type": "https://estate-ci.mindclade.dev/problems/" + strings.ToLower(code), "title": http.StatusText(status), "status": status, "code": code, "detail": detail})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func (server *Server) LogRequest(request *http.Request, status int, duration time.Duration) {
	server.config.Logger.Info("request completed", "method", request.Method, "path", request.URL.Path, "status", status, "duration_ms", duration.Milliseconds())
}
