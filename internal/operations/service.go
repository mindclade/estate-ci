package operations

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mindclade/estate-ci/internal/auth"
	"github.com/mindclade/estate-ci/internal/contract"
	"github.com/mindclade/estate-ci/internal/storage"
)

const IntentSchemaVersion = "estate.operation-intent/v1"

var (
	ErrDenied  = errors.New("operation is not authorized")
	ErrInvalid = errors.New("operation request is invalid")
	ErrReplay  = errors.New("operation request was already used")
	ErrUnready = errors.New("connected operation dispatch is unavailable")
)

type DispatchOutcome struct {
	Accepted          bool
	ReasonCode        string
	ProviderReference string
}

type Dispatcher interface {
	Dispatch(context.Context, RepositoryTarget, contract.OperationRequest) DispatchOutcome
}

type Service struct {
	catalog    *Catalog
	repository storage.Repository
	roles      auth.RoleResolver
	dispatcher Dispatcher
	signer     contract.Signer
	now        func() time.Time
	uuid       func() (string, error)
}

func NewService(catalog *Catalog, repository storage.Repository, roles auth.RoleResolver, dispatcher Dispatcher, signer contract.Signer) (*Service, error) {
	if catalog == nil || repository == nil || roles == nil || dispatcher == nil || signer == nil {
		return nil, errors.New("operation service dependencies are required")
	}
	return &Service{catalog: catalog, repository: repository, roles: roles, dispatcher: dispatcher, signer: signer, now: time.Now, uuid: newUUIDv4}, nil
}

func (service *Service) Create(ctx context.Context, identity auth.Identity, callerRole auth.Role, intent contract.OperationIntent) (contract.OperationReceipt, error) {
	if callerRole < auth.RoleOperator || callerRole > auth.RoleAdmin {
		return contract.OperationReceipt{}, ErrDenied
	}
	now := service.now().UTC().Truncate(time.Second)
	if intent.SchemaVersion != IntentSchemaVersion || !contract.AllowedOperation(intent.Operation) {
		return contract.OperationReceipt{}, ErrInvalid
	}
	target, err := service.catalog.Authorize(intent)
	if err != nil {
		return contract.OperationReceipt{}, fmt.Errorf("%w: %v", ErrUnready, err)
	}
	expiresAt, err := time.Parse(time.RFC3339, intent.ExpiresAt)
	if err != nil || !expiresAt.After(now) || expiresAt.After(now.Add(10*time.Minute)) {
		return contract.OperationReceipt{}, fmt.Errorf("%w: expiry is outside the 10-minute window", ErrInvalid)
	}
	evidence, err := service.repository.GetEvidence(ctx, intent.EvidenceDigest)
	if err != nil {
		return contract.OperationReceipt{}, fmt.Errorf("%w: evidence is unavailable", ErrInvalid)
	}
	if err := validateEvidence(now, identity.Email, intent, evidence, service.roles, ctx); err != nil {
		return contract.OperationReceipt{}, fmt.Errorf("%w: %v", ErrDenied, err)
	}
	nonce, err := contract.NewNonce()
	if err != nil {
		return contract.OperationReceipt{}, errors.New("generate request nonce")
	}
	request := contract.OperationRequest{
		SchemaVersion: contract.RequestSchemaVersion,
		RequestID:     intent.RequestID, Operation: intent.Operation, Repository: intent.Repository,
		WorkflowID: intent.WorkflowID, WorkflowRunID: intent.WorkflowRunID,
		ProtectedMainSHA: intent.ProtectedMainSHA, PlanDigest: intent.PlanDigest, EvidenceDigest: intent.EvidenceDigest,
		Reason: intent.Reason, RequestedBy: strings.ToLower(identity.Email), IssuedAt: contract.Timestamp(now),
		ExpiresAt: contract.Timestamp(expiresAt), Nonce: nonce,
	}
	if err := contract.SealRequest(&request, service.signer); err != nil {
		return contract.OperationReceipt{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	bindingDigest, err := operationBindingDigest(request)
	if err != nil {
		return contract.OperationReceipt{}, errors.New("derive operation idempotency binding")
	}
	if err := service.repository.ReserveRequest(ctx, request.RequestID, bindingDigest, request.Nonce, request.ExpiresAt); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			return contract.OperationReceipt{}, ErrReplay
		}
		return contract.OperationReceipt{}, errors.New("reserve operation replay key")
	}
	if err := service.repository.PutRequest(ctx, request); err != nil {
		return contract.OperationReceipt{}, errors.New("persist signed operation request")
	}
	outcome := service.dispatcher.Dispatch(ctx, target, request)
	receiptID, err := service.uuid()
	if err != nil {
		return contract.OperationReceipt{}, errors.New("generate receipt identity")
	}
	status := "rejected"
	if outcome.Accepted {
		status = "accepted"
	}
	receipt := contract.OperationReceipt{
		SchemaVersion: contract.ReceiptSchemaVersion, ReceiptID: receiptID, RequestID: request.RequestID,
		RequestDigest: request.Digest, Operation: request.Operation, Repository: request.Repository,
		Status: status, ReasonCode: outcome.ReasonCode, ProviderReference: outcome.ProviderReference,
		RecordedAt: contract.Timestamp(now),
	}
	receipt.AuditObject = storage.ReceiptObject(receipt)
	if err := contract.SealReceipt(&receipt, service.signer); err != nil {
		return contract.OperationReceipt{}, errors.New("seal operation receipt")
	}
	if err := service.repository.PutReceipt(ctx, receipt); err != nil {
		return contract.OperationReceipt{}, errors.New("persist operation receipt")
	}
	if !outcome.Accepted {
		return receipt, ErrUnready
	}
	return receipt, nil
}

func operationBindingDigest(request contract.OperationRequest) (string, error) {
	return contract.Digest(map[string]any{
		"operation": request.Operation, "repository": request.Repository, "workflow_id": request.WorkflowID,
		"workflow_run_id": request.WorkflowRunID, "protected_main_sha": request.ProtectedMainSHA,
		"plan_digest": request.PlanDigest, "evidence_digest": request.EvidenceDigest,
	})
}

func validateEvidence(now time.Time, requester string, intent contract.OperationIntent, evidence contract.WorkflowEvidence, roles auth.RoleResolver, ctx context.Context) error {
	if err := evidence.VerifyDigest(now); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(evidence.Digest), []byte(intent.EvidenceDigest)) != 1 || evidence.Repository != intent.Repository || evidence.WorkflowID != intent.WorkflowID ||
		evidence.ProtectedMainSHA != intent.ProtectedMainSHA || evidence.PlanDigest != intent.PlanDigest {
		return errors.New("evidence does not match the requested workflow, main SHA, and plan")
	}
	if intent.Operation == contract.OperationRefreshHealth {
		if intent.WorkflowRunID != 0 {
			return errors.New("health refresh cannot select a caller-provided run")
		}
	} else if evidence.WorkflowRunID != intent.WorkflowRunID {
		return errors.New("evidence does not match the selected workflow run")
	}
	if intent.Operation == contract.OperationCancelRun && !evidence.Superseded {
		return errors.New("cancellation evidence does not mark the run superseded")
	}
	approved := false
	for _, approver := range evidence.Approval.Approvers {
		if strings.EqualFold(approver, requester) {
			continue
		}
		role, err := roles.RoleFor(ctx, approver)
		if err != nil {
			return errors.New("approver role resolution failed")
		}
		if role >= auth.RoleApprover {
			approved = true
			break
		}
	}
	if !approved {
		return errors.New("a distinct Workspace approver is required")
	}
	return nil
}

type FailClosedDispatcher struct{}

func (FailClosedDispatcher) Dispatch(context.Context, RepositoryTarget, contract.OperationRequest) DispatchOutcome {
	return DispatchOutcome{Accepted: false, ReasonCode: "CONNECTED_DISPATCH_DISABLED"}
}

type SimulationDispatcher struct{}

func (SimulationDispatcher) Dispatch(_ context.Context, _ RepositoryTarget, request contract.OperationRequest) DispatchOutcome {
	return DispatchOutcome{Accepted: true, ReasonCode: "LOCAL_SIMULATION_ACCEPTED", ProviderReference: "simulation://operations/" + request.RequestID}
}

func newUUIDv4() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}
