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
	ErrPending = errors.New("operation outcome is pending reconciliation")
)

type DispatchOutcome struct {
	Final             bool
	Accepted          bool
	ReasonCode        string
	ProviderReference string
}

type Dispatcher interface {
	Prepare(context.Context, RepositoryTarget, contract.OperationRequest) (string, DispatchOutcome)
	Dispatch(context.Context, RepositoryTarget, contract.OperationRequest, string) DispatchOutcome
	Recover(context.Context, RepositoryTarget, contract.OperationRequest, string) DispatchOutcome
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
	if intent.SchemaVersion != IntentSchemaVersion || !contract.ValidRequestID(intent.RequestID) || !contract.AllowedOperation(intent.Operation) {
		return contract.OperationReceipt{}, ErrInvalid
	}
	target, err := service.catalog.Authorize(intent)
	if err != nil {
		if errors.Is(err, ErrOperationNotCatalogued) || errors.Is(err, ErrOperationDisabled) {
			return contract.OperationReceipt{}, err
		}
		return contract.OperationReceipt{}, fmt.Errorf("%w: %v", ErrUnready, err)
	}
	if existing, err := service.repository.GetRequest(ctx, intent.RequestID); err == nil {
		if existing.VerifySignature(time.Time{}, service.signer.KeyID(), service.signer.PublicKey()) != nil {
			return contract.OperationReceipt{}, errors.New("verify existing operation request")
		}
		if !requestMatchesIntent(existing, intent, identity.Email) {
			return contract.OperationReceipt{}, ErrReplay
		}
		return service.resume(ctx, target, existing)
	} else if !errors.Is(err, storage.ErrNotFound) {
		return contract.OperationReceipt{}, errors.New("read existing operation request")
	}
	now := service.now().UTC().Truncate(time.Second)
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
	if err := service.repository.ReserveRequest(ctx, request.RequestID, bindingDigest, evidence.Approval.ApprovalID, request.Nonce, request.ExpiresAt); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			if existing, getErr := service.repository.GetRequest(ctx, request.RequestID); getErr == nil &&
				existing.VerifySignature(time.Time{}, service.signer.KeyID(), service.signer.PublicKey()) == nil && requestMatchesIntent(existing, intent, identity.Email) {
				return service.resume(ctx, target, existing)
			}
			return contract.OperationReceipt{}, ErrReplay
		}
		return contract.OperationReceipt{}, errors.New("reserve operation replay key")
	}
	if err := service.repository.PutRequest(ctx, request); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			existing, getErr := service.repository.GetRequest(ctx, request.RequestID)
			if getErr == nil && existing.VerifySignature(time.Time{}, service.signer.KeyID(), service.signer.PublicKey()) == nil && requestMatchesIntent(existing, intent, identity.Email) {
				return service.resume(ctx, target, existing)
			}
			return contract.OperationReceipt{}, ErrReplay
		}
		return contract.OperationReceipt{}, errors.New("persist signed operation request")
	}
	return service.prepare(ctx, target, request)
}

func (service *Service) prepare(ctx context.Context, target RepositoryTarget, request contract.OperationRequest) (contract.OperationReceipt, error) {
	recoveryToken, preparedOutcome := service.dispatcher.Prepare(ctx, target, request)
	receiptID, err := service.uuid()
	if err != nil {
		return contract.OperationReceipt{}, errors.New("generate receipt identity")
	}
	dispatch := contract.OperationDispatch{
		RequestID: request.RequestID, RequestDigest: request.Digest, ReceiptID: receiptID,
		RecoveryToken: recoveryToken, PreparedAt: contract.Timestamp(service.now()),
	}
	if err := contract.SealDispatch(&dispatch, service.signer); err != nil {
		return contract.OperationReceipt{}, errors.New("seal operation dispatch")
	}
	if err := service.repository.PutDispatch(ctx, dispatch); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			return service.resume(ctx, target, request)
		}
		return contract.OperationReceipt{}, errors.New("persist operation dispatch before provider call")
	}
	if preparedOutcome.Final {
		return service.complete(ctx, request, dispatch, preparedOutcome)
	}
	outcome := service.dispatcher.Dispatch(ctx, target, request, dispatch.RecoveryToken)
	return service.complete(ctx, request, dispatch, outcome)
}

func (service *Service) resume(ctx context.Context, target RepositoryTarget, request contract.OperationRequest) (contract.OperationReceipt, error) {
	dispatch, err := service.repository.GetDispatch(ctx, request.RequestID)
	if errors.Is(err, storage.ErrNotFound) {
		return service.prepare(ctx, target, request)
	}
	if err != nil || dispatch.RequestDigest != request.Digest || dispatch.VerifySignature(service.signer.KeyID(), service.signer.PublicKey()) != nil {
		return contract.OperationReceipt{}, errors.New("read durable operation dispatch")
	}
	result, err := service.repository.GetDispatchResult(ctx, request.RequestID)
	if err == nil {
		if result.VerifySignature(service.signer.KeyID(), service.signer.PublicKey()) != nil {
			return contract.OperationReceipt{}, errors.New("verify durable operation dispatch result")
		}
		return service.finalize(ctx, request, dispatch, result)
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return contract.OperationReceipt{}, errors.New("read durable operation dispatch result")
	}
	outcome := service.dispatcher.Recover(ctx, target, request, dispatch.RecoveryToken)
	return service.complete(ctx, request, dispatch, outcome)
}

func (service *Service) complete(ctx context.Context, request contract.OperationRequest, dispatch contract.OperationDispatch, outcome DispatchOutcome) (contract.OperationReceipt, error) {
	if !outcome.Final {
		return contract.OperationReceipt{}, ErrPending
	}
	status := "rejected"
	if outcome.Accepted {
		status = "accepted"
	}
	result := contract.OperationDispatchResult{
		RequestID: request.RequestID, RequestDigest: request.Digest, ReceiptID: dispatch.ReceiptID,
		Status: status, ReasonCode: outcome.ReasonCode, ProviderReference: outcome.ProviderReference,
		RecordedAt: contract.Timestamp(service.now()),
	}
	if err := contract.SealDispatchResult(&result, service.signer); err != nil {
		return contract.OperationReceipt{}, fmt.Errorf("%w: seal operation dispatch result", ErrPending)
	}
	if err := service.repository.PutDispatchResult(ctx, result); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			stored, getErr := service.repository.GetDispatchResult(ctx, request.RequestID)
			if getErr != nil || stored.VerifySignature(service.signer.KeyID(), service.signer.PublicKey()) != nil {
				return contract.OperationReceipt{}, fmt.Errorf("%w: read conflicting operation dispatch result", ErrPending)
			}
			result = stored
		} else {
			return contract.OperationReceipt{}, fmt.Errorf("%w: persist operation dispatch result", ErrPending)
		}
	}
	return service.finalize(ctx, request, dispatch, result)
}

func (service *Service) finalize(ctx context.Context, request contract.OperationRequest, dispatch contract.OperationDispatch, result contract.OperationDispatchResult) (contract.OperationReceipt, error) {
	if result.RequestID != request.RequestID || result.RequestDigest != request.Digest || result.ReceiptID != dispatch.ReceiptID {
		return contract.OperationReceipt{}, errors.New("durable dispatch result does not match its request")
	}
	receipt := contract.OperationReceipt{
		SchemaVersion: contract.ReceiptSchemaVersion, ReceiptID: result.ReceiptID, RequestID: request.RequestID,
		RequestDigest: request.Digest, Operation: request.Operation, Repository: request.Repository,
		Status: result.Status, ReasonCode: result.ReasonCode, ProviderReference: result.ProviderReference,
		RecordedAt: result.RecordedAt,
	}
	receipt.AuditObject = storage.ReceiptObject(receipt)
	if err := contract.SealReceipt(&receipt, service.signer); err != nil {
		return contract.OperationReceipt{}, fmt.Errorf("%w: seal operation receipt", ErrPending)
	}
	if err := service.repository.PutReceipt(ctx, receipt); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			stored, getErr := service.repository.GetReceiptByObject(ctx, receipt.AuditObject)
			if getErr != nil || stored.VerifySignature(service.signer.KeyID(), service.signer.PublicKey()) != nil ||
				stored.RequestDigest != request.Digest || stored.ReceiptID != receipt.ReceiptID {
				return contract.OperationReceipt{}, fmt.Errorf("%w: read conflicting operation receipt", ErrPending)
			}
			receipt = stored
		} else {
			return contract.OperationReceipt{}, fmt.Errorf("%w: persist operation receipt", ErrPending)
		}
	}
	if receipt.Status != "accepted" {
		return receipt, ErrUnready
	}
	return receipt, nil
}

func requestMatchesIntent(request contract.OperationRequest, intent contract.OperationIntent, requester string) bool {
	return request.RequestID == intent.RequestID && request.Operation == intent.Operation && request.Repository == intent.Repository &&
		request.WorkflowID == intent.WorkflowID && request.WorkflowRunID == intent.WorkflowRunID && request.ProtectedMainSHA == intent.ProtectedMainSHA &&
		request.PlanDigest == intent.PlanDigest && request.EvidenceDigest == intent.EvidenceDigest && request.Reason == intent.Reason &&
		strings.EqualFold(request.RequestedBy, requester) && request.ExpiresAt == intent.ExpiresAt
}

func operationBindingDigest(request contract.OperationRequest) (string, error) {
	return contract.Digest(map[string]any{
		"operation": request.Operation, "repository": request.Repository, "workflow_id": request.WorkflowID,
		"workflow_run_id": request.WorkflowRunID, "protected_main_sha": request.ProtectedMainSHA,
		"plan_digest": request.PlanDigest, "evidence_digest": request.EvidenceDigest,
		"requested_by": request.RequestedBy, "reason": request.Reason,
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
	if evidence.Approval.Operation != intent.Operation || !strings.EqualFold(evidence.Approval.RequestedBy, requester) ||
		subtle.ConstantTimeCompare([]byte(evidence.Approval.Reason), []byte(intent.Reason)) != 1 {
		return errors.New("approval does not match the exact operation, requester, and reason")
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

func (FailClosedDispatcher) Prepare(context.Context, RepositoryTarget, contract.OperationRequest) (string, DispatchOutcome) {
	return "ZmFpbC1jbG9zZWQtdjE", DispatchOutcome{Final: true, ReasonCode: "CONNECTED_DISPATCH_DISABLED"}
}
func (FailClosedDispatcher) Dispatch(context.Context, RepositoryTarget, contract.OperationRequest, string) DispatchOutcome {
	return DispatchOutcome{Final: true, ReasonCode: "CONNECTED_DISPATCH_DISABLED"}
}
func (FailClosedDispatcher) Recover(context.Context, RepositoryTarget, contract.OperationRequest, string) DispatchOutcome {
	return DispatchOutcome{Final: true, ReasonCode: "CONNECTED_DISPATCH_DISABLED"}
}

type SimulationDispatcher struct{}

func (SimulationDispatcher) Prepare(context.Context, RepositoryTarget, contract.OperationRequest) (string, DispatchOutcome) {
	return "c2ltdWxhdGlvbi12MQ", DispatchOutcome{}
}
func (SimulationDispatcher) Dispatch(_ context.Context, _ RepositoryTarget, request contract.OperationRequest, _ string) DispatchOutcome {
	return DispatchOutcome{Final: true, Accepted: true, ReasonCode: "LOCAL_SIMULATION_ACCEPTED", ProviderReference: "simulation://operations/" + request.RequestID}
}
func (SimulationDispatcher) Recover(_ context.Context, _ RepositoryTarget, request contract.OperationRequest, _ string) DispatchOutcome {
	return DispatchOutcome{Final: true, Accepted: true, ReasonCode: "LOCAL_SIMULATION_ACCEPTED", ProviderReference: "simulation://operations/" + request.RequestID}
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
