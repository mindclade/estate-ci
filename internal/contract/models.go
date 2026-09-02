package contract

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	HealthSchemaVersion   = "estate.health/v1"
	EvidenceSchemaVersion = "estate.evidence/v1"
	RequestSchemaVersion  = "estate.operation-request/v1"
	ReceiptSchemaVersion  = "estate.operation-receipt/v1"
)

type Operation string

const (
	OperationRefreshHealth Operation = "refresh_estate_health"
	OperationRerunFailed   Operation = "rerun_failed_required_workflow"
	OperationCancelRun     Operation = "cancel_superseded_workflow_run"
)

var (
	shaPattern        = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	repositoryPattern = regexp.MustCompile(`^mindclade/(\.github|[a-z0-9][a-z0-9._-]{0,99})$`)
	requestIDPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	emailPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9._+%-]{0,127}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	keyIDPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)
	noncePattern      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	reasonCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)
)

type RepositoryHealth struct {
	Repository          string `json:"repository"`
	Profile             string `json:"profile"`
	HeadSHA             string `json:"head_sha"`
	LastGreenSHA        string `json:"last_green_sha"`
	RequiredCheckStatus string `json:"required_check_status"`
	QueueSeconds        int64  `json:"queue_seconds"`
	ExecutionSeconds    int64  `json:"execution_seconds"`
	FailureClass        string `json:"failure_class"`
	CacheHitBasisPoints int64  `json:"cache_hit_basis_points"`
	EvidenceDigest      string `json:"evidence_digest"`
	ObservedAt          string `json:"observed_at"`
}

type EstateHealthSnapshot struct {
	SchemaVersion    string             `json:"schema_version"`
	SnapshotID       string             `json:"snapshot_id"`
	ObservedAt       string             `json:"observed_at"`
	ProtectedMainSHA string             `json:"protected_main_sha"`
	Summary          HealthSummary      `json:"summary"`
	Repositories     []RepositoryHealth `json:"repositories"`
	Digest           string             `json:"digest"`
}

type HealthSummary struct {
	Healthy  int64 `json:"healthy"`
	Degraded int64 `json:"degraded"`
	Blocked  int64 `json:"blocked"`
	Unknown  int64 `json:"unknown"`
}

func (snapshot *EstateHealthSnapshot) Seal() error {
	if snapshot.SchemaVersion == "" {
		snapshot.SchemaVersion = HealthSchemaVersion
	}
	sort.Slice(snapshot.Repositories, func(i, j int) bool {
		return snapshot.Repositories[i].Repository < snapshot.Repositories[j].Repository
	})
	if err := snapshot.Validate(); err != nil {
		return err
	}
	material := *snapshot
	material.Digest = ""
	digest, err := Digest(material)
	if err != nil {
		return err
	}
	snapshot.Digest = digest
	return nil
}

func (snapshot EstateHealthSnapshot) Validate() error {
	if snapshot.SchemaVersion != HealthSchemaVersion {
		return errors.New("unsupported health schema_version")
	}
	if !requestIDPattern.MatchString(snapshot.SnapshotID) {
		return errors.New("snapshot_id must be a UUIDv4")
	}
	if !shaPattern.MatchString(snapshot.ProtectedMainSHA) {
		return errors.New("protected_main_sha must be a lowercase commit SHA")
	}
	if _, err := time.Parse(time.RFC3339, snapshot.ObservedAt); err != nil {
		return errors.New("observed_at must be RFC3339")
	}
	if len(snapshot.Repositories) == 0 || len(snapshot.Repositories) > 100 {
		return errors.New("repositories must contain 1 to 100 entries")
	}
	if snapshot.Summary.Healthy < 0 || snapshot.Summary.Degraded < 0 || snapshot.Summary.Blocked < 0 || snapshot.Summary.Unknown < 0 ||
		snapshot.Summary.Healthy+snapshot.Summary.Degraded+snapshot.Summary.Blocked+snapshot.Summary.Unknown != int64(len(snapshot.Repositories)) {
		return errors.New("health summary must account for every repository")
	}
	if snapshot.Digest != "" && !digestPattern.MatchString(snapshot.Digest) {
		return errors.New("snapshot digest is invalid")
	}
	previous := ""
	actualSummary := HealthSummary{}
	for _, repository := range snapshot.Repositories {
		if !repositoryPattern.MatchString(repository.Repository) || repository.Repository <= previous {
			return errors.New("repositories must be unique, valid, and sorted")
		}
		if !shaPattern.MatchString(repository.HeadSHA) || !shaPattern.MatchString(repository.LastGreenSHA) {
			return errors.New("repository health SHAs must be lowercase commit SHAs")
		}
		if !digestPattern.MatchString(repository.EvidenceDigest) {
			return errors.New("repository evidence_digest is invalid")
		}
		if strings.TrimSpace(repository.Profile) != repository.Profile || len(repository.Profile) == 0 || len(repository.Profile) > 64 || strings.ContainsAny(repository.Profile, "\r\n\x00") {
			return errors.New("repository profile is invalid")
		}
		if strings.TrimSpace(repository.FailureClass) != repository.FailureClass || len(repository.FailureClass) == 0 || len(repository.FailureClass) > 64 || strings.ContainsAny(repository.FailureClass, "\r\n\x00") {
			return errors.New("repository failure_class is invalid")
		}
		if _, err := time.Parse(time.RFC3339, repository.ObservedAt); err != nil {
			return errors.New("repository observed_at must be RFC3339")
		}
		switch repository.RequiredCheckStatus {
		case "success":
			actualSummary.Healthy++
		case "failure":
			actualSummary.Degraded++
		case "blocked":
			actualSummary.Blocked++
		case "unknown":
			actualSummary.Unknown++
		default:
			return errors.New("repository required_check_status is invalid")
		}
		if repository.QueueSeconds < 0 || repository.ExecutionSeconds < 0 || repository.CacheHitBasisPoints < 0 || repository.CacheHitBasisPoints > 10000 {
			return errors.New("repository metrics are outside their bounds")
		}
		previous = repository.Repository
	}
	if actualSummary != snapshot.Summary {
		return errors.New("health summary does not match repository statuses")
	}
	return nil
}

func (snapshot EstateHealthSnapshot) VerifyDigest() error {
	if err := snapshot.Validate(); err != nil || snapshot.Digest == "" {
		return errors.New("snapshot is invalid or unsealed")
	}
	want := snapshot.Digest
	snapshot.Digest = ""
	got, err := Digest(snapshot)
	if err != nil || subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		return errors.New("snapshot digest does not bind its canonical content")
	}
	return nil
}

type ApprovalEvidence struct {
	Approvers  []string `json:"approvers"`
	ApprovedAt string   `json:"approved_at"`
	Decision   string   `json:"decision"`
}

type WorkflowEvidence struct {
	SchemaVersion    string           `json:"schema_version"`
	Repository       string           `json:"repository"`
	WorkflowID       int64            `json:"workflow_id"`
	WorkflowRunID    int64            `json:"workflow_run_id"`
	ProtectedMainSHA string           `json:"protected_main_sha"`
	PlanDigest       string           `json:"plan_digest"`
	Conclusion       string           `json:"conclusion"`
	Superseded       bool             `json:"superseded"`
	Approval         ApprovalEvidence `json:"approval"`
	ObservedAt       string           `json:"observed_at"`
	ExpiresAt        string           `json:"expires_at"`
	Digest           string           `json:"digest"`
}

func (evidence *WorkflowEvidence) Seal() error {
	if evidence.SchemaVersion == "" {
		evidence.SchemaVersion = EvidenceSchemaVersion
	}
	for index := range evidence.Approval.Approvers {
		evidence.Approval.Approvers[index] = strings.ToLower(evidence.Approval.Approvers[index])
	}
	sort.Strings(evidence.Approval.Approvers)
	if err := evidence.Validate(time.Time{}); err != nil {
		return err
	}
	material := *evidence
	material.Digest = ""
	digest, err := Digest(material)
	if err != nil {
		return err
	}
	evidence.Digest = digest
	return nil
}

func (evidence WorkflowEvidence) Validate(now time.Time) error {
	if evidence.SchemaVersion != EvidenceSchemaVersion || !repositoryPattern.MatchString(evidence.Repository) {
		return errors.New("evidence identity is invalid")
	}
	if evidence.WorkflowID <= 0 || evidence.WorkflowRunID < 0 {
		return errors.New("workflow identifiers are invalid")
	}
	if !shaPattern.MatchString(evidence.ProtectedMainSHA) || !digestPattern.MatchString(evidence.PlanDigest) {
		return errors.New("evidence bindings are invalid")
	}
	if evidence.Conclusion != "success" || evidence.Approval.Decision != "approved" {
		return errors.New("evidence is not approved and successful")
	}
	approvedAt, err := time.Parse(time.RFC3339, evidence.Approval.ApprovedAt)
	if err != nil {
		return errors.New("approval approved_at must be RFC3339")
	}
	observedAt, err := time.Parse(time.RFC3339, evidence.ObservedAt)
	if err != nil || approvedAt.Before(observedAt.Add(-24*time.Hour)) || approvedAt.After(observedAt.Add(30*time.Second)) {
		return errors.New("evidence timestamps are invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339, evidence.ExpiresAt)
	if err != nil || !expiresAt.After(observedAt) || expiresAt.After(observedAt.Add(24*time.Hour)) ||
		(!now.IsZero() && (observedAt.After(now.Add(30*time.Second)) || !expiresAt.After(now))) {
		return errors.New("evidence is expired or expires_at is invalid")
	}
	if len(evidence.Approval.Approvers) == 0 || len(evidence.Approval.Approvers) > 10 {
		return errors.New("evidence requires a bounded approval set")
	}
	if evidence.Digest != "" && !digestPattern.MatchString(evidence.Digest) {
		return errors.New("evidence digest is invalid")
	}
	previous := ""
	for _, approver := range evidence.Approval.Approvers {
		if !emailPattern.MatchString(approver) || approver <= previous {
			return errors.New("approvers must be valid, unique, and sorted")
		}
		previous = approver
	}
	return nil
}

func (evidence WorkflowEvidence) VerifyDigest(now time.Time) error {
	if err := evidence.Validate(now); err != nil || evidence.Digest == "" {
		return errors.New("evidence is invalid or unsealed")
	}
	want := evidence.Digest
	evidence.Digest = ""
	got, err := Digest(evidence)
	if err != nil || subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		return errors.New("evidence digest does not bind its canonical content")
	}
	return nil
}

type OperationIntent struct {
	SchemaVersion    string    `json:"schema_version"`
	RequestID        string    `json:"request_id"`
	Operation        Operation `json:"operation"`
	Repository       string    `json:"repository"`
	WorkflowID       int64     `json:"workflow_id"`
	WorkflowRunID    int64     `json:"workflow_run_id"`
	ProtectedMainSHA string    `json:"protected_main_sha"`
	PlanDigest       string    `json:"plan_digest"`
	EvidenceDigest   string    `json:"evidence_digest"`
	Reason           string    `json:"reason"`
	ExpiresAt        string    `json:"expires_at"`
}

type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

type OperationRequest struct {
	SchemaVersion    string    `json:"schema_version"`
	RequestID        string    `json:"request_id"`
	Operation        Operation `json:"operation"`
	Repository       string    `json:"repository"`
	WorkflowID       int64     `json:"workflow_id"`
	WorkflowRunID    int64     `json:"workflow_run_id"`
	ProtectedMainSHA string    `json:"protected_main_sha"`
	PlanDigest       string    `json:"plan_digest"`
	EvidenceDigest   string    `json:"evidence_digest"`
	Reason           string    `json:"reason"`
	RequestedBy      string    `json:"requested_by"`
	IssuedAt         string    `json:"issued_at"`
	ExpiresAt        string    `json:"expires_at"`
	Nonce            string    `json:"nonce"`
	Digest           string    `json:"digest"`
	Signature        Signature `json:"signature"`
}

type OperationReceipt struct {
	SchemaVersion     string    `json:"schema_version"`
	ReceiptID         string    `json:"receipt_id"`
	RequestID         string    `json:"request_id"`
	RequestDigest     string    `json:"request_digest"`
	Operation         Operation `json:"operation"`
	Repository        string    `json:"repository"`
	Status            string    `json:"status"`
	ReasonCode        string    `json:"reason_code"`
	ProviderReference string    `json:"provider_reference"`
	RecordedAt        string    `json:"recorded_at"`
	AuditObject       string    `json:"audit_object"`
	Digest            string    `json:"digest"`
	Signature         Signature `json:"signature"`
}

type Signer interface {
	KeyID() string
	Sign(message []byte) ([]byte, error)
}

type Ed25519Signer struct {
	keyID string
	key   ed25519.PrivateKey
}

func NewEd25519Signer(keyID string, key ed25519.PrivateKey) (*Ed25519Signer, error) {
	if !keyIDPattern.MatchString(keyID) || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("signing key configuration is invalid")
	}
	return &Ed25519Signer{keyID: keyID, key: key}, nil
}

func NewEphemeralSigner(keyID string) (*Ed25519Signer, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewEd25519Signer(keyID, key)
}

func LoadEd25519Signer(keyID, path string) (*Ed25519Signer, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16*1024 || !privateKeyMode(info.Mode().Perm()) {
		return nil, errors.New("signing key must be a small 0400, 0440, or 0600 regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read signing key")
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("signing key must be one PKCS#8 PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("parse signing key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing key must use Ed25519")
	}
	return NewEd25519Signer(keyID, key)
}

func privateKeyMode(mode os.FileMode) bool {
	return mode == 0o400 || mode == 0o440 || mode == 0o600
}

func (signer *Ed25519Signer) KeyID() string { return signer.keyID }
func (signer *Ed25519Signer) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(signer.key, message), nil
}

func (signer *Ed25519Signer) PublicKey() ed25519.PublicKey {
	return signer.key.Public().(ed25519.PublicKey)
}

func SealRequest(request *OperationRequest, signer Signer) error {
	if request.SchemaVersion == "" {
		request.SchemaVersion = RequestSchemaVersion
	}
	if err := request.Validate(time.Time{}); err != nil {
		return err
	}
	material := *request
	material.Digest = ""
	material.Signature = Signature{}
	digest, err := Digest(material)
	if err != nil {
		return err
	}
	signed, err := signer.Sign([]byte(digest))
	if err != nil {
		return fmt.Errorf("sign operation request: %w", err)
	}
	request.Digest = digest
	request.Signature = Signature{Algorithm: "Ed25519", KeyID: signer.KeyID(), Value: base64.RawURLEncoding.EncodeToString(signed)}
	return nil
}

func (request OperationRequest) Validate(now time.Time) error {
	if request.SchemaVersion != RequestSchemaVersion || !requestIDPattern.MatchString(request.RequestID) {
		return errors.New("operation request identity is invalid")
	}
	if !AllowedOperation(request.Operation) || !repositoryPattern.MatchString(request.Repository) {
		return errors.New("operation or repository is not allowlisted")
	}
	if request.WorkflowID <= 0 || request.WorkflowRunID < 0 || !shaPattern.MatchString(request.ProtectedMainSHA) {
		return errors.New("workflow binding is invalid")
	}
	if !digestPattern.MatchString(request.PlanDigest) || !digestPattern.MatchString(request.EvidenceDigest) {
		return errors.New("plan or evidence digest is invalid")
	}
	if strings.TrimSpace(request.Reason) != request.Reason || len(request.Reason) < 10 || len(request.Reason) > 500 || strings.ContainsAny(request.Reason, "\r\n\x00") {
		return errors.New("reason must be a single trimmed line of 10 to 500 characters")
	}
	if !emailPattern.MatchString(request.RequestedBy) || !noncePattern.MatchString(request.Nonce) {
		return errors.New("requester or nonce is invalid")
	}
	issuedAt, issuedErr := time.Parse(time.RFC3339, request.IssuedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339, request.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || !expiresAt.After(issuedAt) || expiresAt.After(issuedAt.Add(10*time.Minute)) {
		return errors.New("operation expiry must be after issue time and within 10 minutes")
	}
	if !now.IsZero() && (issuedAt.After(now.Add(30*time.Second)) || !expiresAt.After(now)) {
		return errors.New("operation request is not currently valid")
	}
	if request.Operation == OperationRefreshHealth && request.WorkflowRunID != 0 {
		return errors.New("health refresh must not select a workflow run")
	}
	if request.Operation != OperationRefreshHealth && request.WorkflowRunID <= 0 {
		return errors.New("workflow-run operation requires workflow_run_id")
	}
	return nil
}

func (request OperationRequest) VerifySignature(now time.Time, expectedKeyID string, publicKey ed25519.PublicKey) error {
	if err := request.VerifyDigest(now); err != nil {
		return err
	}
	if err := validateSignature(request.Signature, expectedKeyID); err != nil {
		return err
	}
	material := request
	material.Digest = ""
	material.Signature = Signature{}
	return verifySignature(material, request.Digest, request.Signature, publicKey)
}

func (request OperationRequest) VerifyDigest(now time.Time) error {
	if err := request.Validate(now); err != nil || !digestPattern.MatchString(request.Digest) {
		return errors.New("signed operation request is invalid")
	}
	if err := validateSignature(request.Signature, ""); err != nil {
		return err
	}
	want := request.Digest
	request.Digest = ""
	request.Signature = Signature{}
	got, err := Digest(request)
	if err != nil || subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		return errors.New("operation request digest does not bind its canonical content")
	}
	return nil
}

func SealReceipt(receipt *OperationReceipt, signer Signer) error {
	if receipt.SchemaVersion == "" {
		receipt.SchemaVersion = ReceiptSchemaVersion
	}
	if err := receipt.validateMaterial(); err != nil {
		return err
	}
	material := *receipt
	material.Digest = ""
	material.Signature = Signature{}
	digest, err := Digest(material)
	if err != nil {
		return err
	}
	signed, err := signer.Sign([]byte(digest))
	if err != nil {
		return fmt.Errorf("sign operation receipt: %w", err)
	}
	receipt.Digest = digest
	receipt.Signature = Signature{Algorithm: "Ed25519", KeyID: signer.KeyID(), Value: base64.RawURLEncoding.EncodeToString(signed)}
	return nil
}

func (receipt OperationReceipt) validateMaterial() error {
	if receipt.SchemaVersion != ReceiptSchemaVersion || !requestIDPattern.MatchString(receipt.ReceiptID) || !requestIDPattern.MatchString(receipt.RequestID) || !digestPattern.MatchString(receipt.RequestDigest) {
		return errors.New("operation receipt identity is invalid")
	}
	if !AllowedOperation(receipt.Operation) || !repositoryPattern.MatchString(receipt.Repository) {
		return errors.New("operation receipt binding is invalid")
	}
	if receipt.Status != "accepted" && receipt.Status != "rejected" {
		return errors.New("operation receipt status is invalid")
	}
	if !reasonCodePattern.MatchString(receipt.ReasonCode) {
		return errors.New("operation receipt reason_code is invalid")
	}
	if len(receipt.ProviderReference) > 512 || strings.ContainsAny(receipt.ProviderReference, "\r\n\x00") ||
		receipt.ProviderReference != "" && !strings.HasPrefix(receipt.ProviderReference, "https://") && !strings.HasPrefix(receipt.ProviderReference, "simulation://") {
		return errors.New("operation receipt provider reference is invalid")
	}
	recordedAt, err := time.Parse(time.RFC3339, receipt.RecordedAt)
	if err != nil {
		return errors.New("operation receipt recorded_at is invalid")
	}
	expectedObject := fmt.Sprintf("audit/operations/%s/%s.json", recordedAt.UTC().Format("2006/01/02"), receipt.ReceiptID)
	if receipt.AuditObject != expectedObject {
		return errors.New("operation receipt audit object is invalid")
	}
	return nil
}

func (receipt OperationReceipt) VerifyDigest() error {
	if err := receipt.validateMaterial(); err != nil || !digestPattern.MatchString(receipt.Digest) {
		return errors.New("operation receipt is invalid or unsealed")
	}
	if err := validateSignature(receipt.Signature, ""); err != nil {
		return err
	}
	want := receipt.Digest
	receipt.Digest = ""
	receipt.Signature = Signature{}
	got, err := Digest(receipt)
	if err != nil || subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		return errors.New("operation receipt digest does not bind its canonical content")
	}
	return nil
}

func (receipt OperationReceipt) VerifySignature(expectedKeyID string, publicKey ed25519.PublicKey) error {
	if err := receipt.VerifyDigest(); err != nil {
		return err
	}
	if err := validateSignature(receipt.Signature, expectedKeyID); err != nil {
		return err
	}
	material := receipt
	material.Digest = ""
	material.Signature = Signature{}
	return verifySignature(material, receipt.Digest, receipt.Signature, publicKey)
}

func validateSignature(signature Signature, expectedKeyID string) error {
	value, err := base64.RawURLEncoding.DecodeString(signature.Value)
	if signature.Algorithm != "Ed25519" || !keyIDPattern.MatchString(signature.KeyID) || err != nil || len(value) != ed25519.SignatureSize {
		return errors.New("Ed25519 signature envelope is invalid")
	}
	if expectedKeyID != "" && subtle.ConstantTimeCompare([]byte(signature.KeyID), []byte(expectedKeyID)) != 1 {
		return errors.New("signature key ID is not trusted")
	}
	return nil
}

func verifySignature(material any, digest string, signature Signature, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("Ed25519 public key is invalid")
	}
	got, err := Digest(material)
	if err != nil || subtle.ConstantTimeCompare([]byte(digest), []byte(got)) != 1 {
		return errors.New("signed digest does not bind its canonical content")
	}
	value, _ := base64.RawURLEncoding.DecodeString(signature.Value)
	if !ed25519.Verify(publicKey, []byte(digest), value) {
		return errors.New("Ed25519 signature verification failed")
	}
	return nil
}

func AllowedOperation(operation Operation) bool {
	switch operation {
	case OperationRefreshHealth, OperationRerunFailed, OperationCancelRun:
		return true
	default:
		return false
	}
}

func Timestamp(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format(time.RFC3339)
}

func NewNonce() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", value), nil
}
