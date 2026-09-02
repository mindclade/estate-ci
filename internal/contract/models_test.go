package contract

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testSHA    = "0123456789abcdef0123456789abcdef01234567"
	testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestCanonicalJSONAndDigestAreStable(t *testing.T) {
	left, err := CanonicalJSON(map[string]any{"z": int64(2), "a": []string{"x", "y"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(left), `{"a":["x","y"],"z":2}`; got != want {
		t.Fatalf("canonical JSON = %s, want %s", got, want)
	}
	right, _ := CanonicalJSON(map[string]any{"a": []string{"x", "y"}, "z": int64(2)})
	if string(left) != string(right) {
		t.Fatal("map insertion order changed canonical bytes")
	}
	if _, err := CanonicalJSON(map[string]any{"float": 1.2}); err == nil {
		t.Fatal("float was accepted")
	}
}

func TestSnapshotSealSortsAndBindsEveryField(t *testing.T) {
	snapshot := EstateHealthSnapshot{
		SnapshotID:       "11111111-1111-4111-8111-111111111111",
		ObservedAt:       "2026-09-02T10:00:00Z",
		ProtectedMainSHA: testSHA,
		Summary:          HealthSummary{Healthy: 2},
		Repositories: []RepositoryHealth{
			{Repository: "mindclade/zeta", Profile: "nix-standard", HeadSHA: testSHA, LastGreenSHA: testSHA, RequiredCheckStatus: "success", FailureClass: "none", EvidenceDigest: testDigest, ObservedAt: "2026-09-02T10:00:00Z"},
			{Repository: "mindclade/alpha", Profile: "nix-standard", HeadSHA: testSHA, LastGreenSHA: testSHA, RequiredCheckStatus: "success", FailureClass: "none", EvidenceDigest: testDigest, ObservedAt: "2026-09-02T10:00:00Z"},
		},
	}
	if err := snapshot.Seal(); err != nil {
		t.Fatal(err)
	}
	if snapshot.Repositories[0].Repository != "mindclade/alpha" || !strings.HasPrefix(snapshot.Digest, "sha256:") {
		t.Fatalf("snapshot was not canonicalized: %#v", snapshot)
	}
	original := snapshot.Digest
	snapshot.Repositories[0].QueueSeconds++
	snapshot.Digest = ""
	if err := snapshot.Seal(); err != nil {
		t.Fatal(err)
	}
	if snapshot.Digest == original {
		t.Fatal("digest did not bind repository metrics")
	}
}

func TestOperationRequestIsSignedAndExpires(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewEd25519Signer("test-key-v1", private)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	request := OperationRequest{
		RequestID: "11111111-1111-4111-8111-111111111111", Operation: OperationRerunFailed,
		Repository: "mindclade/bootstrap", WorkflowID: 12, WorkflowRunID: 34,
		ProtectedMainSHA: testSHA, PlanDigest: testDigest, EvidenceDigest: testDigest,
		Reason: "Retry the failed required workflow after runner recovery", RequestedBy: "operator@mindclade.example",
		IssuedAt: Timestamp(issued), ExpiresAt: Timestamp(issued.Add(5 * time.Minute)), Nonce: strings.Repeat("a", 32),
	}
	if err := SealRequest(&request, signer); err != nil {
		t.Fatal(err)
	}
	if err := request.VerifySignature(issued.Add(time.Minute), "test-key-v1", public); err != nil {
		t.Fatalf("verify signed request: %v", err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(request.Signature.Value)
	if err != nil || !ed25519.Verify(public, []byte(request.Digest), signature) {
		t.Fatal("request signature did not verify")
	}
	if err := request.Validate(issued.Add(11 * time.Minute)); err == nil {
		t.Fatal("expired request was accepted")
	}
}

func TestLoadSignerFromProjectedSecret(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(nil)
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	version := filepath.Join(root, "..2026_09_02")
	if err := os.Mkdir(version, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(version, "private-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(version), filepath.Join(root, "..data")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "private-key.pem")
	if err := os.Symlink(filepath.Join("..data", "private-key.pem"), path); err != nil {
		t.Fatal(err)
	}
	signer, err := LoadEd25519Signer("projected-key-v1", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign([]byte("message")); err != nil {
		t.Fatal(err)
	}
}

func TestOperationReceiptSignatureBindsAuditRecord(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := NewEd25519Signer("test-key-v1", private)
	receipt := OperationReceipt{
		ReceiptID: "22222222-2222-4222-8222-222222222222", RequestID: "11111111-1111-4111-8111-111111111111",
		RequestDigest: testDigest, Operation: OperationRerunFailed, Repository: "mindclade/bootstrap",
		Status: "accepted", ReasonCode: "GITHUB_OPERATION_ACCEPTED", ProviderReference: "https://github.example/run/84",
		RecordedAt: "2026-09-02T10:00:00Z", AuditObject: "audit/operations/2026/09/02/22222222-2222-4222-8222-222222222222.json",
	}
	if err := SealReceipt(&receipt, signer); err != nil {
		t.Fatal(err)
	}
	if err := receipt.VerifySignature("test-key-v1", public); err != nil {
		t.Fatalf("verify signed receipt: %v", err)
	}
	receipt.ReasonCode = "TAMPERED"
	if err := receipt.VerifySignature("test-key-v1", public); err == nil {
		t.Fatal("tampered receipt signature was accepted")
	}
}

func TestDispatchOutboxBindsRecoveryAndFinalResult(t *testing.T) {
	signer, _ := NewEphemeralSigner("test-key-v1")
	dispatch := OperationDispatch{
		RequestID: "11111111-1111-4111-8111-111111111111", RequestDigest: testDigest,
		ReceiptID: "22222222-2222-4222-8222-222222222222", RecoveryToken: "cmVjb3ZlcnktdjE",
		PreparedAt: "2026-09-02T10:00:00Z",
	}
	if err := SealDispatch(&dispatch, signer); err != nil || dispatch.VerifySignature("test-key-v1", signer.PublicKey()) != nil {
		t.Fatalf("dispatch=%#v err=%v", dispatch, err)
	}
	dispatch.RecoveryToken = "dGFtcGVyZWQ"
	if err := dispatch.VerifyDigest(); err == nil {
		t.Fatal("tampered recovery state was accepted")
	}
	result := OperationDispatchResult{
		RequestID: "11111111-1111-4111-8111-111111111111", RequestDigest: testDigest,
		ReceiptID: "22222222-2222-4222-8222-222222222222", Status: "accepted",
		ReasonCode: "GITHUB_OPERATION_RECOVERED", ProviderReference: "https://github.example/run/84",
		RecordedAt: "2026-09-02T10:01:00Z",
	}
	if err := SealDispatchResult(&result, signer); err != nil || result.VerifySignature("test-key-v1", signer.PublicKey()) != nil {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	result.Status = "rejected"
	if err := result.VerifyDigest(); err == nil {
		t.Fatal("tampered dispatch result was accepted")
	}
}

func TestOperationAllowlistRejectsGenericDispatchAndInputEscape(t *testing.T) {
	request := OperationRequest{Operation: Operation("workflow_dispatch")}
	if err := request.Validate(time.Time{}); err == nil {
		t.Fatal("generic dispatch was accepted")
	}
	request = OperationRequest{
		SchemaVersion: RequestSchemaVersion, RequestID: "11111111-1111-4111-8111-111111111111",
		Operation: OperationRerunFailed, Repository: "mindclade/bootstrap/../../other", WorkflowID: 1, WorkflowRunID: 2,
		ProtectedMainSHA: testSHA, PlanDigest: testDigest, EvidenceDigest: testDigest,
		Reason: "This reason would otherwise be long enough", RequestedBy: "operator@mindclade.example",
		IssuedAt: "2026-09-02T10:00:00Z", ExpiresAt: "2026-09-02T10:05:00Z", Nonce: strings.Repeat("a", 32),
	}
	if err := request.Validate(time.Time{}); err == nil {
		t.Fatal("repository path escape was accepted")
	}
}
