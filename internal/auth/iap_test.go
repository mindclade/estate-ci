package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIAPValidatorRejectsForgedAndWrongAudienceAssertions(t *testing.T) {
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	trusted, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	forger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwks := jwksForKey("trusted", &trusted.PublicKey)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Cache-Control", "public, max-age=600")
		_ = json.NewEncoder(writer).Encode(jwks)
	}))
	defer server.Close()
	validator, err := NewJWKSValidator("/projects/123/global/backendServices/456", WithJWKSURL(server.URL), WithHTTPClient(server.Client()), WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"aud": "/projects/123/global/backendServices/456", "email": "Operator@mindclade.example",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "iss": IAPIssuer, "sub": "accounts.google.com:123",
	}
	valid := signJWT(t, trusted, "trusted", claims)
	identity, err := validator.Validate(context.Background(), valid)
	if err != nil || identity.Email != "operator@mindclade.example" {
		t.Fatalf("valid assertion rejected: identity=%#v err=%v", identity, err)
	}
	forged := signJWT(t, forger, "trusted", claims)
	if _, err := validator.Validate(context.Background(), forged); err == nil {
		t.Fatal("forged assertion was accepted")
	}
	claims["aud"] = "/projects/other/global/backendServices/456"
	wrongAudience := signJWT(t, trusted, "trusted", claims)
	if _, err := validator.Validate(context.Background(), wrongAudience); err == nil {
		t.Fatal("wrong-audience assertion was accepted")
	}
}

func jwksForKey(keyID string, key *ecdsa.PublicKey) map[string]any {
	coordinate := func(value *big.Int) string {
		return base64.RawURLEncoding.EncodeToString(value.FillBytes(make([]byte, 32)))
	}
	return map[string]any{"keys": []any{map[string]any{
		"alg": "ES256", "crv": "P-256", "kid": keyID, "kty": "EC", "use": "sig",
		"x": coordinate(key.X), "y": coordinate(key.Y),
	}}}
}

func signJWT(t *testing.T, key *ecdsa.PrivateKey, keyID string, claims map[string]any) string {
	t.Helper()
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := encode(map[string]any{"alg": "ES256", "kid": keyID, "typ": "JWT"})
	payload := encode(claims)
	digest := sha256.Sum256([]byte(header + "." + payload))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(signature)
}
