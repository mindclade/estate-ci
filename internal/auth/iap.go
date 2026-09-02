package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	IAPIssuer      = "https://cloud.google.com/iap"
	DefaultJWKSURL = "https://www.gstatic.com/iap/verify/public_key-jwk"
)

type Identity struct {
	Subject   string
	Email     string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type TokenValidator interface {
	Validate(context.Context, string) (Identity, error)
}

type JWKSValidator struct {
	audience string
	issuer   string
	jwksURL  string
	client   *http.Client
	now      func() time.Time

	mu      sync.Mutex
	keys    map[string]*ecdsa.PublicKey
	expires time.Time
}

type ValidatorOption func(*JWKSValidator)

func WithJWKSURL(value string) ValidatorOption { return func(v *JWKSValidator) { v.jwksURL = value } }
func WithHTTPClient(value *http.Client) ValidatorOption {
	return func(v *JWKSValidator) { v.client = value }
}
func WithClock(value func() time.Time) ValidatorOption {
	return func(v *JWKSValidator) { v.now = value }
}

func NewJWKSValidator(audience string, options ...ValidatorOption) (*JWKSValidator, error) {
	if strings.TrimSpace(audience) == "" || len(audience) > 512 {
		return nil, errors.New("IAP audience is required")
	}
	validator := &JWKSValidator{
		audience: audience,
		issuer:   IAPIssuer,
		jwksURL:  DefaultJWKSURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("JWKS redirects are forbidden")
			},
		},
		now: time.Now,
	}
	for _, option := range options {
		option(validator)
	}
	parsed, err := url.Parse(validator.jwksURL)
	if err != nil || parsed.Scheme != "https" && !strings.HasPrefix(validator.jwksURL, "http://127.0.0.1:") {
		return nil, errors.New("JWKS URL must use HTTPS")
	}
	return validator, nil
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type jwtClaims struct {
	Audience  string      `json:"aud"`
	Email     string      `json:"email"`
	ExpiresAt json.Number `json:"exp"`
	IssuedAt  json.Number `json:"iat"`
	Issuer    string      `json:"iss"`
	Subject   string      `json:"sub"`
}

func (validator *JWKSValidator) Validate(ctx context.Context, token string) (Identity, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(token) > 16*1024 {
		return Identity{}, errors.New("IAP assertion has an invalid compact form")
	}
	var header jwtHeader
	if err := decodeSegment(parts[0], &header, true); err != nil {
		return Identity{}, errors.New("IAP assertion header is invalid")
	}
	if header.Algorithm != "ES256" || header.Type != "JWT" || header.KeyID == "" || len(header.KeyID) > 256 {
		return Identity{}, errors.New("IAP assertion algorithm or key is invalid")
	}
	key, err := validator.key(ctx, header.KeyID)
	if err != nil {
		return Identity{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		return Identity{}, errors.New("IAP assertion signature is invalid")
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, hash[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return Identity{}, errors.New("IAP assertion signature verification failed")
	}
	var claims jwtClaims
	if err := decodeSegment(parts[1], &claims, false); err != nil {
		return Identity{}, errors.New("IAP assertion claims are invalid")
	}
	issuedUnix, err := strconv.ParseInt(claims.IssuedAt.String(), 10, 64)
	if err != nil {
		return Identity{}, errors.New("IAP assertion iat is invalid")
	}
	expiresUnix, err := strconv.ParseInt(claims.ExpiresAt.String(), 10, 64)
	if err != nil {
		return Identity{}, errors.New("IAP assertion exp is invalid")
	}
	now := validator.now().UTC()
	issuedAt := time.Unix(issuedUnix, 0).UTC()
	expiresAt := time.Unix(expiresUnix, 0).UTC()
	if claims.Issuer != validator.issuer || claims.Audience != validator.audience {
		return Identity{}, errors.New("IAP assertion issuer or audience is invalid")
	}
	if issuedAt.After(now.Add(30*time.Second)) || !expiresAt.After(now.Add(-30*time.Second)) || expiresAt.Sub(issuedAt) > 2*time.Hour {
		return Identity{}, errors.New("IAP assertion is outside its validity window")
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" || claims.Subject == "" || len(email) > 320 || strings.ContainsAny(email, "\r\n\x00") {
		return Identity{}, errors.New("IAP assertion identity is invalid")
	}
	return Identity{Subject: claims.Subject, Email: email, IssuedAt: issuedAt, ExpiresAt: expiresAt}, nil
}

func decodeSegment(segment string, destination any, strict bool) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil || len(raw) > 8*1024 {
		return errors.New("JWT segment is invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("JWT segment has trailing data")
	}
	return nil
}

type jwksDocument struct {
	Keys []struct {
		Algorithm string `json:"alg"`
		Curve     string `json:"crv"`
		KeyID     string `json:"kid"`
		KeyType   string `json:"kty"`
		Use       string `json:"use"`
		X         string `json:"x"`
		Y         string `json:"y"`
	} `json:"keys"`
}

func (validator *JWKSValidator) key(ctx context.Context, keyID string) (*ecdsa.PublicKey, error) {
	validator.mu.Lock()
	defer validator.mu.Unlock()
	now := validator.now()
	if key := validator.keys[keyID]; key != nil && now.Before(validator.expires) {
		return key, nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, validator.jwksURL, nil)
	if err != nil {
		return nil, errors.New("create JWKS request")
	}
	response, err := validator.client.Do(request)
	if err != nil {
		return nil, errors.New("fetch IAP verification keys")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch IAP verification keys: HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1024*1024))
	var document jwksDocument
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF || len(document.Keys) == 0 || len(document.Keys) > 20 {
		return nil, errors.New("IAP verification key set is invalid")
	}
	keys := make(map[string]*ecdsa.PublicKey, len(document.Keys))
	for _, encoded := range document.Keys {
		if encoded.Algorithm != "ES256" || encoded.Curve != "P-256" || encoded.KeyType != "EC" || encoded.Use != "sig" || encoded.KeyID == "" {
			return nil, errors.New("IAP verification key has an invalid contract")
		}
		x, xErr := base64.RawURLEncoding.DecodeString(encoded.X)
		y, yErr := base64.RawURLEncoding.DecodeString(encoded.Y)
		if xErr != nil || yErr != nil || len(x) != 32 || len(y) != 32 {
			return nil, errors.New("IAP verification key coordinates are invalid")
		}
		key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !key.Curve.IsOnCurve(key.X, key.Y) {
			return nil, errors.New("IAP verification key is not on P-256")
		}
		if keys[encoded.KeyID] != nil {
			return nil, errors.New("IAP verification key ID is duplicated")
		}
		keys[encoded.KeyID] = key
	}
	validator.keys = keys
	validator.expires = now.Add(cacheLifetime(response.Header.Get("Cache-Control")))
	key := validator.keys[keyID]
	if key == nil {
		return nil, errors.New("IAP assertion references an unknown verification key")
	}
	return key, nil
}

func cacheLifetime(cacheControl string) time.Duration {
	for _, directive := range strings.Split(cacheControl, ",") {
		name, value, found := strings.Cut(strings.TrimSpace(directive), "=")
		if found && strings.EqualFold(name, "max-age") {
			seconds, err := strconv.ParseInt(value, 10, 64)
			if err == nil && seconds >= 60 && seconds <= 24*60*60 {
				return time.Duration(seconds) * time.Second
			}
		}
	}
	return 10 * time.Minute
}
