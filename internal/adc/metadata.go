package adc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const metadataTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

type MetadataTokenSource struct {
	endpoint string
	scopes   []string
	client   *http.Client
	now      func() time.Time
	mu       sync.Mutex
	token    string
	expires  time.Time
}

func NewMetadataClient(scopes ...string) (*http.Client, error) {
	source, err := newMetadataTokenSource(metadataTokenURL, scopes, &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("metadata redirects are forbidden") },
	})
	if err != nil {
		return nil, err
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: &authorizationTransport{base: http.DefaultTransport, tokens: source},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("Google API redirects are forbidden")
		}}, nil
}

func newMetadataTokenSource(endpoint string, scopes []string, client *http.Client) (*MetadataTokenSource, error) {
	if client == nil || len(scopes) == 0 || len(scopes) > 10 {
		return nil, errors.New("metadata token scopes are required")
	}
	for _, scope := range scopes {
		parsed, err := url.Parse(scope)
		if err != nil || parsed.Scheme != "https" || parsed.Host != "www.googleapis.com" || !strings.HasPrefix(parsed.Path, "/auth/") {
			return nil, errors.New("metadata token scope is invalid")
		}
	}
	return &MetadataTokenSource{endpoint: endpoint, scopes: append([]string(nil), scopes...), client: client, now: time.Now}, nil
}

func (source *MetadataTokenSource) Token(ctx context.Context) (string, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.token != "" && source.now().Add(time.Minute).Before(source.expires) {
		return source.token, nil
	}
	query := url.Values{"scopes": {strings.Join(source.scopes, ",")}}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, source.endpoint+"?"+query.Encode(), nil)
	request.Header.Set("Metadata-Flavor", "Google")
	response, err := source.client.Do(request)
	if err != nil {
		return "", errors.New("obtain workload identity access token")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Metadata-Flavor") != "Google" {
		return "", fmt.Errorf("obtain workload identity access token: HTTP %d", response.StatusCode)
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || decoder.Decode(&struct{}{}) != io.EOF || payload.AccessToken == "" || len(payload.AccessToken) > 4096 || strings.TrimSpace(payload.AccessToken) != payload.AccessToken || strings.ContainsAny(payload.AccessToken, "\r\n\x00") || payload.TokenType != "Bearer" || payload.ExpiresIn < 60 || payload.ExpiresIn > 7200 {
		return "", errors.New("workload identity access token response is invalid")
	}
	source.token = payload.AccessToken
	source.expires = source.now().Add(time.Duration(payload.ExpiresIn) * time.Second)
	return source.token, nil
}

type authorizationTransport struct {
	base   http.RoundTripper
	tokens *MetadataTokenSource
}

func (transport *authorizationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	token, err := transport.tokens.Token(request.Context())
	if err != nil {
		return nil, err
	}
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	clone.Header.Set("Authorization", "Bearer "+token)
	return transport.base.RoundTrip(clone)
}
