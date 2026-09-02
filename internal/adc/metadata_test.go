package adc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMetadataTokenSourceRequiresFlavorAndCaches(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if request.Header.Get("Metadata-Flavor") != "Google" {
			t.Error("metadata flavor missing")
		}
		writer.Header().Set("Metadata-Flavor", "Google")
		_, _ = writer.Write([]byte(`{"access_token":"workload-token","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer server.Close()
	source, err := newMetadataTokenSource(server.URL, []string{"https://www.googleapis.com/auth/cloud-platform"}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return time.Unix(1000, 0) }
	for range 2 {
		token, err := source.Token(context.Background())
		if err != nil || token != "workload-token" {
			t.Fatalf("token=%q err=%v", token, err)
		}
	}
	if calls != 1 {
		t.Fatalf("metadata calls=%d, want 1", calls)
	}
}
