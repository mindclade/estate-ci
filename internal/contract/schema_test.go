package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPublishedSchemasAndOpenAPIParseAndStayVersioned(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	paths := []string{
		"schemas/estate-health-v1.schema.json",
		"schemas/operation-dispatch-result-v1.schema.json",
		"schemas/operation-dispatch-v1.schema.json",
		"schemas/operation-request-v1.schema.json",
		"schemas/operation-receipt-v1.schema.json",
		"schemas/workflow-evidence-v1.schema.json",
		"schemas/workflow-evidence-v2.schema.json",
		"api/openapi.json",
	}
	for _, relative := range paths {
		t.Run(relative, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, relative))
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			if len(document) == 0 {
				t.Fatal("schema document is empty")
			}
		})
	}
}
