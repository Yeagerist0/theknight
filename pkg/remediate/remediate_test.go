package remediate

import (
	"testing"

	"github.com/Yeagerist0/theknight/pkg/rules"
)

func TestGenerate_UnknownRemediationID(t *testing.T) {
	f := rules.Finding{RemediationID: "does-not-exist"}

	_, ok, err := Generate(f)
	if err != nil {
		t.Fatalf("Generate() error = %v, want nil", err)
	}
	if ok {
		t.Fatal("Generate() ok = true, want false for an unregistered RemediationID")
	}
}

func TestSafeIdent(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"deploy-role", "deploy-role"},
		{"My SG!", "My_SG"},
		{"", "resource"},
		{"123-web", "_123-web"},
	}

	for _, tt := range tests {
		if got := SafeIdent(tt.name); got != tt.want {
			t.Errorf("SafeIdent(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}
