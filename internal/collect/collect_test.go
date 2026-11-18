package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDeniedCallIsMissingNotEmpty(t *testing.T) {
	dir := t.TempDir()
	for api, name := range Files {
		body := `{}`
		if api == APIInstances {
			body = `{"Reservations":[]}`
		}
		if api == APIRouteTables {
			body = `{"Error":{"Code":"UnauthorizedOperation","Message":"denied"}}`
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := FixtureCollector{Dir: dir}.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if reason, missing := s.Missing(APIRouteTables); !missing || reason != "UnauthorizedOperation" {
		t.Errorf("route tables missing=%v reason=%q, want UnauthorizedOperation", missing, reason)
	}
	if got := s.MissingAPIs(); len(got) != 1 || got[0] != APIRouteTables {
		t.Errorf("missing APIs = %v", got)
	}
}
