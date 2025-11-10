package main

import (
	"os"
	"testing"
)

func TestLoadPolicy_Defaults(t *testing.T) {
	// Should not panic and should populate bands and weights
	loadPolicy("")
	if len(pol.Weights) == 0 || len(pol.Bands) == 0 {
		t.Fatalf("expected default policy to load")
	}
	if gradeResult(nil) < 1 || gradeResult(nil) > 5 {
		t.Fatalf("grade out of band")
	}
}

func TestLoadPolicy_CustomMerge(t *testing.T) {
	tmp := t.TempDir()
	path := tmp + "/policy.yaml"
	custom := `
weights:
  HSTS_MISSING: 123
bands:
  - { min: 0, max: 10, grade: 1 }
  - { min: 11, max: 20, grade: 5 }
`
	if err := os.WriteFile(path, []byte(custom), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	loadPolicy(path)

	// Custom weight overrides default
	if pol.Weights["HSTS_MISSING"] != 123 {
		t.Fatalf("expected HSTS_MISSING weight 123, got %d", pol.Weights["HSTS_MISSING"])
	}

	// Custom bands override default
	if len(pol.Bands) != 2 || pol.Bands[1].Grade != 5 {
		t.Fatalf("expected 2 custom bands, got %+v", pol.Bands)
	}

	// Score 12 should fall into grade 5 per custom bands
	g := gradeResult([]Risk{{Code: "HSTS_MISSING"}}) // weight 123 > 20 anyway
	if g != 5 {
		t.Fatalf("expected grade 5, got %d", g)
	}
}
