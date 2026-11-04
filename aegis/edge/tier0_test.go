package main

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

func testPolicy() *Policy {
	return &Policy{
		FeatureMap: map[string]int{"ip_known_bad": 0, "rate": 1},
		Weights:    [][3]float64{{-1, 0.5, 3}, {0, 0.1, 0.2}},
		BlockGate:  0.9,
	}
}

func TestExtremeFeatureFailsClosed(t *testing.T) {
	for _, v := range []float64{1e308, math.Inf(1), math.NaN()} {
		d := decide(testPolicy(), Event{ID: "e", Features: map[string]float64{"ip_known_bad": v}})
		if d.Action != "escalate" || !d.HITLRequired {
			t.Fatalf("feature %v: got %+v, want escalate + HITL", v, d)
		}
	}
}

func TestOrdinaryEventStillDecides(t *testing.T) {
	d := decide(testPolicy(), Event{ID: "e", Features: map[string]float64{"ip_known_bad": 0}})
	if d.Action == "" {
		t.Fatal("no action")
	}
}

func TestPolicyWithOutOfRangeIndexIsRefused(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "p.json")
	os.WriteFile(p, []byte(`{"feature_map":{"a":0,"b":7},"weights":[[0,0,0],[0,0,0]],"bias":[0,0,0]}`), 0o600)
	if _, err := loadPolicy(p); err == nil {
		t.Fatal("policy with index 7 over 2 rows was accepted")
	}
}
