package main

import (
	"encoding/json"
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

// review round 8 R8-1: an undecodable event is escalated (fail-closed), never skipped.
func TestUndecodableEventFailsClosedWithID(t *testing.T) {
	cases := map[string]string{
		`{"id":"string-feature","features":{"ip_known_bad":1,"rate":"x"}}`:     "string-feature",
		`{"id":"overflow-literal","features":{"ip_known_bad":1,"rate":1e400}}`: "overflow-literal",
		`{"features":{"rate":"x"},"id":"late-id"}`:                             "late-id",
		`{"id":"trunc","features":{"rate":`:                                    "trunc",
		`{"id":42,"features":{"rate":"x"}}`:                                    "42",
		`not json at all`:                                                      "",
	}
	for line, wantID := range cases {
		var d Decision
		if err := json.Unmarshal(decideLine(testPolicy(), []byte(line)), &d); err != nil {
			t.Fatalf("%s: output not JSON: %v", line, err)
		}
		if d.Action != "escalate" || !d.HITLRequired || d.ID != wantID {
			t.Fatalf("%s: got %+v, want escalate+HITL id=%q", line, d, wantID)
		}
	}
}

func TestEveryLineGetsOneDecision(t *testing.T) {
	in := []string{
		`{"id":"a","features":{"ip_known_bad":1}}`,
		`{"id":"b","features":{"rate":"x"}}`,
		`{"id":"c","features":{"ip_known_bad":0}}`,
	}
	for i, l := range in {
		var d Decision
		json.Unmarshal(decideLine(testPolicy(), []byte(l)), &d)
		if d.ID != string(rune('a'+i)) || d.Action == "" {
			t.Fatalf("line %d: %+v", i, d)
		}
	}
}
