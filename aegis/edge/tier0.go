// Tier-0 inline traffic filter — Go skeleton.
//
// Purpose: at bank scale (millions of req/s) Python is too slow for
// per-request decisions. This is the Go data-plane that consumes a
// trained policy (typically a PPO classifier) and renders allow/block/
// escalate decisions in microseconds.
//
// Walking-skeleton scope:
//   - Reads JSON-lines events from stdin (stand-in for Kafka).
//   - Loads a "policy" JSON file with feature weights (export from
//     stable-baselines3 via aegis/rl/export_policy.py).
//   - Applies the policy and prints decisions.
//
// Production swaps:
//   - stdin reader  -> Kafka consumer (Sarama / segmentio/kafka-go)
//   - JSON policy   -> ONNX or torchserve inference for richer models
//   - stdout writer -> Kafka produce + Envoy ext_authz response
//
// Build:
//   cd aegis/edge && go build -o tier0 .
// Run:
//   cat sample_events.jsonl | ./tier0 -policy ../rl/policy.json
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"regexp"
)

// Policy: linear-feature classifier as a stand-in for a deployed PPO
// model. Real PPO inference would load an ONNX export.
type Policy struct {
	Version    string             `json:"version"`
	FeatureMap map[string]int     `json:"feature_map"`
	// Each row [3]float64 = (allow_logit, escalate_logit, block_logit)
	Weights    [][3]float64       `json:"weights"`
	Bias       [3]float64         `json:"bias"`
	BlockGate  float64            `json:"block_gate"` // refuses to emit "block" without HITL above this score
}

type Event struct {
	ID       string             `json:"id"`
	Features map[string]float64 `json:"features"`
}

type Decision struct {
	ID           string  `json:"id"`
	Action       string  `json:"action"`     // allow | escalate | block
	Confidence   float64 `json:"confidence"`
	HITLRequired bool    `json:"hitl_required"`
}

func loadPolicy(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var p Policy
	if err := json.NewDecoder(f).Decode(&p); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	if len(p.Weights) != len(p.FeatureMap) {
		return nil, fmt.Errorf("policy weights (%d) != feature_map (%d)", len(p.Weights), len(p.FeatureMap))
	}
	// every index must name a weight row: an out-of-range index used to panic on the first matching event
	// and take the data plane down (review round 7 R-6)
	for name, idx := range p.FeatureMap {
		if idx < 0 || idx >= len(p.Weights) {
			return nil, fmt.Errorf("feature_map[%q] = %d is outside the %d weight rows", name, idx, len(p.Weights))
		}
	}
	for i, row := range p.Weights {
		for _, w := range row {
			if math.IsNaN(w) || math.IsInf(w, 0) {
				return nil, fmt.Errorf("weight row %d is not finite", i)
			}
		}
	}
	for _, b := range p.Bias {
		if math.IsNaN(b) || math.IsInf(b, 0) {
			return nil, fmt.Errorf("bias is not finite")
		}
	}
	return &p, nil
}

func softmax(x [3]float64) [3]float64 {
	max := x[0]
	for _, v := range x {
		if v > max {
			max = v
		}
	}
	var sum float64
	var out [3]float64
	for i, v := range x {
		out[i] = expFast(v - max)
		sum += out[i]
	}
	for i := range out {
		out[i] /= sum
	}
	return out
}

// expFast: avoid math import for portability of this skeleton.
func expFast(x float64) float64 {
	// Pade approximation, good enough for softmax demo purposes.
	if x < -20 {
		return 0
	}
	if x > 20 {
		return 4.85e8
	}
	// Use repeated squaring of exp(x/2^n)
	n := 8
	v := 1 + x/float64(int(1)<<n)
	for i := 0; i < n; i++ {
		v *= v
	}
	return v
}

// failClosed: an event the policy cannot score goes to a human, never to "allow".
func failClosed(id string) Decision {
	return Decision{ID: id, Action: "escalate", Confidence: 0, HITLRequired: true}
}

func finite(x float64) bool { return !math.IsNaN(x) && !math.IsInf(x, 0) }

func decide(p *Policy, ev Event) Decision {
	logits := p.Bias
	for name, idx := range p.FeatureMap {
		val, ok := ev.Features[name]
		if !ok {
			continue
		}
		if !finite(val) || idx < 0 || idx >= len(p.Weights) {
			return failClosed(ev.ID)
		}
		logits[0] += p.Weights[idx][0] * val
		logits[1] += p.Weights[idx][1] * val
		logits[2] += p.Weights[idx][2] * val
	}
	// an extreme feature (1e308 × weight) overflowed to ±Inf → NaN probabilities → argmax "allow" (review round 7 R-6)
	for _, l := range logits {
		if !finite(l) {
			return failClosed(ev.ID)
		}
	}
	probs := softmax(logits)
	for _, v := range probs {
		if !finite(v) {
			return failClosed(ev.ID)
		}
	}
	// argmax
	best := 0
	for i, v := range probs {
		if v > probs[best] {
			best = i
		}
	}
	actions := []string{"allow", "escalate", "block"}
	d := Decision{
		ID:         ev.ID,
		Action:     actions[best],
		Confidence: probs[best],
	}
	// Refuse to auto-block below the gate; route to escalate instead.
	if d.Action == "block" && d.Confidence < p.BlockGate {
		d.Action = "escalate"
		d.HITLRequired = true
	}
	if d.Action == "block" || d.Action == "escalate" {
		d.HITLRequired = true
	}
	return d
}

// idPattern: last-resort id recovery from a line that is not even valid JSON.
var idPattern = regexp.MustCompile(`"id"\s*:\s*"((?:[^"\\]|\\.)*)"`)

// bestEffortID recovers the event id from a line that failed to decode as an Event, so the fail-closed
// decision can still be correlated by the consumer. Empty when nothing usable is found.
func bestEffortID(line []byte) string {
	var partial struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(line, &partial) == nil && len(partial.ID) > 0 {
		var s string
		if json.Unmarshal(partial.ID, &s) == nil {
			return s
		}
		return string(partial.ID) // numeric / other scalar id: keep its literal text
	}
	if m := idPattern.FindSubmatch(line); m != nil {
		var s string
		if json.Unmarshal(append(append([]byte{'"'}, m[1]...), '"'), &s) == nil {
			return s
		}
	}
	return ""
}

// decideLine turns one input line into exactly one encoded decision. An event that does not decode (bad
// JSON, a string or out-of-range number where a feature belongs) is escalated with HITL, never skipped:
// a skipped line left the consumer one decision short and mis-aligned (review round 8 R8-1).
func decideLine(p *Policy, line []byte) []byte {
	var ev Event
	var d Decision
	if err := json.Unmarshal(line, &ev); err != nil {
		id := ev.ID
		if id == "" {
			id = bestEffortID(line)
		}
		fmt.Fprintf(os.Stderr, "undecodable event %q: %v — fail-closed escalate\n", id, err)
		d = failClosed(id)
	} else {
		d = decide(p, ev)
	}
	out, merr := json.Marshal(d)
	if merr != nil {
		// never an empty line: the consumer must see a decision for every event
		out, _ = json.Marshal(failClosed(d.ID))
	}
	return out
}

func main() {
	policyPath := flag.String("policy", "policy.json", "Path to PPO/linear policy JSON")
	flag.Parse()

	p, err := loadPolicy(*policyPath)
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}

	rd := bufio.NewReader(os.Stdin)
	wr := bufio.NewWriter(os.Stdout)
	defer wr.Flush()

	for {
		line, err := rd.ReadBytes('\n')
		if len(line) == 0 {
			if err == io.EOF {
				return
			}
			if err != nil {
				log.Fatalf("read: %v", err)
			}
			continue
		}
		if len(bytes.TrimSpace(line)) > 0 { // a blank line is not an event; anything else gets one decision
			wr.Write(decideLine(p, line))
			wr.WriteByte('\n')
		}
		if err == io.EOF {
			return
		}
	}
}
