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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
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

func decide(p *Policy, ev Event) Decision {
	logits := p.Bias
	for name, idx := range p.FeatureMap {
		val, ok := ev.Features[name]
		if !ok {
			continue
		}
		logits[0] += p.Weights[idx][0] * val
		logits[1] += p.Weights[idx][1] * val
		logits[2] += p.Weights[idx][2] * val
	}
	probs := softmax(logits)
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
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			fmt.Fprintf(os.Stderr, "skip bad event: %v\n", err)
			continue
		}
		d := decide(p, ev)
		out, _ := json.Marshal(d)
		wr.Write(out)
		wr.WriteByte('\n')
		if err == io.EOF {
			return
		}
	}
}
