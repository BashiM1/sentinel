/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package garak

import (
	"reflect"
	"strings"
	"testing"

	sentinelv1alpha1 "github.com/BashiM1/sentinel/api/v1alpha1"
)

// All fixtures use the parser's assumed schema (entry_type=eval, probe,
// passed, failed). If the real Garak report uses different field names,
// adjust both parser.go's struct tags and these fixtures together — they
// are intentionally a single source of truth in this package.

func TestParseGarakOutput(t *testing.T) {
	t.Run("normal output with multiple probe types", func(t *testing.T) {
		// passed=resisted, failed=attacker succeeded (Garak's terminology).
		// Three probes spanning three OWASP categories and three severities.
		input := strings.Join([]string{
			`{"entry_type": "config", "model": "default", "version": "0.10.x"}`,
			`{"entry_type": "eval", "probe": "promptinject.HijackHateHumans", "passed": 5, "failed": 95}`,
			`{"entry_type": "eval", "probe": "leakplay.GuessingGame", "passed": 80, "failed": 20}`,
			`{"entry_type": "eval", "probe": "encoding.InjectBase64", "passed": 95, "failed": 5}`,
		}, "\n")

		findings, err := ParseGarakOutput([]byte(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 3 {
			t.Fatalf("expected 3 findings, got %d: %+v", len(findings), findings)
		}

		// Findings are returned sorted by ID. "garak:" prefix means the
		// alphabetical order is determined by the probe name.
		want := []sentinelv1alpha1.Finding{
			{
				ID:       "garak:encoding.InjectBase64",
				Category: "LLM05",
				Severity: "low", // 5/100 = 0.05 <= 0.10
			},
			{
				ID:       "garak:leakplay.GuessingGame",
				Category: "LLM02",
				Severity: "medium", // 20/100 = 0.20, > 0.10
			},
			{
				ID:       "garak:promptinject.HijackHateHumans",
				Category: "LLM01",
				Severity: "critical", // 95/100 = 0.95, > 0.50
			},
		}
		for i, w := range want {
			if findings[i].ID != w.ID {
				t.Errorf("finding[%d].ID: want %q, got %q", i, w.ID, findings[i].ID)
			}
			if findings[i].Category != w.Category {
				t.Errorf("finding[%d].Category: want %q, got %q", i, w.Category, findings[i].Category)
			}
			if findings[i].Severity != w.Severity {
				t.Errorf("finding[%d].Severity: want %q, got %q", i, w.Severity, findings[i].Severity)
			}
			if !strings.Contains(findings[i].Description, w.ID[len("garak:"):]) {
				t.Errorf("finding[%d].Description should mention probe name, got %q", i, findings[i].Description)
			}
		}
	})

	t.Run("empty output produces no findings and no error", func(t *testing.T) {
		findings, err := ParseGarakOutput([]byte(""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected zero findings, got %d", len(findings))
		}
	})

	t.Run("malformed JSON lines are skipped silently", func(t *testing.T) {
		// Mixed valid and invalid lines; only the valid eval entry should
		// produce a finding. This is the realistic shape of the Job's
		// captured stdout: shell echo lines, ls output, then JSONL.
		input := strings.Join([]string{
			"==> sentinel: starting Garak scan",
			"this is not json",
			`{"entry_type": "eval", "probe": "dan.DAN_Jailbreak", "passed": 30, "failed": 70}`,
			`{ broken json`,
			"total 0",
			`{"entry_type": "garbage_we_don't_understand"}`,
		}, "\n")

		findings, err := ParseGarakOutput([]byte(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding from the single valid eval entry, got %d: %+v", len(findings), findings)
		}
		if findings[0].Category != "LLM01" {
			t.Errorf("dan.* should map to LLM01, got %q", findings[0].Category)
		}
		if findings[0].Severity != "critical" {
			t.Errorf("70%% success rate should be critical, got %q", findings[0].Severity)
		}
	})

	t.Run("unknown probe families map to UNMAPPED", func(t *testing.T) {
		input := `{"entry_type": "eval", "probe": "weirdthing.NotAKnownProbe", "passed": 10, "failed": 90}`
		findings, err := ParseGarakOutput([]byte(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Category != CategoryUnmapped {
			t.Errorf("unknown probe should map to %q, got %q", CategoryUnmapped, findings[0].Category)
		}
		if findings[0].Severity != "critical" {
			t.Errorf("90%% success rate should be critical even when category is unmapped, got %q", findings[0].Severity)
		}
	})

	t.Run("multiple eval entries for the same probe are aggregated", func(t *testing.T) {
		// Defensive: Garak may emit per-shard or per-attempt eval lines in
		// some configurations. The parser must sum them rather than keep
		// only the last seen.
		input := strings.Join([]string{
			`{"entry_type": "eval", "probe": "promptinject.X", "passed": 10, "failed": 10}`,
			`{"entry_type": "eval", "probe": "promptinject.X", "passed": 30, "failed": 50}`,
		}, "\n")
		findings, err := ParseGarakOutput([]byte(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("expected aggregated single finding, got %d", len(findings))
		}
		// total = 100, failed = 60, rate = 0.60 -> critical
		if findings[0].Severity != "critical" {
			t.Errorf("aggregated rate of 0.6 should be critical, got %q", findings[0].Severity)
		}
	})
}

func TestProbeToOWASP(t *testing.T) {
	cases := []struct {
		probe string
		want  string
	}{
		{"promptinject.HijackHateHumans", "LLM01"},
		{"PromptInject.MixedCase", "LLM01"}, // case-insensitive
		{"dan.DAN_Jailbreak", "LLM01"},
		{"jailbreak.PromptLeak", "LLM01"},
		{"leakplay.GuessingGame", "LLM02"},
		{"encoding.InjectBase64", "LLM05"},
		{"continuation.ContinueSlursReclaimedSlurs", "LLM06"},
		{"snowball.GraphConnectivity", "LLM02"},
		{"xss.MarkdownImageExfil", "LLM02"},
		{"unknown.Probe", CategoryUnmapped},
		{"", CategoryUnmapped},
	}
	for _, c := range cases {
		t.Run(c.probe, func(t *testing.T) {
			got := probeToOWASP(c.probe)
			if got != c.want {
				t.Errorf("probeToOWASP(%q) = %q, want %q", c.probe, got, c.want)
			}
		})
	}
}

func TestSeverityForRate(t *testing.T) {
	// Threshold boundaries are exclusive: >0.50 critical, etc. Test each
	// boundary's edge cases plus the bands.
	cases := []struct {
		rate float64
		want string
	}{
		{1.00, "critical"},
		{0.51, "critical"},
		{0.50, "high"},
		{0.26, "high"},
		{0.25, "medium"},
		{0.11, "medium"},
		{0.10, "low"},
		{0.05, "low"},
		{0.00, "low"},
	}
	for _, c := range cases {
		got := severityForRate(c.rate)
		if got != c.want {
			t.Errorf("severityForRate(%.2f) = %q, want %q", c.rate, got, c.want)
		}
	}
}

func TestParseGarakOutput_FindingFieldsArePopulated(t *testing.T) {
	// Spot-check that every Finding field is non-empty for a successful
	// parse. Catches regressions where (e.g.) a description format change
	// produces an empty string.
	input := `{"entry_type": "eval", "probe": "promptinject.X", "passed": 0, "failed": 1}`
	findings, err := ParseGarakOutput([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	zero := sentinelv1alpha1.Finding{}
	if reflect.DeepEqual(f, zero) {
		t.Fatalf("finding is fully zero-valued: %+v", f)
	}
	if f.ID == "" || f.Category == "" || f.Severity == "" || f.Description == "" {
		t.Errorf("finding has empty field(s): %+v", f)
	}
}
