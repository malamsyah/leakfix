package agent

import "time"

// Guardrails enforces SPEC §9.4 hard limits.
type Guardrails struct {
	MaxIterationsPerFinding int
	MaxInputTokens          int
	MaxOutputTokens         int
	MaxTotalFindings        int
	PerFindingTimeout       time.Duration
	TotalTimeout            time.Duration
	MaxReadFileBytes        int
}

// DefaultGuardrails returns the spec defaults.
func DefaultGuardrails() Guardrails {
	return Guardrails{
		MaxIterationsPerFinding: 8,
		MaxInputTokens:          20000,
		MaxOutputTokens:         4000,
		MaxTotalFindings:        50,
		PerFindingTimeout:       90 * time.Second,
		TotalTimeout:            15 * time.Minute,
		MaxReadFileBytes:        50 * 1024,
	}
}
