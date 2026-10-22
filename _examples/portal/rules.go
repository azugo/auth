package portal

import (
	"context"
	"sync"

	"azugo.io/auth"
	"azugo.io/auth/session"

	"github.com/goccy/go-json"
)

const (
	// StepRules is the name of the login step asking the user to accept the portal rules.
	StepRules = "rules"
	// RulesVersion is the current version of the portal rules; raising it asks every user again.
	RulesVersion = "2026-10"
)

// Rules is a login step holding a session until its user has accepted the current portal rules.
type Rules struct {
	mu sync.Mutex
	// accepted maps a user ID to the rules version it accepted.
	accepted map[string]string
}

// NewRules creates the rules step with no acceptances recorded.
func NewRules() *Rules {
	return &Rules{accepted: make(map[string]string)}
}

// Name implements auth.LoginStep.
func (r *Rules) Name() string {
	return StepRules
}

// Required implements auth.LoginStep.
func (r *Rules) Required(_ context.Context, s *session.Session, _ auth.UserInfo) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.accepted[s.UserID] != RulesVersion, nil
}

// Prompt implements auth.LoginStep.
func (r *Rules) Prompt(context.Context, *session.Session, auth.UserInfo) (auth.StepPrompt, error) {
	return auth.StepPrompt{Interaction: "accept_rules", Data: map[string]any{"version": RulesVersion}}, nil
}

// Resolve implements auth.LoginStep; the payload is {"version": "<accepted version>"}.
func (r *Rules) Resolve(_ context.Context, s *session.Session, _ auth.UserInfo, payload []byte) (auth.StepResult, error) {
	var in struct {
		Version string `json:"version"`
	}

	if err := json.Unmarshal(payload, &in); err != nil || in.Version != RulesVersion {
		return auth.StepResult{Data: map[string]any{"error": "You must accept the current rules to continue."}}, nil //nolint:nilerr
	}

	r.mu.Lock()
	r.accepted[s.UserID] = in.Version
	r.mu.Unlock()

	s.Context["rules_version"] = in.Version

	return auth.StepResult{Done: true}, nil
}
