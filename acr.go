package auth

import (
	"slices"
	"strings"

	"azugo.io/auth/client"
	"azugo.io/auth/contract"
	"azugo.io/auth/session"

	"github.com/goccy/go-json"
)

// acrRequest is the authentication-context request carried by acr_values (voluntary) or an
// essential claims request (hard).
type acrRequest struct {
	Values    []string
	Essential bool
}

// parseACRRequest combines the acr_values parameter with the OIDC claims parameter, whose
// id_token.acr entry takes precedence and may mark the request essential.
func parseACRRequest(acrValues, claims string) acrRequest {
	req := acrRequest{Values: strings.Fields(acrValues)}

	if claims == "" {
		return req
	}

	var doc struct {
		IDToken struct {
			ACR *struct {
				Essential bool     `json:"essential"`
				Value     string   `json:"value"`
				Values    []string `json:"values"`
			} `json:"acr"`
		} `json:"id_token"`
	}

	if err := json.Unmarshal([]byte(claims), &doc); err != nil || doc.IDToken.ACR == nil {
		return req
	}

	acr := doc.IDToken.ACR
	req.Essential = acr.Essential

	values := acr.Values
	if acr.Value != "" {
		values = append([]string{acr.Value}, values...)
	}

	if len(values) > 0 {
		req.Values = values
	}

	return req
}

// acrLevel returns the configured level for value, or nil.
func (a *Auth) acrLevel(value string) *contract.ACRLevelConfig {
	if value == "" {
		return nil
	}

	for i := range a.config.ACRLevels {
		if a.config.ACRLevels[i].Value == value {
			return &a.config.ACRLevels[i]
		}
	}

	return nil
}

// ACRSatisfies reports whether the satisfied acr meets required on the configured ladder.
func (a *Auth) ACRSatisfies(acr, required string) bool {
	if required == "" {
		return true
	}

	need := a.acrLevel(required)
	have := a.acrLevel(acr)

	return need != nil && have != nil && have.Level >= need.Level
}

// resolveTargetACR picks the level the session must reach.
func (a *Auth) resolveTargetACR(cl *client.Client, req acrRequest, reachable func(*contract.ACRLevelConfig) bool) (*contract.ACRLevelConfig, error) {
	if len(a.config.ACRLevels) == 0 {
		if req.Essential && len(req.Values) > 0 {
			return nil, ErrUnmetAuthenticationRequirements
		}

		return nil, nil
	}

	floor := a.acrLevel(cl.MinACR)
	if floor != nil && !reachable(floor) {
		return nil, ErrUnmetAuthenticationRequirements
	}

	var target *contract.ACRLevelConfig

	for _, v := range req.Values {
		lvl := a.acrLevel(v)
		if lvl == nil || (len(cl.AllowedACRValues) > 0 && !slices.Contains(cl.AllowedACRValues, v)) {
			continue
		}

		if floor != nil && lvl.Level < floor.Level {
			continue
		}

		if reachable(lvl) {
			target = lvl

			break
		}
	}

	if target == nil && req.Essential && len(req.Values) > 0 {
		return nil, ErrUnmetAuthenticationRequirements
	}

	if target == nil {
		if d := a.acrLevel(cl.DefaultACR); d != nil && reachable(d) {
			target = d
		}
	}

	if target == nil {
		for i := range a.config.ACRLevels {
			lvl := &a.config.ACRLevels[i]
			if reachable(lvl) && (target == nil || lvl.Level < target.Level) {
				target = lvl
			}
		}
	}

	if floor != nil && (target == nil || target.Level < floor.Level) {
		target = floor
	}

	return target, nil
}

// primaryMethod returns the primary authentication method that established session.
func primaryMethod(sess *session.Session) string {
	if sess.AuthProvider != "" {
		return sess.AuthProvider
	}

	return client.AuthMethodPassword
}

// levelSatisfied reports whether session already meets required level.
func levelSatisfied(lvl *contract.ACRLevelConfig, sess *session.Session) bool {
	if len(lvl.AuthMethods) > 0 && !slices.Contains(lvl.AuthMethods, primaryMethod(sess)) {
		return false
	}

	if !lvl.RequireMFA {
		return true
	}

	if sess.MFAMethod != "" && (len(lvl.MFAMethods) == 0 || slices.Contains(lvl.MFAMethods, sess.MFAMethod)) {
		return true
	}

	return intersects(sess.AMR, lvl.MFASatisfiedByAMR)
}

// satisfiedACR returns the highest configured level session meets.
func (a *Auth) satisfiedACR(sess *session.Session) string {
	var best *contract.ACRLevelConfig

	for i := range a.config.ACRLevels {
		lvl := &a.config.ACRLevels[i]
		if levelSatisfied(lvl, sess) && (best == nil || lvl.Level > best.Level) {
			best = lvl
		}
	}

	if best == nil {
		return ""
	}

	sess.AMR = mergeAMR(sess.AMR, best.AMR)

	return best.Value
}

// intersects reports whether a and b share an element.
func intersects(a, b []string) bool {
	return slices.ContainsFunc(a, func(v string) bool { return slices.Contains(b, v) })
}
