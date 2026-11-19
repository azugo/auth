package auth

import (
	"context"
	"strings"
	"time"

	"azugo.io/auth/session"
	"azugo.io/auth/token"

	"azugo.io/core/cache"
)

// KeepAlive records activity on the active session behind token, without loading its user, and
// returns the session.
func (a *Auth) KeepAlive(ctx context.Context, tok string) (*session.Session, error) {
	var sess *session.Session

	if strings.HasPrefix(tok, pasetoPrefix) {
		claims, err := a.codec.DecodeAccess(tok)
		if err != nil {
			return nil, NewOAuthErrorFrom(err)
		}

		if sess, err = a.liveSession(ctx, claims); err != nil {
			return nil, err
		}

		if !firstParty(claims, sess) {
			return nil, NewOAuthErrorFrom(ErrFirstPartyRequired)
		}
	} else {
		claims, err := a.verifyJWTAccessToken(ctx, tok)
		if err != nil {
			return nil, err
		}

		// A client credentials JWT has no session.
		if claims.SessionID == "" {
			return nil, NewOAuthErrorFrom(token.ErrInvalidToken)
		}

		if sess, err = a.activeSession(ctx, claims.SessionID); err != nil {
			return nil, err
		}

		if claims.ClientID != sess.ClientID {
			return nil, NewOAuthErrorFrom(ErrFirstPartyRequired)
		}
	}

	a.RecordActivity(ctx, sess)

	return sess, nil
}

// RecordActivity moves session's idle deadline on, writing at most once per tenth of SessionIdleTTL.
func (a *Auth) RecordActivity(ctx context.Context, sess *session.Session) {
	if !sess.Active() {
		return
	}

	ttl := a.config.SessionIdleTTL
	now := time.Now()

	var idle time.Time

	switch {
	case ttl > 0:
		if sess.IdleExpiresAt.After(now.Add(ttl - ttl/10)) {
			return
		}

		idle = now.Add(ttl)
	case sess.IdleExpiresAt.IsZero():
		return
	}

	if err := a.sessions.Touch(ctx, sess.ID, idle); err != nil {
		return
	}

	sess.LastSeen = now
	sess.IdleExpiresAt = idle
}

// RecordSessionActivity is RecordActivity for a session known only by ID, as behind a JWT; it
// loads the session at most once per tenth of SessionIdleTTL on each instance.
func (a *Auth) RecordSessionActivity(ctx context.Context, sessionID string) {
	ttl := a.config.SessionIdleTTL
	if ttl <= 0 || sessionID == "" {
		return
	}

	if seen, _ := a.activity.Get(ctx, sessionID); seen {
		return
	}

	_ = a.activity.Set(ctx, sessionID, true, cache.TTL[bool](ttl/10))

	sess, err := a.sessions.Get(ctx, sessionID)
	if err != nil {
		return
	}

	a.RecordActivity(ctx, sess)

	if due := time.Until(sess.IdleExpiresAt.Add(ttl/10 - ttl)); due > 0 && due < ttl/10 {
		_ = a.activity.Set(ctx, sessionID, true, cache.TTL[bool](due))
	}
}
