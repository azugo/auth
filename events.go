package auth

import (
	"context"

	"azugo.io/auth/event"

	"azugo.io/azugo"
	"go.uber.org/zap"
)

type logEventSink struct {
	auth *Auth
}

func (s *logEventSink) Emit(ctx context.Context, e event.Event) {
	actx := azugo.RequestContext(ctx)
	log := s.auth.Log(ctx).Named("event").WithOptions(zap.AddCallerSkip(2))

	fields := make([]zap.Field, 0, 4+len(e.Detail))
	fields = append(fields, zap.String("event.action", e.Type))

	if e.UserID != "" {
		fields = append(fields, zap.String("user.id", e.UserID))
	}

	if e.ClientID != "" {
		fields = append(fields, zap.String("client.id", e.ClientID))
	}

	// The request logger already carries source.ip.
	if e.IP != "" && actx == nil {
		fields = append(fields, zap.String("source.ip", e.IP))
	}

	for k, v := range e.Detail {
		if k == detailKeyUsername {
			fields = append(fields, zap.Any("user.name", v))

			continue
		}

		fields = append(fields, zap.Any("labels."+k, v))
	}

	log.Info("auth event", fields...)
}
