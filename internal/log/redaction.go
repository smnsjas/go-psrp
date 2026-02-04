package log

import (
	"context"
	"log/slog"
	"strings"
)

// sensitiveKeys defines the list of keys whose values should be redacted.
// Keys are case-insensitive.
var sensitiveKeys = map[string]struct{}{
	"password": {},
	"pass":     {},
	"secret":   {},
	"token":    {},
	"key":      {},
	"hash":     {},
	"auth":     {},
	"ticket":   {},
	"cred":     {},
}

// RedactingHandler is a slogan.Handler that redacts sensitive information.
type RedactingHandler struct {
	next slog.Handler
}

// NewRedactingHandler creates a new RedactingHandler.
func NewRedactingHandler(next slog.Handler) *RedactingHandler {
	return &RedactingHandler{next: next}
}

// Enabled implements slog.Handler.
func (h *RedactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

// Handle implements slog.Handler. It redacts sensitive attributes before passing to the next handler.
func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	var attrs []slog.Attr

	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, redactAttr(a))
		return true
	})

	// Create a new record with redacted attributes
	newRecord := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	newRecord.AddAttrs(attrs...)

	return h.next.Handle(ctx, newRecord)
}

// WithAttrs implements slog.Handler.
func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redactedAttrs := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		redactedAttrs[i] = redactAttr(a)
	}
	return &RedactingHandler{next: h.next.WithAttrs(redactedAttrs)}
}

// WithGroup implements slog.Handler.
func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{next: h.next.WithGroup(name)}
}

func redactAttr(a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		redactedGroup := make([]interface{}, len(attrs))
		for i, attr := range attrs {
			redactedGroup[i] = redactAttr(attr)
		}
		return slog.Group(a.Key, redactedGroup...)
	}

	// Check if key is sensitive
	lowerKey := strings.ToLower(a.Key)
	for sens := range sensitiveKeys {
		if strings.Contains(lowerKey, sens) {
			return slog.String(a.Key, "[REDACTED]")
		}
	}

	return a
}
