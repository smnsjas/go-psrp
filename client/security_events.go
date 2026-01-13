package client

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// NIST SP 800-92 compliant event types
const (
	EventAuthentication   = "authentication"
	EventConnection       = "connection"
	EventCommand          = "command"
	EventReconnection     = "reconnection"
	EventSessionLifecycle = "session_lifecycle"
)

// Security event subtypes
const (
	SubtypeConnEstablished = "established"
	SubtypeConnClosed      = "closed"
	SubtypeConnFailed      = "failed"
	SubtypeAuthAttempt     = "attempt"
	SubtypeAuthSuccess     = "success"
	SubtypeAuthFailure     = "failure"
	SubtypeSessionOpen     = "open"
	SubtypeSessionOpened   = "open" // Alias for backward compatibility if needed, or simply use this.
	SubtypeSessionClosed   = "closed"
	SubtypeCommandExecute  = "execute"
	SubtypeCommandComplete = "complete"
	SubtypeCommandFailed   = "failed"

	// Reconnection subtypes
	SubtypeReconnAttempt   = "attempt"
	SubtypeReconnSuccess   = "success"
	SubtypeReconnExhausted = "exhausted"
)

// Security event outcomes
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeDenied  = "denied"
	OutcomeAttempt = "attempt"
)

// Security event severities
const (
	SeverityInfo     = "INFO"
	SeverityWarning  = "WARNING"
	SeverityError    = "ERROR"
	SeverityCritical = "CRITICAL"
)

// SecurityEvent represents a structured security log event compliant with NIST SP 800-92.
type SecurityEvent struct {
	// NIST Required Fields
	Timestamp string `json:"timestamp"`  // ISO 8601 UTC
	EventType string `json:"event_type"` // auth, connection, command
	Subtype   string `json:"subtype"`    // success, failure, attempt
	Severity  string `json:"severity"`   // INFO, WARN, ERROR

	// Identity & Context
	User          string `json:"user,omitempty"`
	Source        string `json:"source"`         // "go-psrp" client
	Target        string `json:"target"`         // server/endpoint
	CorrelationID string `json:"correlation_id"` // Session-scoped UUID

	// Operation Details
	Action  string         `json:"action"`            // e.g., "NegotiateAuth", "CreatePipeline"
	Outcome string         `json:"outcome"`           // success, failure
	Details map[string]any `json:"details,omitempty"` // Context-specific details
}

// SecurityLogger is a helper to generate and write security events.
type SecurityLogger struct {
	logger        *slog.Logger
	user          string
	target        string
	correlationID string
}

// NewSecurityLogger creates a new logger for a session.
// It generates a new CorrelationID (UUID) for this logger instance.
func NewSecurityLogger(logger *slog.Logger, user, target string) *SecurityLogger {
	return &SecurityLogger{
		logger:        logger,
		user:          user,
		target:        target,
		correlationID: uuid.New().String(),
	}
}

// LogEvent constructs and logs a security event.
func (l *SecurityLogger) LogEvent(eventType, subtype, severity, outcome string, details map[string]any) {
	if l.logger == nil {
		return
	}

	event := &SecurityEvent{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		EventType:     eventType,
		Subtype:       subtype,
		Severity:      severity,
		User:          l.user,
		Source:        "go-psrp",
		Target:        l.target,
		CorrelationID: l.correlationID,
		Action:        subtype, // Default action to subtype if not clearer
		Outcome:       outcome,
		Details:       details,
	}

	// Marshaling checks
	if details == nil {
		event.Details = make(map[string]any)
	}

	switch severity {
	case SeverityInfo:
		l.logger.Info("SecurityEvent", "event", event)
	case SeverityWarning:
		l.logger.Warn("SecurityEvent", "event", event)
	case SeverityError, SeverityCritical:
		l.logger.Error("SecurityEvent", "event", event)
	default:
		l.logger.Info("SecurityEvent", "event", event)
	}
}

// LogConnection logs connection events.
func (l *SecurityLogger) LogConnection(subtype, outcome, severity string, details map[string]any) {
	l.LogEvent(EventConnection, subtype, severity, outcome, details)
}

// LogSession logs session lifecycle events.
func (l *SecurityLogger) LogSession(subtype, outcome, severity string, details map[string]any) {
	l.LogEvent(EventSessionLifecycle, subtype, severity, outcome, details)
}

// LogCommand logs command execution events.
func (l *SecurityLogger) LogCommand(subtype, outcome, severity string, details map[string]any) {
	l.LogEvent(EventCommand, subtype, severity, outcome, details)
}

// LogAuthentication logs authentication events.
func (l *SecurityLogger) LogAuthentication(subtype, outcome, severity string, details map[string]any) {
	l.LogEvent(EventAuthentication, subtype, severity, outcome, details)
}

// LogReconnection logs reconnection events.
func (l *SecurityLogger) LogReconnection(subtype, outcome, severity string, details map[string]any) {
	l.LogEvent(EventReconnection, subtype, severity, outcome, details)
}

// String returns the JSON representation of the event
func (e *SecurityEvent) String() string {
	b, _ := json.Marshal(e)
	return string(b)
}
