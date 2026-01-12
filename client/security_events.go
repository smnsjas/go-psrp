// Package client provides a high-level PSRP client.
//
// This file implements NIST SP 800-92 compliant security event logging.
// All security-relevant events are logged with standardized event types,
// structured fields, and correlation IDs for tracing.
package client

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// Security event types per NIST SP 800-92
const (
	// EventAuthentication covers login attempts and credential validation.
	EventAuthentication = "authentication"

	// EventConnection covers network connection lifecycle.
	EventConnection = "connection"

	// EventCommand covers command execution lifecycle.
	EventCommand = "command"

	// EventReconnection covers automatic reconnection attempts.
	EventReconnection = "reconnection"

	// EventSession covers session lifecycle (open/close).
	EventSession = "session"
)

// Security event subtypes
const (
	// Authentication subtypes
	SubtypeAuthAttempt = "attempt"
	SubtypeAuthSuccess = "success"
	SubtypeAuthFailure = "failure"

	// Connection subtypes
	SubtypeConnEstablished = "established"
	SubtypeConnClosed      = "closed"
	SubtypeConnFailed      = "failed"

	// Reconnection subtypes
	SubtypeReconnAttempt   = "attempt"
	SubtypeReconnSuccess   = "success"
	SubtypeReconnExhausted = "exhausted"

	// Command subtypes
	SubtypeCmdExecute  = "execute"
	SubtypeCmdComplete = "complete"
	SubtypeCmdFailed   = "failed"

	// Session subtypes
	SubtypeSessionOpened = "opened"
	SubtypeSessionClosed = "closed"
)

// Event outcomes per NIST SP 800-92
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeDenied  = "denied"
)

// Severity levels per NIST SP 800-92
const (
	SeverityInfo     = "INFO"
	SeverityWarning  = "WARNING"
	SeverityError    = "ERROR"
	SeverityCritical = "CRITICAL"
)

// SecurityEvent represents a NIST SP 800-92 compliant security log event.
// All fields follow the required data elements specification.
type SecurityEvent struct {
	// Timestamp when the event occurred (ISO 8601 with timezone)
	Timestamp string `json:"timestamp"`

	// EventType is the category of the event
	EventType string `json:"event_type"`

	// Subtype provides additional classification
	Subtype string `json:"subtype,omitempty"`

	// Component that generated the event
	Component string `json:"component"`

	// CorrelationID traces related events across session lifecycle
	CorrelationID string `json:"correlation_id"`

	// User identity (if applicable)
	User string `json:"user,omitempty"`

	// Target of the action (server, command, etc.)
	Target string `json:"target"`

	// Outcome of the action (success/failure/denied)
	Outcome string `json:"outcome"`

	// Severity level (INFO/WARNING/ERROR/CRITICAL)
	Severity string `json:"severity"`

	// Details contains additional context-specific information
	Details map[string]any `json:"details,omitempty"`
}

// NewSecurityEvent creates a new security event with required fields populated.
func NewSecurityEvent(
	eventType, subtype string,
	correlationID string,
	target string,
	outcome string,
	severity string,
) *SecurityEvent {
	return &SecurityEvent{
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		EventType:     eventType,
		Subtype:       subtype,
		Component:     "go-psrp/client",
		CorrelationID: correlationID,
		Target:        target,
		Outcome:       outcome,
		Severity:      severity,
		Details:       make(map[string]any),
	}
}

// WithUser adds user identity to the event.
func (e *SecurityEvent) WithUser(user string) *SecurityEvent {
	e.User = user
	return e
}

// WithDetail adds a detail field to the event.
func (e *SecurityEvent) WithDetail(key string, value any) *SecurityEvent {
	if e.Details == nil {
		e.Details = make(map[string]any)
	}
	e.Details[key] = value
	return e
}

// Log emits the security event to the provided slog logger.
// The event is logged as a structured JSON object.
func (e *SecurityEvent) Log(logger *slog.Logger) {
	if logger == nil {
		return
	}

	// Choose log level based on severity
	var logFunc func(msg string, args ...any)
	switch e.Severity {
	case SeverityCritical, SeverityError:
		logFunc = logger.Error
	case SeverityWarning:
		logFunc = logger.Warn
	default:
		logFunc = logger.Info
	}

	// Log with structured fields
	logFunc("security_event",
		"event_type", e.EventType,
		"subtype", e.Subtype,
		"correlation_id", e.CorrelationID,
		"user", e.User,
		"target", e.Target,
		"outcome", e.Outcome,
		"severity", e.Severity,
		"details", e.Details,
	)
}

// JSON returns the event as a JSON string for external logging systems.
func (e *SecurityEvent) JSON() string {
	data, err := json.Marshal(e)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// SecurityLogger provides NIST SP 800-92 compliant security logging.
type SecurityLogger struct {
	logger        *slog.Logger
	correlationID string
	user          string
	target        string
}

// NewSecurityLogger creates a new security logger with correlation ID.
func NewSecurityLogger(logger *slog.Logger, user, target string) *SecurityLogger {
	return &SecurityLogger{
		logger:        logger,
		correlationID: uuid.New().String(),
		user:          user,
		target:        target,
	}
}

// CorrelationID returns the correlation ID for this logger.
func (sl *SecurityLogger) CorrelationID() string {
	return sl.correlationID
}

// SetCorrelationID sets a specific correlation ID (for session resumption).
func (sl *SecurityLogger) SetCorrelationID(id string) {
	sl.correlationID = id
}

// LogAuthentication logs an authentication event.
func (sl *SecurityLogger) LogAuthentication(subtype, outcome, severity string, details map[string]any) {
	event := NewSecurityEvent(EventAuthentication, subtype, sl.correlationID, sl.target, outcome, severity).
		WithUser(sl.user)
	for k, v := range details {
		event.WithDetail(k, v)
	}
	event.Log(sl.logger)
}

// LogConnection logs a connection event.
func (sl *SecurityLogger) LogConnection(subtype, outcome, severity string, details map[string]any) {
	event := NewSecurityEvent(EventConnection, subtype, sl.correlationID, sl.target, outcome, severity).
		WithUser(sl.user)
	for k, v := range details {
		event.WithDetail(k, v)
	}
	event.Log(sl.logger)
}

// LogReconnection logs a reconnection event.
func (sl *SecurityLogger) LogReconnection(subtype, outcome, severity string, details map[string]any) {
	event := NewSecurityEvent(EventReconnection, subtype, sl.correlationID, sl.target, outcome, severity).
		WithUser(sl.user)
	for k, v := range details {
		event.WithDetail(k, v)
	}
	event.Log(sl.logger)
}

// LogCommand logs a command execution event.
func (sl *SecurityLogger) LogCommand(subtype, outcome, severity string, script string, details map[string]any) {
	event := NewSecurityEvent(EventCommand, subtype, sl.correlationID, sl.target, outcome, severity).
		WithUser(sl.user).
		WithDetail("script_preview", truncateScript(script, 100))
	for k, v := range details {
		event.WithDetail(k, v)
	}
	event.Log(sl.logger)
}

// LogSession logs a session lifecycle event.
func (sl *SecurityLogger) LogSession(subtype, outcome, severity string, details map[string]any) {
	event := NewSecurityEvent(EventSession, subtype, sl.correlationID, sl.target, outcome, severity).
		WithUser(sl.user)
	for k, v := range details {
		event.WithDetail(k, v)
	}
	event.Log(sl.logger)
}

// truncateScript truncates a script for logging (avoids logging sensitive content).
func truncateScript(script string, maxLen int) string {
	if len(script) <= maxLen {
		return script
	}
	return script[:maxLen] + "..."
}
