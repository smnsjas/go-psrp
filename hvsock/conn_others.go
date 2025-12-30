//go:build !windows

// Package hvsock provides Hyper-V socket (HVSocket) connectivity for PowerShell Direct.
// This file contains stubs for non-Windows platforms.
package hvsock

import (
	"context"
	"errors"
	"net"

	"github.com/google/uuid"
)

// ErrNotSupported indicates HVSocket is only available on Windows.
var ErrNotSupported = errors.New("hvsock is only supported on windows")

// Dial connects to the PowerShell Direct broker service on the specified VM.
// This is a stub for non-Windows platforms.
func Dial(_ context.Context, _ uuid.UUID) (net.Conn, error) {
	return nil, ErrNotSupported
}

// DialService connects to a specific Hyper-V socket service on the specified VM.
// This is a stub for non-Windows platforms.
func DialService(_ context.Context, _, _ uuid.UUID) (net.Conn, error) {
	return nil, ErrNotSupported
}

// ConnectAndAuthenticate is a stub for non-Windows platforms.
func ConnectAndAuthenticate(_ context.Context, _ uuid.UUID, _, _, _, _ string) (net.Conn, error) {
	return nil, ErrNotSupported
}
