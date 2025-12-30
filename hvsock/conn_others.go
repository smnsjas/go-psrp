//go:build !windows

package hvsock

import (
	"context"
	"errors"
	"net"

	"github.com/google/uuid"
)

var ErrNotSupported = errors.New("hvsock is only supported on windows")

// Dial connects to the PowerShell Direct broker service on the specified VM.
// This is a stub for non-Windows platforms.
func Dial(ctx context.Context, vmID uuid.UUID) (net.Conn, error) {
	return nil, ErrNotSupported
}

// DialService connects to a specific Hyper-V socket service on the specified VM.
// This is a stub for non-Windows platforms.
func DialService(ctx context.Context, vmID, serviceID uuid.UUID) (net.Conn, error) {
	return nil, ErrNotSupported
}

// ConnectAndAuthenticate is a stub for non-Windows platforms.
func ConnectAndAuthenticate(ctx context.Context, vmID uuid.UUID, domain, user, pass, configName string) (net.Conn, error) {
	return nil, ErrNotSupported
}
