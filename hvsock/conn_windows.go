//go:build windows

package hvsock

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/google/uuid"
)

// Dial connects to the PowerShell Direct broker service on the specified VM.
// This is a convenience wrapper that uses PsrpBrokerServiceID.
func Dial(ctx context.Context, vmID uuid.UUID) (net.Conn, error) {
	return DialService(ctx, vmID, PsrpBrokerServiceID)
}

// DialService connects to a specific Hyper-V socket service on the specified VM.
func DialService(ctx context.Context, vmID, serviceID uuid.UUID) (net.Conn, error) {
	vmGuid := uuidToGUID(vmID)
	svcGuid := uuidToGUID(serviceID)

	addr := &winio.HvsockAddr{
		VMID:      vmGuid,
		ServiceID: svcGuid,
	}

	debugf("Dialing HvSocket: VM=%s Service=%s", vmID, serviceID)
	conn, err := winio.Dial(ctx, addr)
	if err != nil {
		debugf("Dial failed: %v", err)
		return nil, err
	}
	debugf("Dial succeeded")
	return conn, nil
}

// uuidToGUID converts a google/uuid.UUID to go-winio's guid.GUID.
// uuid.UUID is stored as big-endian bytes per RFC 4122.
// go-winio's guid.FromArray expects big-endian bytes and handles conversion.
func uuidToGUID(u uuid.UUID) guid.GUID {
	var arr [16]byte
	copy(arr[:], u[:])
	return guid.FromArray(arr)
}
